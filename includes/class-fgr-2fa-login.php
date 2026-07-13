<?php
defined( 'ABSPATH' ) || exit;

/**
 * Steuert den 2FA-Login-Ablauf:
 * 1. Passwort-Check abgefangen → 2FA-Formular anzeigen
 * 2. Code prüfen → einloggen oder Fehler melden
 * 3. 2FA-Einrichtung erzwingen wenn nötig
 */
class FGR_2FA_Login {

    public function __construct() {
        add_filter( 'authenticate',    [ $this, 'intercept' ],        100, 3 );
        add_action( 'wp_login_failed', [ $this, 'redirect_to_2fa' ],  10,  2 );
        add_action( 'login_init',      [ $this, 'handle_2fa_page' ] );
        add_action( 'admin_init',      [ $this, 'enforce_setup' ] );
    }

    // =========================================================
    // Nach erfolgreichem Passwort-Check: 2FA einschalten
    // =========================================================

    public function intercept( $user, $username, $password ) {
        if ( ! ( $user instanceof WP_User ) ) return $user;
        if ( ! self::requires_2fa( $user ) )  return $user;
        if ( ! FGR_2FA_Auth::is_enabled( $user->ID ) ) return $user; // Noch nicht eingerichtet → erst einloggen

        $token = bin2hex( random_bytes( 16 ) );
        set_transient( 'fgr_2fa_pending_' . $token, $user->ID, 600 );

        return new WP_Error( 'fgr_2fa_required', $token );
    }

    // =========================================================
    // Weiterleitung zur 2FA-Seite
    // =========================================================

    public function redirect_to_2fa( string $username, WP_Error $error ): void {
        if ( $error->get_error_code() !== 'fgr_2fa_required' ) return;

        $token = $error->get_error_message( 'fgr_2fa_required' );
        $redir = esc_url_raw( $_POST['redirect_to'] ?? admin_url() );

        wp_safe_redirect( add_query_arg( [
            'action'      => 'fgr_2fa',
            'fgr_token'   => $token,
            'redirect_to' => rawurlencode( $redir ),
        ], wp_login_url() ) );
        exit;
    }

    // =========================================================
    // 2FA-Seite: Formular zeigen oder Code prüfen
    // =========================================================

    public function handle_2fa_page(): void {
        if ( ( $_REQUEST['action'] ?? '' ) !== 'fgr_2fa' ) return;

        $token   = sanitize_key( $_REQUEST['fgr_token'] ?? '' );
        $redir   = esc_url_raw( rawurldecode( $_REQUEST['redirect_to'] ?? admin_url() ) );
        $user_id = (int) get_transient( 'fgr_2fa_pending_' . $token );

        if ( ! $user_id || ! $token ) {
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        $method = FGR_2FA_Auth::get_method( $user_id );

        // Code-Übermittlung verarbeiten
        if ( isset( $_POST['fgr_2fa_submit'] ) ) {
            check_admin_referer( 'fgr_2fa_verify_' . $token, 'fgr_2fa_nonce' );
            $code = sanitize_text_field( $_POST['fgr_2fa_code'] ?? '' );
            $this->verify_and_login( $user_id, $token, $code, $method, $redir );
            return;
        }

        // E-Mail-Code beim ersten Laden senden
        if ( $method === 'email' && ! isset( $_GET['resend'] ) ) {
            FGR_2FA_Auth::email_send_code( $user_id );
        }

        // Erneut senden (auf Anfrage)
        if ( $method === 'email' && isset( $_GET['resend'] ) ) {
            FGR_2FA_Auth::email_send_code( $user_id );
        }

        $this->render_form( $user_id, $token, $method, $redir, '' );
    }

    private function verify_and_login( int $user_id, string $token, string $code, string $method, string $redir ): void {
        // Rate-Limit: max. 5 Fehlversuche pro Token
        $attempts_key = 'fgr_2fa_attempts_' . $token;
        $attempts     = (int) get_transient( $attempts_key );

        if ( $attempts >= 5 ) {
            delete_transient( 'fgr_2fa_pending_' . $token );
            delete_transient( $attempts_key );
            $this->render_form( $user_id, $token, $method, $redir, 'Zu viele Fehlversuche. Bitte melde dich erneut an.' );
            return;
        }

        $verified = false;
        $error    = '';
        $clean    = preg_replace( '/[\s\-]/', '', $code );

        // Backup-Code (8 Zeichen nach Bereinigung)
        if ( strlen( $clean ) === 8 ) {
            $verified = FGR_2FA_Auth::backup_verify( $user_id, $code );
            if ( ! $verified ) $error = 'Ungültiger Backup-Code.';
        } elseif ( $method === 'totp' ) {
            $secret   = FGR_2FA_Auth::get_totp_secret( $user_id );
            $verified = FGR_2FA_Auth::totp_verify( $secret, $code );
            if ( ! $verified ) $error = 'Ungültiger Code. Bitte prüfe die Uhrzeit auf deinem Gerät.';
        } elseif ( $method === 'email' ) {
            $verified = FGR_2FA_Auth::email_verify_code( $user_id, $code );
            if ( ! $verified ) $error = 'Ungültiger oder abgelaufener Code.';
        } else {
            $error = 'Unbekannte 2FA-Methode.';
        }

        if ( $verified ) {
            delete_transient( 'fgr_2fa_pending_' . $token );
            delete_transient( $attempts_key );
            $user = get_user_by( 'id', $user_id );
            wp_set_auth_cookie( $user_id, false );
            do_action( 'wp_login', $user->user_login, $user );
            wp_safe_redirect( $redir );
            exit;
        }

        set_transient( $attempts_key, $attempts + 1, 600 );
        $this->render_form( $user_id, $token, $method, $redir, $error );
    }

    private function render_form( int $user_id, string $token, string $method, string $redir, string $error ): void {
        nocache_headers();
        $resend_url = add_query_arg( [
            'action'      => 'fgr_2fa',
            'fgr_token'   => $token,
            'redirect_to' => rawurlencode( $redir ),
            'resend'      => '1',
        ], wp_login_url() );

        login_header( 'Zwei-Faktor-Authentifizierung' );
        ?>
        <style>
        .fgr-2fa-box { background:#f0f4f8; border:1px solid #c8d8e8; padding:14px 18px; border-radius:4px; margin-bottom:20px; font-size:13px; color:#3c434a; }
        #fgr_2fa_code { font-size:22px; letter-spacing:6px; text-align:center; width:100%; box-sizing:border-box; }
        .fgr-backup-link { display:block; text-align:right; font-size:12px; margin-top:6px; }
        .fgr-2fa-error { color:#d63638; font-weight:500; margin-bottom:16px; padding:8px 12px; background:#fef7f7; border:1px solid #f0a3a3; border-radius:4px; }
        </style>

        <?php if ( $error ) : ?>
            <p class="fgr-2fa-error"><?php echo esc_html( $error ); ?></p>
        <?php endif; ?>

        <div class="fgr-2fa-box">
            <?php if ( $method === 'email' ) : ?>
                Ein 6-stelliger Code wurde an deine E-Mail-Adresse gesendet.
            <?php else : ?>
                Öffne deine Authenticator-App und gib den aktuellen Code ein.
            <?php endif; ?>
        </div>

        <form name="fgr2fa" id="loginform" action="" method="post">
            <p>
                <label for="fgr_2fa_code">6-stelliger Code</label>
                <input type="text" id="fgr_2fa_code" name="fgr_2fa_code"
                       inputmode="numeric" autocomplete="one-time-code"
                       maxlength="9" autofocus class="input" value="">
            </p>
            <a href="#" id="fgr-backup-toggle" class="fgr-backup-link">Backup-Code verwenden</a>

            <input type="hidden" name="action"      value="fgr_2fa">
            <input type="hidden" name="fgr_token"   value="<?php echo esc_attr( $token ); ?>">
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redir ); ?>">
            <?php wp_nonce_field( 'fgr_2fa_verify_' . $token, 'fgr_2fa_nonce' ); ?>

            <p class="submit">
                <input type="submit" name="fgr_2fa_submit" value="Bestätigen"
                       class="button button-primary button-large" style="width:100%">
            </p>
        </form>

        <?php if ( $method === 'email' ) : ?>
        <p style="text-align:center;margin-top:14px">
            <a href="<?php echo esc_url( $resend_url ); ?>">Neuen Code senden</a>
        </p>
        <?php endif; ?>

        <p style="text-align:center;margin-top:8px">
            <a href="<?php echo esc_url( wp_login_url() ); ?>">← Zurück zur Anmeldung</a>
        </p>

        <script>
        document.getElementById('fgr-backup-toggle').addEventListener('click', function(e) {
            e.preventDefault();
            var inp   = document.getElementById('fgr_2fa_code');
            var label = document.querySelector('label[for="fgr_2fa_code"]');
            if ( inp.dataset.backup !== '1' ) {
                inp.dataset.backup = '1';
                inp.inputMode   = 'text';
                inp.maxLength   = 9;
                inp.style.letterSpacing = '2px';
                inp.placeholder = 'XXXX-XXXX';
                inp.value = '';
                label.textContent = 'Backup-Code';
                this.textContent  = '← Zurück zum normalen Code';
            } else {
                inp.dataset.backup = '0';
                inp.inputMode   = 'numeric';
                inp.maxLength   = 6;
                inp.style.letterSpacing = '6px';
                inp.placeholder = '';
                inp.value = '';
                label.textContent = '6-stelliger Code';
                this.textContent  = 'Backup-Code verwenden';
            }
            inp.focus();
        });
        </script>
        <?php
        login_footer();
        exit;
    }

    // =========================================================
    // 2FA-Einrichtung erzwingen (nach Login, im Admin-Bereich)
    // =========================================================

    public function enforce_setup(): void {
        if ( ! is_user_logged_in() || wp_doing_ajax() ) return;

        global $pagenow;
        // Nicht weiterleiten wenn Benutzer bereits auf der Profil-Seite ist
        if ( in_array( $pagenow, [ 'profile.php', 'user-edit.php' ], true ) ) return;

        $user = wp_get_current_user();
        if ( self::requires_2fa( $user ) && ! FGR_2FA_Auth::is_enabled( $user->ID ) ) {
            wp_safe_redirect( get_edit_profile_url( $user->ID ) . '#fgr-2fa-setup' );
            exit;
        }
    }

    // =========================================================
    // Hilfsmethode: Braucht diese Rolle 2FA?
    // =========================================================

    public static function requires_2fa( WP_User $user ): bool {
        $opt            = fgr_2fa_get_option();
        $required_roles = $opt['required_roles'] ?? [ 'administrator' ];
        return ! empty( array_intersect( $user->roles, $required_roles ) );
    }
}
