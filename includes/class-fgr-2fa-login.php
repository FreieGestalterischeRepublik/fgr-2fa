<?php
defined( 'ABSPATH' ) || exit;

/**
 * Steuert den 2FA-Login-Ablauf.
 *
 * Ablauf:
 * 1. login_init (Prio 1) fängt den Login-POST früh ab
 * 2. Passwort korrekt + 2FA nötig → Formular direkt als POST-Antwort (kein Redirect!)
 * 3. User gibt Code ein → POST auf dieselbe URL → Code prüfen → einloggen
 *
 * Kein Redirect bedeutet: Browser wertet die Seite als Nutzeraktion →
 * Fokus ist echt → Paste funktioniert ohne extra Mausklick.
 */
class FGR_2FA_Login {

    public function __construct() {
        add_action( 'login_init',  [ $this, 'handle_login_init' ], 1 );
        add_action( 'admin_init',  [ $this, 'enforce_setup' ] );
    }

    // =========================================================
    // Zentraler Einstiegspunkt in login_init
    // =========================================================

    public function handle_login_init(): void {
        $action = $_REQUEST['action'] ?? 'login';

        // 2FA-Code-Übermittlung oder Formular-Anzeige
        if ( $action === 'fgr_2fa' ) {
            $this->handle_2fa_page();
            return;
        }

        // Login-Formular abschicken
        if ( $action !== 'login' || ! isset( $_POST['log'], $_POST['pwd'] ) ) {
            return;
        }

        $raw_username = sanitize_user( wp_unslash( $_POST['log'] ) );
        $password     = wp_unslash( $_POST['pwd'] );

        // Benutzer per Login-Name oder E-Mail suchen (ohne Passwort-Prüfung)
        $user = get_user_by( 'login', $raw_username )
             ?: get_user_by( 'email', $raw_username );

        if ( ! $user )                                      return; // Unbekannter Nutzer → WP normal
        if ( ! self::requires_2fa( $user ) )                return; // Keine 2FA für diese Rolle
        if ( ! FGR_2FA_Auth::is_enabled( $user->ID ) )     return; // 2FA noch nicht eingerichtet

        // Passwort direkt prüfen – vermeidet doppelte Auth-Hook-Aufrufe
        if ( ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
            return; // Falsches Passwort → WordPress zeigt Fehlermeldung normal
        }

        // Alles OK → 2FA-Formular DIREKT als POST-Antwort rendern (kein Redirect!)
        $token = bin2hex( random_bytes( 16 ) );
        set_transient( 'fgr_2fa_pending_' . $token, $user->ID, 600 );

        $method = FGR_2FA_Auth::get_method( $user->ID );
        $redir  = esc_url_raw( $_POST['redirect_to'] ?? admin_url() );

        if ( $method === 'email' ) {
            FGR_2FA_Auth::email_send_code( $user->ID );
        }

        $this->render_form( $user->ID, $token, $method, $redir, '' );
        // render_form ruft exit auf – WordPress-Login läuft nicht weiter
    }

    // =========================================================
    // 2FA-Seite: Formular zeigen oder Code prüfen
    // =========================================================

    private function handle_2fa_page(): void {
        $token   = sanitize_key( $_REQUEST['fgr_token'] ?? '' );
        $redir   = esc_url_raw( $_REQUEST['redirect_to'] ?? admin_url() );
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

        // Neuen E-Mail-Code senden (auf explizite Anfrage via resend-Link)
        if ( $method === 'email' ) {
            FGR_2FA_Auth::email_send_code( $user_id );
        }

        $this->render_form( $user_id, $token, $method, $redir, '' );
    }

    // =========================================================
    // Code prüfen und einloggen
    // =========================================================

    private function verify_and_login( int $user_id, string $token, string $code, string $method, string $redir ): void {
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

    // =========================================================
    // Formular rendern
    // =========================================================

    private function render_form( int $user_id, string $token, string $method, string $redir, string $error ): void {
        nocache_headers();

        $wp_error = $error ? new WP_Error( 'fgr_2fa_error', esc_html( $error ) ) : null;

        $message = ( $method === 'email' )
            ? '<p class="message">Ein 6-stelliger Code wurde an deine E-Mail-Adresse gesendet.</p>'
            : '<p class="message">Gib den aktuellen Code aus deiner Authenticator-App ein.</p>';

        $resend_url = add_query_arg( [
            'action'      => 'fgr_2fa',
            'fgr_token'   => $token,
            'redirect_to' => rawurlencode( $redir ),
        ], wp_login_url() );

        login_header( 'Zwei-Faktor-Authentifizierung', $message, $wp_error );
        ?>

        <form name="fgr2fa" id="loginform" action="" method="post">
            <p>
                <label for="fgr_2fa_code">Sicherheitscode</label>
                <input type="text" id="fgr_2fa_code" name="fgr_2fa_code"
                       class="input" size="20"
                       inputmode="numeric" autocomplete="one-time-code"
                       maxlength="9" value=""
                       style="text-align:center;font-size:22px;letter-spacing:8px;font-family:monospace">
            </p>
            <p style="text-align:right;margin-top:-6px">
                <a href="#" id="fgr-backup-toggle" style="font-size:12px">Backup-Code verwenden</a>
            </p>

            <input type="hidden" name="action"      value="fgr_2fa">
            <input type="hidden" name="fgr_token"   value="<?php echo esc_attr( $token ); ?>">
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redir ); ?>">
            <?php wp_nonce_field( 'fgr_2fa_verify_' . $token, 'fgr_2fa_nonce' ); ?>

            <p class="submit">
                <input type="submit" name="fgr_2fa_submit" value="Bestätigen"
                       class="button button-primary button-large">
            </p>
        </form>

        <p id="nav">
            <?php if ( $method === 'email' ) : ?>
            <a href="<?php echo esc_url( $resend_url ); ?>">Neuen Code senden</a>
            &nbsp;|&nbsp;
            <?php endif; ?>
            <a href="<?php echo esc_url( wp_login_url() ); ?>">← Zurück zur Anmeldung</a>
        </p>

        <script>
        ( function () {
            document.getElementById( 'fgr-backup-toggle' ).addEventListener( 'click', function ( e ) {
                e.preventDefault();
                var inp   = document.getElementById( 'fgr_2fa_code' );
                var label = document.querySelector( 'label[for="fgr_2fa_code"]' );
                if ( inp.dataset.backup !== '1' ) {
                    inp.dataset.backup      = '1';
                    inp.inputMode           = 'text';
                    inp.maxLength           = 9;
                    inp.style.letterSpacing = '2px';
                    inp.placeholder         = 'XXXX-XXXX';
                    inp.value               = '';
                    label.textContent       = 'Backup-Code';
                    this.textContent        = '← Zurück zum normalen Code';
                } else {
                    inp.dataset.backup      = '0';
                    inp.inputMode           = 'numeric';
                    inp.maxLength           = 6;
                    inp.style.letterSpacing = '8px';
                    inp.placeholder         = '';
                    inp.value               = '';
                    label.textContent       = 'Sicherheitscode';
                    this.textContent        = 'Backup-Code verwenden';
                }
                inp.focus();
            } );
        } )();
        </script>
        <?php
        login_footer( 'fgr_2fa_code' );
        exit;
    }

    // =========================================================
    // 2FA-Einrichtung erzwingen
    // =========================================================

    public function enforce_setup(): void {
        if ( ! is_user_logged_in() || wp_doing_ajax() ) return;

        global $pagenow;
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
