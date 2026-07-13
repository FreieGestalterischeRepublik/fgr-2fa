<?php
defined( 'ABSPATH' ) || exit;

/**
 * 2FA-Einrichtung auf der Profil-Seite des Benutzers.
 */
class FGR_2FA_Profile {

    public function __construct() {
        add_action( 'show_user_profile',    [ $this, 'render_section' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue' ] );

        // AJAX-Aktionen
        add_action( 'wp_ajax_fgr_2fa_get_totp',      [ $this, 'ajax_get_totp' ] );
        add_action( 'wp_ajax_fgr_2fa_verify_totp',    [ $this, 'ajax_verify_totp' ] );
        add_action( 'wp_ajax_fgr_2fa_send_email',     [ $this, 'ajax_send_email' ] );
        add_action( 'wp_ajax_fgr_2fa_verify_email',   [ $this, 'ajax_verify_email' ] );
        add_action( 'wp_ajax_fgr_2fa_disable',        [ $this, 'ajax_disable' ] );
        add_action( 'wp_ajax_fgr_2fa_regen_backup',   [ $this, 'ajax_regen_backup' ] );
    }

    public function enqueue( string $hook ): void {
        if ( $hook !== 'profile.php' ) return;
        wp_enqueue_style(
            'fgr-2fa',
            FGR_2FA_URL . 'assets/css/fgr-2fa.css',
            [],
            FGR_2FA_VERSION
        );
        wp_enqueue_script(
            'fgr-2fa-profile',
            FGR_2FA_URL . 'assets/js/fgr-2fa-profile.js',
            [ 'jquery' ],
            FGR_2FA_VERSION,
            true
        );
        wp_localize_script( 'fgr-2fa-profile', 'fgr2fa', [
            'ajax_url' => admin_url( 'admin-ajax.php' ),
            'nonce'    => wp_create_nonce( 'fgr_2fa_profile' ),
        ] );
    }

    // =========================================================
    // Profil-Abschnitt rendern
    // =========================================================

    public function render_section( WP_User $user ): void {
        $method   = FGR_2FA_Auth::get_method( $user->ID );
        $enabled  = FGR_2FA_Auth::is_enabled( $user->ID );
        $count    = $enabled ? FGR_2FA_Auth::backup_count( $user->ID ) : 0;
        $required = FGR_2FA_Login::requires_2fa( $user );
        $labels   = [ 'totp' => 'Authenticator-App (TOTP)', 'email' => 'E-Mail-Code' ];
        ?>
        <div id="fgr-2fa-setup">
            <h2>Zwei-Faktor-Authentifizierung</h2>

            <?php if ( $enabled ) : ?>

                <div class="fgr-2fa-status">
                    <span class="fgr-2fa-badge active">✓ 2FA ist aktiviert</span>
                    <span class="fgr-2fa-method">Methode: <?php echo esc_html( $labels[ $method ] ?? $method ); ?></span>
                </div>

                <div class="fgr-2fa-card">
                    <h3>Backup-Codes</h3>
                    <p>
                        Du hast noch <strong><?php echo esc_html( $count ); ?>
                        Backup-Code<?php echo $count !== 1 ? 's' : ''; ?></strong>.
                        <?php if ( $count <= 2 ) : ?>
                        <strong style="color:#d63638"> Bitte generiere neue Codes!</strong>
                        <?php endif; ?>
                    </p>
                    <button type="button" id="fgr-regen-backup" class="button button-secondary">
                        Neue Backup-Codes generieren
                    </button>
                </div>

                <?php if ( ! $required ) : ?>
                <div class="fgr-2fa-card fgr-2fa-danger-zone">
                    <h3>2FA deaktivieren</h3>
                    <p>Nach dem Deaktivieren kannst du dich ohne zweiten Faktor einloggen.</p>
                    <button type="button" id="fgr-disable-2fa" class="button fgr-btn-danger">
                        2FA deaktivieren
                    </button>
                </div>
                <?php else : ?>
                <p class="description">
                    ℹ️ 2FA ist für deine Rolle vorgeschrieben und kann nicht deaktiviert werden.
                </p>
                <?php endif; ?>

            <?php else : ?>

                <div class="fgr-2fa-status">
                    <span class="fgr-2fa-badge inactive">✗ 2FA ist nicht aktiviert</span>
                    <?php if ( $required ) : ?>
                    <p class="fgr-2fa-warning">
                        ⚠️ Deine Benutzerrolle erfordert 2FA. Bitte richte es unten ein.
                    </p>
                    <?php endif; ?>
                </div>

                <div class="fgr-2fa-setup-buttons">
                    <button type="button" id="fgr-setup-totp" class="button button-primary">
                        Mit Authenticator-App einrichten
                    </button>
                    <button type="button" id="fgr-setup-email" class="button button-secondary">
                        Mit E-Mail-Code einrichten
                    </button>
                </div>

                <!-- TOTP-Assistent -->
                <div id="fgr-totp-wizard" class="fgr-2fa-wizard" style="display:none">
                    <h3>Authenticator-App einrichten</h3>
                    <ol>
                        <li>Öffne <strong>Google Authenticator</strong>, <strong>Authy</strong> oder eine andere TOTP-App.</li>
                        <li>Tippe auf <strong>„+"</strong> → <strong>„QR-Code scannen"</strong>.</li>
                        <li>Scanne den Code unten — oder wähle <em>„Schlüssel eingeben"</em> für die manuelle Eingabe.</li>
                        <li>Gib danach den 6-stelligen Code aus der App ein und klicke <strong>Bestätigen</strong>.</li>
                    </ol>
                    <div id="fgr-totp-qr" class="fgr-qr-container">
                        <p class="fgr-loading">Code wird generiert…</p>
                    </div>
                    <div id="fgr-totp-secret-wrap" style="display:none">
                        <p><strong>Manuelle Eingabe – Schlüssel:</strong></p>
                        <code id="fgr-totp-secret" class="fgr-secret-key"></code>
                        <button type="button" id="fgr-copy-secret" class="button button-secondary">Kopieren</button>
                    </div>
                    <div class="fgr-2fa-verify-row" style="margin-top:20px">
                        <input type="text" id="fgr-totp-code-input"
                               placeholder="6-stelliger Code" maxlength="6"
                               inputmode="numeric" class="regular-text">
                        <button type="button" id="fgr-confirm-totp" class="button button-primary">Bestätigen</button>
                    </div>
                    <p id="fgr-totp-error" class="fgr-error" style="display:none"></p>
                </div>

                <!-- E-Mail-Assistent -->
                <div id="fgr-email-wizard" class="fgr-2fa-wizard" style="display:none">
                    <h3>E-Mail-Code einrichten</h3>
                    <p>
                        Wir senden einen Bestätigungscode an
                        <strong><?php echo esc_html( $user->user_email ); ?></strong>.
                    </p>
                    <button type="button" id="fgr-send-email-code" class="button button-secondary">
                        Code senden
                    </button>
                    <div id="fgr-email-code-wrap" style="display:none;margin-top:16px">
                        <p>Gib den Code aus deiner E-Mail ein:</p>
                        <div class="fgr-2fa-verify-row">
                            <input type="text" id="fgr-email-code-input"
                                   placeholder="6-stelliger Code" maxlength="6"
                                   inputmode="numeric" class="regular-text">
                            <button type="button" id="fgr-confirm-email" class="button button-primary">Bestätigen</button>
                        </div>
                        <p id="fgr-email-error" class="fgr-error" style="display:none"></p>
                    </div>
                </div>

            <?php endif; ?>

            <!-- Backup-Codes Anzeige (nach Generierung) -->
            <div id="fgr-backup-codes-display" class="fgr-2fa-card" style="display:none">
                <h3>Deine Backup-Codes</h3>
                <p>
                    ⚠️ <strong>Bitte jetzt speichern!</strong> Diese Codes werden nur einmal
                    angezeigt. Jeder Code kann nur einmal verwendet werden.
                </p>
                <div id="fgr-backup-codes-list" class="fgr-backup-grid"></div>
                <p style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:4px">
                    <button type="button" id="fgr-copy-backup" class="button button-secondary">
                        Alle kopieren
                    </button>
                    <button type="button" id="fgr-backup-done" class="button button-primary">
                        Codes gespeichert – Fertig
                    </button>
                </p>
            </div>
        </div>
        <?php
    }

    // =========================================================
    // AJAX-Handler
    // =========================================================

    private function check_nonce(): void {
        check_ajax_referer( 'fgr_2fa_profile', 'nonce' );
    }

    public function ajax_get_totp(): void {
        $this->check_nonce();
        $user_id = get_current_user_id();
        $user    = wp_get_current_user();
        $secret  = FGR_2FA_Auth::totp_generate_secret();
        set_transient( 'fgr_2fa_setup_secret_' . $user_id, $secret, 600 );
        $label  = get_bloginfo( 'name' ) . ':' . $user->user_email;
        $qr_url = FGR_2FA_Auth::totp_get_qr_url( $label, $secret );
        wp_send_json_success( [ 'qr_url' => $qr_url, 'secret' => $secret ] );
    }

    public function ajax_verify_totp(): void {
        $this->check_nonce();
        $user_id = get_current_user_id();
        $code    = sanitize_text_field( $_POST['code'] ?? '' );
        $secret  = get_transient( 'fgr_2fa_setup_secret_' . $user_id );
        if ( ! $secret ) {
            wp_send_json_error( 'Sitzung abgelaufen. Bitte Seite neu laden.' );
        }
        if ( ! FGR_2FA_Auth::totp_verify( $secret, $code ) ) {
            wp_send_json_error( 'Ungültiger Code. Bitte prüfe die Uhrzeit auf deinem Gerät.' );
        }
        $backup_codes = FGR_2FA_Auth::activate_totp( $user_id, $secret );
        wp_send_json_success( [ 'backup_codes' => $backup_codes ] );
    }

    public function ajax_send_email(): void {
        $this->check_nonce();
        $user_id = get_current_user_id();
        if ( ! FGR_2FA_Auth::email_send_code( $user_id ) ) {
            wp_send_json_error( 'Code wurde kürzlich gesendet. Bitte warte eine Minute.' );
        }
        wp_send_json_success();
    }

    public function ajax_verify_email(): void {
        $this->check_nonce();
        $user_id = get_current_user_id();
        $code    = sanitize_text_field( $_POST['code'] ?? '' );
        if ( ! FGR_2FA_Auth::email_verify_code( $user_id, $code ) ) {
            wp_send_json_error( 'Ungültiger oder abgelaufener Code.' );
        }
        $backup_codes = FGR_2FA_Auth::activate_email( $user_id );
        wp_send_json_success( [ 'backup_codes' => $backup_codes ] );
    }

    public function ajax_disable(): void {
        $this->check_nonce();
        $user = wp_get_current_user();
        if ( FGR_2FA_Login::requires_2fa( $user ) ) {
            wp_send_json_error( '2FA kann für deine Benutzerrolle nicht deaktiviert werden.' );
        }
        FGR_2FA_Auth::disable( $user->ID );
        wp_send_json_success();
    }

    public function ajax_regen_backup(): void {
        $this->check_nonce();
        $backup_codes = FGR_2FA_Auth::backup_generate( get_current_user_id() );
        wp_send_json_success( [ 'backup_codes' => $backup_codes ] );
    }
}
