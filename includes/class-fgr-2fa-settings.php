<?php
defined( 'ABSPATH' ) || exit;

/**
 * Admin-Einstellungsseite: Rollen-Konfiguration + Benutzer-Übersicht.
 */
class FGR_2FA_Settings {

    public function __construct() {
        $menu_hook = is_multisite() ? 'network_admin_menu' : 'admin_menu';
        add_action( $menu_hook,   [ $this, 'add_menu' ] );
        add_action( 'admin_init', [ $this, 'handle_save' ] );
    }

    public function add_menu(): void {
        add_submenu_page(
            'fgr-plugins',
            'FGR 2FA',
            '2FA',
            'manage_options',
            'fgr-2fa',
            [ $this, 'render_page' ]
        );
    }

    public function handle_save(): void {
        if ( ! isset( $_POST['fgr_2fa_save'] ) ) return;
        check_admin_referer( 'fgr_2fa_save', 'fgr_2fa_nonce' );

        $roles = array_map( 'sanitize_key', (array) ( $_POST['required_roles'] ?? [] ) );

        // Nur bekannte WordPress-Rollen akzeptieren
        global $wp_roles;
        $valid = array_keys( $wp_roles->get_names() );
        $roles = array_values( array_intersect( $roles, $valid ) );

        fgr_2fa_update_option( [ 'required_roles' => $roles ] );
        add_settings_error( 'fgr_2fa', 'saved', 'Einstellungen gespeichert.', 'success' );
    }

    public function render_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) return;
        settings_errors( 'fgr_2fa' );

        $opt            = fgr_2fa_get_option();
        $required_roles = $opt['required_roles'] ?? [ 'administrator' ];

        global $wp_roles;
        $roles = $wp_roles->get_names();
        ?>
        <div class="wrap">
            <h1>FGR 2FA</h1>
            <p style="color:#888;margin-top:-8px">aus der <em>Freien Gestalterischen Republik</em></p>

            <form method="post">
                <?php wp_nonce_field( 'fgr_2fa_save', 'fgr_2fa_nonce' ); ?>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">2FA erforderlich für</th>
                        <td>
                            <?php foreach ( $roles as $slug => $name ) : ?>
                            <label style="display:block;margin-bottom:6px">
                                <input type="checkbox" name="required_roles[]"
                                       value="<?php echo esc_attr( $slug ); ?>"
                                       <?php checked( in_array( $slug, $required_roles, true ) ); ?>>
                                <?php echo esc_html( translate_user_role( $name ) ); ?>
                            </label>
                            <?php endforeach; ?>
                            <p class="description">
                                Benutzer mit diesen Rollen müssen 2FA einrichten.
                                Sie werden nach dem Login zur Profilseite weitergeleitet, bis die Einrichtung abgeschlossen ist.
                            </p>
                        </td>
                    </tr>
                </table>

                <p class="submit">
                    <button type="submit" name="fgr_2fa_save" class="button button-primary">
                        Einstellungen speichern
                    </button>
                </p>
            </form>

            <hr>
            <h2>Benutzer-Übersicht</h2>
            <?php $this->render_user_table(); ?>
        </div>
        <?php
    }

    private function render_user_table(): void {
        $users  = get_users( [ 'number' => 200, 'orderby' => 'login' ] );
        $labels = [ 'totp' => 'Authenticator-App', 'email' => 'E-Mail-Code' ];
        ?>
        <table class="wp-list-table widefat fixed striped" style="max-width:900px">
            <thead>
                <tr>
                    <th>Benutzer</th>
                    <th>E-Mail</th>
                    <th>Rolle</th>
                    <th>2FA-Status</th>
                    <th>Methode</th>
                    <th>Backup-Codes</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $users as $user ) :
                    $method  = FGR_2FA_Auth::get_method( $user->ID );
                    $enabled = FGR_2FA_Auth::is_enabled( $user->ID );
                    $count   = $enabled ? FGR_2FA_Auth::backup_count( $user->ID ) : '–';
                ?>
                <tr>
                    <td><strong><?php echo esc_html( $user->user_login ); ?></strong></td>
                    <td><?php echo esc_html( $user->user_email ); ?></td>
                    <td><?php echo esc_html( implode( ', ', $user->roles ) ); ?></td>
                    <td>
                        <?php if ( $enabled ) : ?>
                            <span style="color:green;font-weight:600">✓ Aktiviert</span>
                        <?php else : ?>
                            <span style="color:#888">✗ Nicht aktiviert</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html( $labels[ $method ] ?? '–' ); ?></td>
                    <td><?php echo esc_html( $count ); ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }
}
