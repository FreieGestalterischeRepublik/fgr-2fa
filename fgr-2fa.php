<?php
/**
 * Plugin Name:  FGR 2FA
 * Description:  Zwei-Faktor-Authentifizierung für WordPress. Unterstützt TOTP (Authenticator-App), E-Mail-Code und Backup-Codes. Konfigurierbar nach Benutzerrolle.
 * Version:      1.0.13
 * Author:       Freie Gestalterische Republik
 * Author URI:   https://fgr.design
 * License:      GPL-2.0-or-later
 * Requires PHP: 8.0
 * Requires at least: 6.0
 * Text Domain:  fgr-2fa
 */

defined( 'ABSPATH' ) || exit;

define( 'FGR_2FA_VERSION', '1.0.13' );
define( 'FGR_2FA_DIR',     plugin_dir_path( __FILE__ ) );
define( 'FGR_2FA_URL',     plugin_dir_url( __FILE__ ) );

// Update-Checker: prüft GitHub auf neue Versionen
require_once FGR_2FA_DIR . 'lib/plugin-update-checker/plugin-update-checker.php';
$fgr_2fa_updater = YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
    'https://github.com/FreieGestalterischeRepublik/fgr-2fa/',
    __FILE__,
    'fgr-2fa'
);
$fgr_2fa_updater->setBranch( 'main' );

require_once FGR_2FA_DIR . 'includes/class-fgr-2fa-auth.php';
require_once FGR_2FA_DIR . 'includes/class-fgr-2fa-login.php';
require_once FGR_2FA_DIR . 'includes/class-fgr-2fa-profile.php';
require_once FGR_2FA_DIR . 'includes/class-fgr-2fa-settings.php';

function fgr_2fa_get_option(): array {
    return (array) get_option( 'fgr_2fa_settings', [] );
}

function fgr_2fa_update_option( array $data ): void {
    update_option( 'fgr_2fa_settings', $data, false );
}

add_action( 'plugins_loaded', function () {
    new FGR_2FA_Settings();
    new FGR_2FA_Login();
    new FGR_2FA_Profile();
} );
