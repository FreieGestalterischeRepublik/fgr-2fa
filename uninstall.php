<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Plugin-Option löschen
delete_option( 'fgr_2fa_settings' );

// User-Meta aller Benutzer löschen
$users = get_users( [ 'fields' => 'ID', 'number' => -1 ] );
foreach ( $users as $user_id ) {
    delete_user_meta( $user_id, 'fgr_2fa_method' );
    delete_user_meta( $user_id, 'fgr_2fa_totp_secret' );
    delete_user_meta( $user_id, 'fgr_2fa_backup_codes' );
}

// Alle 2FA-Transients aus der Datenbank entfernen
global $wpdb;
$wpdb->query(
    "DELETE FROM {$wpdb->options}
     WHERE option_name LIKE '_transient_fgr_2fa_%'
        OR option_name LIKE '_transient_timeout_fgr_2fa_%'"
);
