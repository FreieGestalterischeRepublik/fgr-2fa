<?php
defined( 'ABSPATH' ) || exit;

/**
 * Alle kryptographischen Operationen: TOTP, E-Mail-Code, Backup-Codes, User-Status.
 */
class FGR_2FA_Auth {

    private const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    // =========================================================
    // TOTP – Time-based One-Time Password (RFC 6238)
    // =========================================================

    public static function totp_generate_secret(): string {
        $secret = '';
        for ( $i = 0; $i < 32; $i++ ) {
            $secret .= self::BASE32[ random_int( 0, 31 ) ];
        }
        return $secret;
    }

    private static function base32_decode( string $input ): string {
        $input  = strtoupper( preg_replace( '/\s/', '', $input ) );
        $buffer = 0;
        $bits   = 0;
        $output = '';

        for ( $i = 0; $i < strlen( $input ); $i++ ) {
            $pos = strpos( self::BASE32, $input[ $i ] );
            if ( $pos === false ) continue;
            $buffer = ( $buffer << 5 ) | $pos;
            $bits  += 5;
            if ( $bits >= 8 ) {
                $bits  -= 8;
                $output .= chr( ( $buffer >> $bits ) & 0xFF );
            }
        }

        return $output;
    }

    public static function totp_get_code( string $secret, ?int $step = null ): string {
        $step = $step ?? (int) floor( time() / 30 );
        $key  = self::base32_decode( $secret );
        // 8-Byte Big-Endian-Darstellung des Zeitschritts
        $msg  = "\x00\x00\x00\x00" . pack( 'N', $step );
        $hash = hash_hmac( 'sha1', $msg, $key, true );
        $off  = ord( $hash[19] ) & 0x0F;
        $code = (
            ( ( ord( $hash[ $off ] )     & 0x7F ) << 24 ) |
            ( ( ord( $hash[ $off + 1 ] ) & 0xFF ) << 16 ) |
            ( ( ord( $hash[ $off + 2 ] ) & 0xFF ) << 8  ) |
            ( ( ord( $hash[ $off + 3 ] ) & 0xFF ) )
        ) % 1_000_000;
        return str_pad( (string) $code, 6, '0', STR_PAD_LEFT );
    }

    /**
     * Prüft einen TOTP-Code. $user_id wird für Replay-Schutz benötigt: ein einmal
     * erfolgreich verwendeter Zeitschritt wird gesperrt, damit ein abgefangener/erspähter
     * Code nicht innerhalb seines Gültigkeitsfensters ein zweites Mal funktioniert.
     */
    public static function totp_verify( int $user_id, string $secret, string $code, int $window = 1 ): bool {
        $code = preg_replace( '/\s/', '', $code );
        if ( strlen( $code ) !== 6 || ! ctype_digit( $code ) ) return false;
        $step      = (int) floor( time() / 30 );
        $last_used = (int) get_user_meta( $user_id, 'fgr_2fa_totp_last_step', true );
        for ( $i = -$window; $i <= $window; $i++ ) {
            $candidate = $step + $i;
            if ( $candidate <= $last_used ) continue; // bereits verwendeter oder älterer Zeitschritt
            if ( hash_equals( self::totp_get_code( $secret, $candidate ), $code ) ) {
                update_user_meta( $user_id, 'fgr_2fa_totp_last_step', $candidate );
                return true;
            }
        }
        return false;
    }

    /** Gibt die otpauth://-URI für den TOTP-Setup zurück; der QR-Code wird lokal im Browser gerendert. */
    public static function totp_get_otpauth_uri( string $label, string $secret ): string {
        return 'otpauth://totp/' . rawurlencode( $label ) . '?secret=' . $secret . '&digits=6&period=30';
    }

    // =========================================================
    // E-Mail-Code
    // =========================================================

    /** Sendet einen 6-stelligen Einmalcode per E-Mail. Rate-Limit: 1 pro Minute. */
    public static function email_send_code( int $user_id ): bool {
        if ( get_transient( 'fgr_2fa_email_rl_' . $user_id ) ) return false;

        $code = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
        set_transient( 'fgr_2fa_email_code_' . $user_id, password_hash( $code, PASSWORD_BCRYPT ), 600 );
        set_transient( 'fgr_2fa_email_rl_' . $user_id, 1, 60 );

        $user = get_user_by( 'id', $user_id );
        return wp_mail(
            $user->user_email,
            'Dein Anmeldecode – ' . get_bloginfo( 'name' ),
            "Dein 2FA-Code lautet:\n\n{$code}\n\nDieser Code ist 10 Minuten gültig.\nBitte gib ihn niemals weiter."
        );
    }

    public static function email_verify_code( int $user_id, string $code ): bool {
        $code = preg_replace( '/\s/', '', $code );
        if ( strlen( $code ) !== 6 || ! ctype_digit( $code ) ) return false;
        $hash = get_transient( 'fgr_2fa_email_code_' . $user_id );
        if ( ! $hash ) return false;
        if ( password_verify( $code, $hash ) ) {
            delete_transient( 'fgr_2fa_email_code_' . $user_id );
            return true;
        }
        return false;
    }

    // =========================================================
    // Backup-Codes
    // =========================================================

    /** Generiert 10 neue Backup-Codes, speichert gehashte Werte, gibt Klartext zurück. */
    public static function backup_generate( int $user_id ): array {
        $codes  = [];
        $hashes = [];
        for ( $i = 0; $i < 10; $i++ ) {
            $raw      = strtoupper( bin2hex( random_bytes( 4 ) ) ); // 8 Hex-Zeichen
            $codes[]  = substr( $raw, 0, 4 ) . '-' . substr( $raw, 4 ); // Format: XXXX-XXXX
            $hashes[] = password_hash( $raw, PASSWORD_BCRYPT );
        }
        update_user_meta( $user_id, 'fgr_2fa_backup_codes', wp_json_encode( $hashes ) );
        return $codes;
    }

    /**
     * Prüft einen Backup-Code und löscht ihn bei Erfolg (Einmalverwendung).
     * Schreibt per Compare-and-Swap direkt über $wpdb zurück (statt get_user_meta +
     * update_user_meta), damit zwei gleichzeitige Anfragen mit demselben Code nicht
     * beide erfolgreich sein können (Race Condition).
     */
    public static function backup_verify( int $user_id, string $code ): bool {
        global $wpdb;
        $code = strtoupper( preg_replace( '/[\s\-]/', '', $code ) );

        for ( $try = 0; $try < 3; $try++ ) {
            $stored = get_user_meta( $user_id, 'fgr_2fa_backup_codes', true );
            $hashes = (array) json_decode( $stored ?: '[]', true );

            $match_i = null;
            foreach ( $hashes as $i => $hash ) {
                if ( password_verify( $code, $hash ) ) {
                    $match_i = $i;
                    break;
                }
            }
            if ( null === $match_i ) return false;

            unset( $hashes[ $match_i ] );
            $new = wp_json_encode( array_values( $hashes ) );

            $updated = $wpdb->update(
                $wpdb->usermeta,
                [ 'meta_value' => $new ],
                [ 'user_id' => $user_id, 'meta_key' => 'fgr_2fa_backup_codes', 'meta_value' => $stored ],
                [ '%s' ],
                [ '%d', '%s', '%s' ]
            );
            wp_cache_delete( $user_id, 'user_meta' );

            if ( $updated > 0 ) return true;
            // Zwischenzeitlich von einer parallelen Anfrage geändert → mit aktuellem Stand erneut versuchen.
        }
        return false;
    }

    public static function backup_count( int $user_id ): int {
        $stored = get_user_meta( $user_id, 'fgr_2fa_backup_codes', true );
        return count( (array) json_decode( $stored ?: '[]', true ) );
    }

    // =========================================================
    // Nutzerbezogenes Rate-Limit für Login-Versuche
    // =========================================================
    // Das Limit von 5 Fehlversuchen pro Login-Token (siehe FGR_2FA_Login) reicht allein
    // nicht: ein Angreifer mit korrektem Passwort könnte beliebig oft einen neuen Token
    // anfordern und so den 6-stelligen TOTP-Coderaum über viele Anläufe brute-forcen.
    // Dieses Limit zählt Fehlversuche pro Nutzer, unabhängig vom Token.

    private const USER_MAX_ATTEMPTS    = 10;
    private const USER_LOCKOUT_SECONDS = 900; // 15 Minuten

    public static function login_rate_limited( int $user_id ): bool {
        return (int) get_transient( 'fgr_2fa_user_fails_' . $user_id ) >= self::USER_MAX_ATTEMPTS;
    }

    public static function login_register_failure( int $user_id ): void {
        $key = 'fgr_2fa_user_fails_' . $user_id;
        $n   = (int) get_transient( $key );
        set_transient( $key, $n + 1, self::USER_LOCKOUT_SECONDS );
    }

    public static function login_clear_failures( int $user_id ): void {
        delete_transient( 'fgr_2fa_user_fails_' . $user_id );
    }

    // =========================================================
    // User-Status
    // =========================================================

    public static function get_method( int $user_id ): string {
        return get_user_meta( $user_id, 'fgr_2fa_method', true ) ?: '';
    }

    public static function get_totp_secret( int $user_id ): string {
        return get_user_meta( $user_id, 'fgr_2fa_totp_secret', true ) ?: '';
    }

    public static function is_enabled( int $user_id ): bool {
        return in_array( self::get_method( $user_id ), [ 'totp', 'email' ], true );
    }

    /** TOTP aktivieren und Backup-Codes generieren. */
    public static function activate_totp( int $user_id, string $secret ): array {
        update_user_meta( $user_id, 'fgr_2fa_method',      'totp' );
        update_user_meta( $user_id, 'fgr_2fa_totp_secret', $secret );
        delete_transient( 'fgr_2fa_setup_secret_' . $user_id );
        return self::backup_generate( $user_id );
    }

    /** E-Mail-Methode aktivieren und Backup-Codes generieren. */
    public static function activate_email( int $user_id ): array {
        update_user_meta( $user_id, 'fgr_2fa_method', 'email' );
        return self::backup_generate( $user_id );
    }

    /** 2FA komplett deaktivieren. */
    public static function disable( int $user_id ): void {
        delete_user_meta( $user_id, 'fgr_2fa_method' );
        delete_user_meta( $user_id, 'fgr_2fa_totp_secret' );
        delete_user_meta( $user_id, 'fgr_2fa_totp_last_step' );
        delete_user_meta( $user_id, 'fgr_2fa_backup_codes' );
    }
}
