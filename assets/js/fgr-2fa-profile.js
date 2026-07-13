/* FGR 2FA – Profil-Seite Interaktionen */
( function ( $ ) {
    'use strict';

    var ajaxUrl = fgr2fa.ajax_url;
    var nonce   = fgr2fa.nonce;
    var secret  = '';

    // --- Hilfsfunktionen ---

    function ajax( action, data, onSuccess, onError ) {
        $.post( ajaxUrl, $.extend( { action: action, nonce: nonce }, data ) )
            .done( function ( resp ) {
                if ( resp.success ) {
                    onSuccess( resp.data );
                } else {
                    if ( onError ) onError( resp.data || 'Ein Fehler ist aufgetreten.' );
                }
            } )
            .fail( function () {
                if ( onError ) onError( 'Verbindungsfehler. Bitte Seite neu laden.' );
            } );
    }

    function showBackupCodes( codes ) {
        var $display = $( '#fgr-backup-codes-display' );
        var $list    = $( '#fgr-backup-codes-list' ).empty();
        codes.forEach( function ( code ) {
            $list.append( '<div class="fgr-backup-code">' + code + '</div>' );
        } );
        $display.show();
        $display[0].scrollIntoView( { behavior: 'smooth', block: 'start' } );
    }

    // === TOTP-Setup ===

    $( '#fgr-setup-totp' ).on( 'click', function () {
        $( '#fgr-email-wizard' ).hide();
        var $wizard = $( '#fgr-totp-wizard' ).show();

        if ( ! secret ) {
            $( '#fgr-totp-qr' ).html( '<p class="fgr-loading">QR-Code wird generiert…</p>' );
            ajax( 'fgr_2fa_get_totp', {}, function ( data ) {
                secret = data.secret;
                $( '#fgr-totp-qr' ).html(
                    '<img src="' + data.qr_url + '" width="200" height="200" alt="QR-Code">'
                );
                $( '#fgr-totp-secret' ).text( data.secret.replace( /(.{4})/g, '$1 ' ).trim() );
                $( '#fgr-totp-secret-wrap' ).show();
            }, function ( msg ) {
                $( '#fgr-totp-qr' ).html( '<p class="fgr-error">' + msg + '</p>' );
            } );
        }

        $wizard[0].scrollIntoView( { behavior: 'smooth' } );
    } );

    $( '#fgr-copy-secret' ).on( 'click', function () {
        var $btn = $( this );
        navigator.clipboard.writeText( secret ).then( function () {
            $btn.text( 'Kopiert!' );
            setTimeout( function () { $btn.text( 'Kopieren' ); }, 2000 );
        } );
    } );

    $( '#fgr-confirm-totp' ).on( 'click', function () {
        var code = $( '#fgr-totp-code-input' ).val().trim();
        var $err = $( '#fgr-totp-error' ).hide();
        var $btn = $( this );

        if ( code.length !== 6 ) {
            $err.text( 'Bitte gib den 6-stelligen Code aus der App ein.' ).show();
            return;
        }

        $btn.prop( 'disabled', true ).text( 'Wird geprüft…' );

        ajax( 'fgr_2fa_verify_totp', { code: code }, function ( data ) {
            showBackupCodes( data.backup_codes );
        }, function ( msg ) {
            $err.text( msg ).show();
            $btn.prop( 'disabled', false ).text( 'Bestätigen' );
            $( '#fgr-totp-code-input' ).val( '' ).focus();
        } );
    } );

    // === E-Mail-Setup ===

    $( '#fgr-setup-email' ).on( 'click', function () {
        $( '#fgr-totp-wizard' ).hide();
        var $wizard = $( '#fgr-email-wizard' ).show();
        $wizard[0].scrollIntoView( { behavior: 'smooth' } );
    } );

    $( '#fgr-send-email-code' ).on( 'click', function () {
        var $btn = $( this ).prop( 'disabled', true ).text( 'Wird gesendet…' );

        ajax( 'fgr_2fa_send_email', {}, function () {
            $( '#fgr-email-code-wrap' ).show();
            $btn.text( 'Erneut senden' ).prop( 'disabled', false );
        }, function ( msg ) {
            alert( msg );
            $btn.prop( 'disabled', false ).text( 'Code senden' );
        } );
    } );

    $( '#fgr-confirm-email' ).on( 'click', function () {
        var code = $( '#fgr-email-code-input' ).val().trim();
        var $err = $( '#fgr-email-error' ).hide();
        var $btn = $( this );

        if ( code.length !== 6 ) {
            $err.text( 'Bitte gib den 6-stelligen Code ein.' ).show();
            return;
        }

        $btn.prop( 'disabled', true ).text( 'Wird geprüft…' );

        ajax( 'fgr_2fa_verify_email', { code: code }, function ( data ) {
            showBackupCodes( data.backup_codes );
        }, function ( msg ) {
            $err.text( msg ).show();
            $btn.prop( 'disabled', false ).text( 'Bestätigen' );
            $( '#fgr-email-code-input' ).val( '' ).focus();
        } );
    } );

    // === Backup-Codes neu generieren ===

    $( '#fgr-regen-backup' ).on( 'click', function () {
        if ( ! confirm( 'Wirklich neue Backup-Codes generieren?\nDie alten Codes werden sofort ungültig.' ) ) return;
        var $btn = $( this ).prop( 'disabled', true ).text( 'Wird generiert…' );

        ajax( 'fgr_2fa_regen_backup', {}, function ( data ) {
            showBackupCodes( data.backup_codes );
            $btn.prop( 'disabled', false ).text( 'Neue Backup-Codes generieren' );
        }, function ( msg ) {
            alert( msg );
            $btn.prop( 'disabled', false ).text( 'Neue Backup-Codes generieren' );
        } );
    } );

    // === Fertig-Button: Seite neu laden ===

    $( document ).on( 'click', '#fgr-backup-done', function () {
        location.reload();
    } );

    // === Alle Backup-Codes kopieren ===

    $( '#fgr-copy-backup' ).on( 'click', function () {
        var $btn  = $( this );
        var codes = [];
        $( '.fgr-backup-code' ).each( function () { codes.push( $( this ).text() ); } );
        navigator.clipboard.writeText( codes.join( '\n' ) ).then( function () {
            $btn.text( 'Kopiert!' );
            setTimeout( function () { $btn.text( 'Alle kopieren' ); }, 2000 );
        } );
    } );

    // === 2FA deaktivieren ===

    $( '#fgr-disable-2fa' ).on( 'click', function () {
        if ( ! confirm( '2FA wirklich deaktivieren?\nDein Konto wird dadurch weniger sicher.' ) ) return;
        var $btn = $( this ).prop( 'disabled', true ).text( 'Wird deaktiviert…' );

        ajax( 'fgr_2fa_disable', {}, function () {
            location.reload();
        }, function ( msg ) {
            alert( msg );
            $btn.prop( 'disabled', false ).text( '2FA deaktivieren' );
        } );
    } );

} )( jQuery );
