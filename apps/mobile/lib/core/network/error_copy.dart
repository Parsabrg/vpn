import '../../l10n/app_localizations.dart';
import '../wireguard/windows_wireguard_tunnel.dart';
import '../xray/xray_tunnel_controller.dart';
import 'api_exception.dart';

/// Renders any caught error into copy safe to show a user, without ever
/// inventing detail the API didn't actually provide.
///
/// The server writes its own details in English. In English they are shown
/// as written; in any other language they are replaced by the translated
/// sentence for their kind -- the server's details are deliberately generic
/// ("was not accepted", "is temporarily unavailable", "not found"), so the
/// kind is all they carry and nothing is lost by translating it.
String userFacingErrorMessage(Object error, AppText text) {
  // Windows and Linux tunnel failures are generated locally and should tell
  // the user which one of the elevation/runtime steps failed. Hiding these
  // behind the generic copy made a real adapter/route problem impossible to
  // diagnose -- and on Linux it hid that the password prompt was refused or
  // that wireguard-tools is missing.
  if (error is StateError &&
      (error.message.startsWith('Windows ') ||
          error.message.startsWith('Linux '))) {
    return error.message;
  }
  if (error is WireGuardNoAnswer) {
    return text.errorWireguardNoHandshake;
  }
  if (error is TunnelStartTimeout) {
    return text.errorTunnelNoTraffic;
  }
  if (error is NebulaConnectivityException) {
    return text.errorOffline;
  }
  if (error is NebulaApiException) {
    if (error.isRateLimited) {
      return text.errorRateLimited;
    }
    if (error.isServerMaintenance) {
      return text.errorServerMaintenance;
    }
    if (error.isAccountExpired) {
      return text.errorAccountExpired;
    }
    if (error.isDeviceLimitReached) {
      return text.errorDeviceLimitReached;
    }
    if (error.isQuotaExhausted) {
      // Worded for the person who cannot connect, not for the operator.
      // Trying again will not help and there is exactly one thing that
      // will, so the message says what that is.
      return text.errorQuotaExhausted;
    }
    if (text.localeName == 'en') {
      return error.detail;
    }
    return switch (error.statusCode) {
      404 => text.errorNotFound,
      503 => text.errorUnavailable,
      _ => text.errorNotAccepted,
    };
  }
  return text.errorGeneric;
}
