import '../../l10n/app_localizations.dart';
import '../devices/devices_state.dart';

/// Which of the connect screen's seven presentations to draw.
///
/// The redesign is one screen that switches, not seven screens, so the choice
/// is made once here rather than by conditionals scattered through a build
/// method. It is a pure function of [DevicesState], which is what makes the
/// rules testable without pumping a widget.
///
/// The ordering inside [connectViewOf] is the whole design. In particular
/// [notProtected] must never be reachable by a path that also reads as
/// success: a provisioned peer with no live tunnel is the single most
/// misleading state this app can be in, and the previous UI hid it in a
/// paragraph on a card that otherwise looked connected.
enum ConnectView {
  /// First load. Drawn as skeleton bars at the position of real content, not
  /// a spinner.
  loading,

  /// The server list could not be fetched at all.
  unreachable,

  /// Reached the API, and this account has no servers permitted.
  noServers,

  /// Idle, with a server and protocol chosen.
  off,

  /// A connect request is in flight.
  connecting,

  /// Provisioned *and* a live local tunnel is up.
  protected,

  /// Provisioned, but no tunnel. Registered is not protected.
  notProtected,
}

/// Derives the presentation from state.
///
/// Load status is checked before connection status on purpose. If the server
/// list failed to refresh, the screen says so even while a stale peer object
/// is still in state -- claiming "Protected" over a connection we can no
/// longer verify is the failure mode worth avoiding, and it costs only a
/// reload to get back.
ConnectView connectViewOf(DevicesState state) {
  switch (state.loadStatus) {
    case DevicesLoadStatus.loading:
      return ConnectView.loading;
    case DevicesLoadStatus.failed:
      return ConnectView.unreachable;
    case DevicesLoadStatus.loaded:
      break;
  }

  if (state.servers.isEmpty) {
    return ConnectView.noServers;
  }
  if (state.isSubmitting) {
    return ConnectView.connecting;
  }
  if (!state.isConnected) {
    return ConnectView.off;
  }
  // Connected, so the only question left is whether a tunnel actually came
  // up. `tunnelEstablished` is a separate signal from `isConnected` precisely
  // because the two disagree on every Android build shipped so far.
  return state.tunnelEstablished
      ? ConnectView.protected
      : ConnectView.notProtected;
}

/// Copy for the uppercase mono line above the state word.
///
/// Kept beside the view rather than in the widget so the wording is diffable
/// against the handoff without reading layout code.
extension ConnectViewCopy on ConnectView {
  /// The large word. `null` where the design draws something other than a
  /// single word: skeleton bars, or the three-line "Nothing / to connect /
  /// to yet".
  String? word(AppText text) {
    switch (this) {
      case ConnectView.loading:
        return null;
      case ConnectView.unreachable:
        return text.wordUnreachable;
      case ConnectView.noServers:
        return null;
      case ConnectView.off:
        return text.wordOff;
      case ConnectView.connecting:
        return text.wordConnecting;
      case ConnectView.protected:
        return text.wordProtected;
      case ConnectView.notProtected:
        return text.wordNotProtected;
    }
  }

  /// The call-to-action's label. `null` while loading, where the CTA is an
  /// inert filled block rather than a button.
  String? ctaLabel(AppText text) {
    switch (this) {
      case ConnectView.loading:
        return null;
      case ConnectView.unreachable:
        return text.ctaTryAgain;
      case ConnectView.noServers:
        return text.ctaRefresh;
      case ConnectView.off:
        return text.ctaConnect;
      case ConnectView.connecting:
        return text.ctaCancel;
      case ConnectView.protected:
        return text.ctaDisconnect;
      case ConnectView.notProtected:
        return text.ctaRetryTunnel;
    }
  }

  /// Whether this presentation is one where the user is actually protected.
  ///
  /// Exists so the question is asked in one place. [ConnectView.notProtected]
  /// answering `false` here is the entire point of the state.
  bool get isProtected => this == ConnectView.protected;
}
