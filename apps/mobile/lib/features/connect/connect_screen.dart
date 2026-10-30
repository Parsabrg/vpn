import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/auth/auth_notifier.dart';
import '../../core/auth/auth_state.dart';
import '../../core/format/bytes.dart';
import '../../core/free/free_mode.dart';
import '../../core/storage/storage_providers.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/theme/type_scale.dart';
import '../../core/tunnel/tunnel_traffic.dart';
import '../../core/widgets/panel/panel_atoms.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/panel/panel_row.dart';
import '../../core/xray/local_proxy.dart';
import '../../l10n/app_localizations.dart';
import '../devices/devices_controller.dart';
import '../devices/devices_state.dart';
import '../free/free_mode_screen.dart';
import 'configuration_screen.dart';
import 'connect_view.dart';
import 'servers_screen.dart';
import 'tunnel_traffic_provider.dart';

/// The first tab, and the whole point of the app.
///
/// One screen with seven presentations rather than seven screens: the status
/// line, the state word, the row set and the action all change together, and
/// [connectViewOf] decides which set is showing. Keeping that decision in a
/// pure function means the states can be tested without pumping a widget, and
/// means this file only has to lay them out.
/// Below this height the Connect screen scrolls as one page.
const double _pinnedLayoutMinHeight = 560;

class ConnectScreen extends ConsumerStatefulWidget {
  const ConnectScreen({super.key});

  @override
  ConsumerState<ConnectScreen> createState() => _ConnectScreenState();
}

class _ConnectScreenState extends ConsumerState<ConnectScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      final DevicesController controller = ref.read(
        devicesControllerProvider.notifier,
      );
      await controller.load();
      if (!mounted) {
        return;
      }
      await controller.connectOnLaunchIfWanted(
        ref.read(deviceIdStoreProvider).read(),
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    final DevicesState state = ref.watch(devicesControllerProvider);
    final ConnectView view = connectViewOf(state);
    final NebulaPalette palette = context.palette;
    // Watched here and passed down, rather than watched inside
    // ConnectStateBlock: that widget is deliberately a pure function of what
    // it is given, which is what lets its seven presentations be tested
    // without standing up a controller.
    final TunnelTraffic? traffic = ref.watch(tunnelTrafficProvider).value;

    return Scaffold(
      backgroundColor: palette.bg,
      body: SafeArea(
        child: Padding(
          // 24px screen padding; the CTA block sits in 20px insets, so it is
          // pulled back out below rather than nested inside this.
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: LayoutBuilder(
            builder: (BuildContext context, BoxConstraints box) {
              final Widget block = ConnectStateBlock(
                view: view,
                state: state,
                traffic: traffic,
                freeMode: ref.watch(freeModeProvider),
              );
              final Widget messages = ConnectMessages(
                state: state,
                serverUnreachable:
                    ref.watch(authNotifierProvider) is AuthUnreachable,
              );
              final Widget action = Padding(
                padding: const EdgeInsets.fromLTRB(0, 0, 0, 16),
                child: _Action(view: view, state: state),
              );
              // Short screens (landscape on a phone) scroll as one page: with
              // the messages and the button pinned, the state and its rows
              // were squeezed to nothing behind an error card (2026-10-19).
              if (box.maxHeight < _pinnedLayoutMinHeight) {
                return SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: <Widget>[
                      const _TopBar(),
                      block,
                      const SizedBox(height: 16),
                      messages,
                      action,
                    ],
                  ),
                );
              }
              return Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: <Widget>[
                  const _TopBar(),
                  Expanded(child: SingleChildScrollView(child: block)),
                  // Outside the scroll, so it cannot end up below the fold:
                  // at the end of the rows it was cut off right above the
                  // button, with nothing to say more was there.
                  messages,
                  action,
                ],
              );
            },
          ),
        ),
      ),
    );
  }
}

class _TopBar extends ConsumerWidget {
  const _TopBar();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final NebulaPalette palette = context.palette;
    return Padding(
      padding: const EdgeInsets.only(top: 28),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.baseline,
        textBaseline: TextBaseline.alphabetic,
        children: <Widget>[
          Text(
            'NEBULA',
            style: context.type.wordmark.copyWith(color: palette.textMuted),
          ),
          const Spacer(),
          // Adding links and subscriptions, where it is found: tucked into
          // Settings nobody came across it. Free mode shows it too: its Free
          // tab has the same Add buttons, but a first install looked for
          // them here (2026-10-17).
          IconButton(
            tooltip: AppText.of(context).ownLinksTitle,
            icon: Icon(Icons.add, color: palette.textPrimary),
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute<void>(
                builder: (BuildContext context) =>
                    const FreeModeScreen(ownLinks: true),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// Status line, state word, and the rows beneath them.
///
/// Public because it is the part worth testing on its own: it is a pure
/// function of a view and a state, so a test can drive all seven
/// presentations without standing up a controller and a fake repository.
class ConnectStateBlock extends StatelessWidget {
  const ConnectStateBlock({
    required this.view,
    required this.state,
    super.key,
    this.traffic,
    this.freeMode = false,
  });

  final ConnectView view;
  final DevicesState state;

  /// No account and no server of one's own: there is no peer to register,
  /// so the words for a signed-in failure ("Peer only", "Registered on")
  /// say something untrue.
  final bool freeMode;

  /// The live tunnel reading, or null when there is none yet.
  ///
  /// Null and zero are different and are drawn differently: null is "no
  /// reading", which is what a tunnel that has just come up looks like for
  /// the moment before its first report; zero is a reading that says nothing
  /// has been carried.
  final TunnelTraffic? traffic;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        const SizedBox(height: 56),
        _statusLine(context),
        const SizedBox(height: 12),
        _word(context),
        const SizedBox(height: 44),
        _rows(context),
        const SizedBox(height: 16),
      ],
    );
  }

  Widget _statusLine(BuildContext context) {
    final AppText text = AppText.of(context);
    switch (view) {
      case ConnectView.loading:
        return const SizedBox(
          height: 16,
          child: SkeletonBar(width: 120, height: 12),
        );
      case ConnectView.off:
        return StatusLine(tone: StatusTone.off, text: text.statusDisconnected);
      case ConnectView.connecting:
        return StatusLine(tone: StatusTone.working, text: text.statusHandshake);
      case ConnectView.protected when state.localProxy != null:
        return StatusLine(
          tone: StatusTone.live,
          text: text.statusLocalProxy('127.0.0.1:${state.localProxy!.port}'),
        );
      case ConnectView.protected when state.sanctionsOnly:
        return StatusLine(
          tone: StatusTone.live,
          text: text.statusSanctionsOnly(
            state.selectedServer?.displayName ??
                state.connectedServerCode ??
                '',
          ),
        );
      case ConnectView.protected:
        return StatusLine(
          tone: StatusTone.live,
          // Elapsed session time needs a ticker the state does not carry
          // yet, so this shows the server alone rather than a fake clock.
          text: state.selectedServer?.displayName ?? text.statusConnected,
        );
      case ConnectView.notProtected:
        return StatusLine(
          tone: StatusTone.warning,
          text: freeMode ? text.statusNoTunnel : text.statusPeerOnly,
        );
      case ConnectView.unreachable:
        return StatusLine(
          tone: StatusTone.error,
          text: text.statusNoConnection,
        );
      case ConnectView.noServers:
        return StatusLine(tone: StatusTone.off, text: text.statusNoServers);
    }
  }

  Widget _word(BuildContext context) {
    final AppText text = AppText.of(context);
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    if (view == ConnectView.loading) {
      return const SizedBox(
        height: 50,
        child: Align(
          alignment: AlignmentDirectional.centerStart,
          child: SkeletonBar(width: 200, height: 34),
        ),
      );
    }
    if (view == ConnectView.noServers) {
      return Text(
        text.nothingToConnect,
        style: type.stateWord.copyWith(color: palette.textPrimary),
      );
    }

    final Color color;
    switch (view) {
      case ConnectView.protected:
        // The one place textMax is used -- and not for a local proxy, which
        // protects only the apps pointed at it.
        color = state.localProxy != null
            ? palette.textPrimary
            : palette.textMax;
      case ConnectView.notProtected:
        color = palette.amberText;
      case ConnectView.off:
      case ConnectView.connecting:
      case ConnectView.unreachable:
      case ConnectView.loading:
      case ConnectView.noServers:
        color = palette.textPrimary;
    }

    // Not "Protected" when only sanctioned services go through the server:
    // everything else is leaving directly, and the largest word on the screen
    // is the last place to overstate that.
    // Nor "Protected" for a local proxy: nothing reaches it unless an app
    // was pointed at it.
    final String word = view != ConnectView.protected
        ? view.word(text)!
        : state.localProxy != null
        ? text.wordProxyOn
        : state.sanctionsOnly
        ? text.wordOn
        : view.word(text)!;
    return Text(word, style: type.stateWord.copyWith(color: color));
  }

  static void _openServers(BuildContext context) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (BuildContext context) => const ServersScreen(),
      ),
    );
  }

  Widget _rows(BuildContext context) {
    final AppText text = AppText.of(context);
    final NebulaPalette palette = context.palette;

    switch (view) {
      case ConnectView.loading:
        return const Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[_SkeletonRow(), _SkeletonRow()],
        );

      case ConnectView.off:
        return PanelRowGroup(
          rows: <PanelRow>[
            PanelRow(
              label: text.rowServer,
              value: state.selectedServer?.displayName ?? text.choose,
              onTap: () => _openServers(context),
            ),
            PanelRow(
              label: text.rowProtocol,
              value: state.selectedProfileCode == automaticProfileCode
                  ? text.protocolAutomatic
                  : state.selectedProfileCode == null
                  ? text.choose
                  : state.profileLabel(state.selectedProfileCode!),
              // Same destination: the protocol list is a property of the
              // selected server, so there is nowhere separate to go.
              onTap: () => _openServers(context),
            ),
          ],
        );

      case ConnectView.connecting:
        // Deliberately not tappable: changing the target mid-handshake would
        // leave the request and the screen disagreeing.
        return PanelRowGroup(
          rows: <PanelRow>[
            PanelRow(
              label: text.rowServer,
              value: state.selectedServer?.displayName ?? '—',
            ),
            PanelRow(
              label: text.rowProtocol,
              // In Automatic, the protocol being tried right now.
              value: state.selectedProfileCode == automaticProfileCode
                  ? (state.activeProfileCode == null
                        ? text.protocolAutomatic
                        : state.profileLabel(state.activeProfileCode!))
                  : state.selectedProfileCode == null
                  ? '—'
                  : state.profileLabel(state.selectedProfileCode!),
            ),
          ],
        );

      case ConnectView.protected when state.localProxy != null:
        final LocalProxyRows proxyRows = LocalProxyRows(
          context: context,
          proxy: state.localProxy!,
        );
        return PanelRowGroup(
          rows: <PanelRow>[
            PanelRow(
              label: text.rowServer,
              value:
                  state.selectedServer?.displayName ??
                  state.connectedServerCode ??
                  '—',
            ),
            PanelRow(
              label: text.rowProtocol,
              value: state.activeProfileCode != null
                  ? state.profileLabel(state.activeProfileCode!)
                  : state.activeProtocolCode ?? '—',
            ),
            ...proxyRows.rows(),
            PanelRow(
              label: text.rowDownloaded,
              value: traffic == null ? '—' : formatBytes(traffic!.rxBytes),
            ),
            PanelRow(
              label: text.rowUploaded,
              value: traffic == null ? '—' : formatBytes(traffic!.txBytes),
            ),
          ],
        );

      case ConnectView.protected:
        return PanelRowGroup(
          rows: <PanelRow>[
            PanelRow(
              label: text.rowAddress,
              value:
                  state.xrayClient?.serverAddress ??
                  state.selectedServer?.publicHost ??
                  '—',
            ),
            PanelRow(
              label: text.rowProtocol,
              value: state.activeProfileCode != null
                  ? state.profileLabel(state.activeProfileCode!)
                  : state.activeProtocolCode ?? '—',
            ),
            // Two rows rather than one. A row ellipsizes a value that does
            // not fit, which is right for an address but not for a pair:
            // "↓ 641 KB   ↑ …" dropped the upload figure entirely on a real
            // phone. Split, neither figure can crowd the other out.
            //
            // Spelled out rather than arrowed, which also removes the only
            // place a reader could mistake one direction for the other.
            PanelRow(
              label: text.rowDownloaded,
              value: traffic == null ? '—' : formatBytes(traffic!.rxBytes),
            ),
            PanelRow(
              label: text.rowUploaded,
              value: traffic == null ? '—' : formatBytes(traffic!.txBytes),
            ),
            PanelRow(
              label: text.rowSession,
              // WireGuard counts bytes, not time, and this process cannot
              // know when a tunnel it did not start came up. An em dash says
              // that; a clock started at zero would be a plausible lie.
              value: traffic?.elapsed == null
                  ? '—'
                  : formatTunnelDuration(traffic!.elapsed!),
            ),
          ],
        );

      case ConnectView.notProtected:
        return PanelRowGroup(
          rows: <PanelRow>[
            PanelRow(
              label: freeMode ? text.rowServer : text.rowRegisteredOn,
              value:
                  state.selectedServer?.displayName ??
                  state.connectedServerCode ??
                  '—',
              // "Try another server" is what the error says when none of a
              // server's protocols got through; this is where to do it.
              valueColor: palette.amberText,
              onTap: () => _openServers(context),
            ),
            // The way out of a protocol this network blocks: without it the
            // only button retried the same one (Hysteria2 on a phone whose
            // network drops UDP, 2026-10-17).
            PanelRow(
              label: text.rowProtocol,
              value: state.selectedProfileCode == automaticProfileCode
                  ? text.protocolAutomatic
                  : state.selectedProfileCode == null
                  ? text.choose
                  : state.profileLabel(state.selectedProfileCode!),
              valueColor: palette.amberText,
              onTap: () => _openServers(context),
            ),
            PanelRow(
              label: text.rowConfiguration,
              value: text.view,
              valueColor: palette.amberText,
              onTap: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                  builder: (BuildContext context) =>
                      const ConfigurationScreen(),
                ),
              ),
            ),
          ],
        );

      case ConnectView.unreachable:
        // The reason, not a guess at it: "check your network" over a
        // working network sent the owner looking in the wrong place while
        // the API answered and something else had failed.
        return Text(
          state.loadErrorMessage ?? text.checkYourNetwork,
          style: context.type.topBarMeta.copyWith(color: palette.textMuted),
        );

      case ConnectView.noServers:
        return SizedBox(
          width: 300,
          child: Text(
            text.noServersPermitted,
            style: context.type.rowLabel.copyWith(color: palette.textMuted),
          ),
        );
    }
  }
}

/// Why the last attempt failed, and where the screen's contents came from
/// when that is not the server. Drawn between the rows and the button,
/// never inside the scroll.
class ConnectMessages extends StatelessWidget {
  const ConnectMessages({
    required this.state,
    super.key,
    this.serverUnreachable = false,
  });

  final DevicesState state;

  /// A session is stored but the server did not answer, so what is on screen
  /// comes from this device rather than from the server.
  final bool serverUnreachable;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        // Why a connect attempt did not work.
        //
        // The controller has always recorded this and nothing has ever drawn
        // it, so every refusal the server makes -- an exhausted data
        // allowance above all -- reached a person as a button that appeared
        // to do nothing at all. Pressing it again is then the only
        // reasonable thing to try, and it fails the same silent way.
        if (state.actionErrorMessage != null) ...<Widget>[
          _ActionError(message: state.actionErrorMessage!),
          const SizedBox(height: 12),
        ],
        // Where the screen's contents came from, when that is not the
        // server. Saying nothing would present saved settings, and a tunnel
        // raised from a saved credential, as though the server had just
        // confirmed both.
        // Only while that connection is up: after it ended, "Connected with
        // credentials saved on this device" sat under Off (seen 2026-10-18).
        if (serverUnreachable ||
            (state.fromSavedCredential && state.tunnelEstablished)) ...<Widget>[
          _Notice(
            message: state.fromSavedCredential && state.tunnelEstablished
                ? AppText.of(context).savedCredentialNotice
                : AppText.of(context).offlineNotice,
          ),
          const SizedBox(height: 12),
        ],
      ],
    );
  }
}

class _SkeletonRow extends StatelessWidget {
  const _SkeletonRow();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        border: Border(top: BorderSide(color: context.palette.hairline)),
      ),
      padding: const EdgeInsets.symmetric(vertical: 18),
      child: const Row(
        children: <Widget>[
          SkeletonBar(width: 64, height: 12),
          Spacer(),
          SkeletonBar(width: 104, height: 12),
        ],
      ),
    );
  }
}

class _Action extends ConsumerWidget {
  const _Action({required this.view, required this.state});

  final ConnectView view;
  final DevicesState state;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (view == ConnectView.loading) {
      return const PanelCtaPlaceholder();
    }

    final String? deviceId = ref.watch(deviceIdStoreProvider).read();
    final DevicesController controller = ref.read(
      devicesControllerProvider.notifier,
    );

    CtaStyle style;
    VoidCallback? onPressed;

    switch (view) {
      case ConnectView.off:
        style = CtaStyle.primary;
        // Disabled until there is something to connect to. The controller
        // ignores a connect with no server or profile selected, so an enabled
        // button here would do nothing at all when pressed -- worse than one
        // that plainly cannot be pressed yet.
        final bool ready =
            state.selectedServerCode != null &&
            state.selectedProfileCode != null;
        onPressed = deviceId == null || !ready
            ? null
            : () => controller.connect(deviceId);
      case ConnectView.connecting:
        style = CtaStyle.secondary;
        // Live while a connect is in flight. The same view covers a
        // disconnect finishing, which has nothing to cancel.
        onPressed = controller.canCancelConnect
            ? controller.cancelConnect
            : null;
      case ConnectView.protected:
        style = CtaStyle.secondary;
        onPressed = deviceId == null
            ? null
            : () => controller.disconnect(deviceId);
      case ConnectView.notProtected:
        style = CtaStyle.warning;
        onPressed = deviceId == null
            ? null
            : () => controller.connect(deviceId);
      case ConnectView.unreachable:
      case ConnectView.noServers:
        style = view == ConnectView.unreachable
            ? CtaStyle.primary
            : CtaStyle.secondary;
        onPressed = controller.load;
      case ConnectView.loading:
        throw StateError('handled above');
    }

    return PanelCta(
      label: view.ctaLabel(AppText.of(context))!,
      onPressed: onPressed,
      style: style,
    );
  }
}

/// The reason the last attempt failed, shown where the attempt was made.
///
/// Deliberately not a snackbar. A refusal like a spent data allowance is not
/// transient information to be glanced at and lost -- it is the state the
/// screen is in until somebody else changes it, and it has to still be there
/// when the person looks back at the screen wondering why nothing happened.
/// The neutral sibling of [_ActionError]: nothing has gone wrong, the app is
/// just saying which of the two it is working from.
class _Notice extends StatelessWidget {
  const _Notice({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: palette.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: palette.border),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Icon(Icons.info_outline, size: 18, color: palette.textMuted),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              message,
              style: context.type.rowValue.copyWith(color: palette.textMuted),
            ),
          ),
        ],
      ),
    );
  }
}

class _ActionError extends StatelessWidget {
  const _ActionError({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: palette.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: palette.border),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Icon(Icons.error_outline, size: 18, color: palette.redText),
          const SizedBox(width: 10),
          Expanded(
            // Wraps rather than ellipsizes. The copy is a whole sentence
            // ending in the one thing that will actually fix it, and a row
            // that clipped it would drop exactly that half.
            child: Text(
              message,
              style: TextStyle(
                color: palette.textPrimary,
                fontSize: 13,
                height: 1.4,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// What an app is set up with to use the local proxy, each tap-to-copy.
///
/// The password is shown rather than hidden: the whole point of the screen is
/// to be copied from, and it only opens this phone's own loopback proxy.
class LocalProxyRows {
  const LocalProxyRows({required this.context, required this.proxy});

  final BuildContext context;
  final LocalProxy proxy;

  List<PanelRow> rows() {
    final AppText text = AppText.of(context);
    return <PanelRow>[
      PanelRow(
        label: text.rowAddress,
        value: '127.0.0.1:${proxy.port}',
        onTap: () => _copy('127.0.0.1:${proxy.port}'),
      ),
      PanelRow(
        label: text.rowUsername,
        value: proxy.username,
        onTap: () => _copy(proxy.username),
      ),
      PanelRow(
        label: text.rowPassword,
        value: proxy.password,
        onTap: () => _copy(proxy.password),
      ),
    ];
  }

  Future<void> _copy(String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (!context.mounted) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(AppText.of(context).copiedToClipboard)),
    );
  }
}
