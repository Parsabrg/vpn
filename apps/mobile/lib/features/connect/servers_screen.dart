import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/free/free_mode.dart';
import '../../core/servers/server_latency.dart';
import '../../core/servers/server_repository.dart';
import '../../core/storage/storage_providers.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/widgets/panel/panel_atoms.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/panel/panel_list_row.dart';
import '../../l10n/app_localizations.dart';
import '../devices/devices_controller.dart';
import '../devices/devices_state.dart';
import '../devices/profile_order.dart';

/// Pick a server, then a protocol on that server.
///
/// Both choices live on one screen because they are not independent: the
/// protocol list is a property of the selected server, and splitting them
/// across two screens would let a user pick a protocol the next server does
/// not offer.
///
/// Selection is local until the CTA is pressed. Writing straight through to
/// the controller on each tap would mean backing out of this screen silently
/// changed what the connect screen is pointed at.
class ServersScreen extends ConsumerStatefulWidget {
  const ServersScreen({super.key});

  @override
  ConsumerState<ServersScreen> createState() => _ServersScreenState();
}

class _ServersScreenState extends ConsumerState<ServersScreen> {
  String? _serverCode;
  String? _profileCode;

  @override
  Widget build(BuildContext context) {
    final DevicesState state = ref.watch(devicesControllerProvider);
    final ServerLatencyState latency = ref.watch(serverLatencyProvider);
    final NebulaPalette palette = context.palette;

    // Measured from this device to the server, so it only means anything
    // while the tunnel is down. With the tunnel up the app's own sockets go
    // through it, and the number would quietly be the round trip to the
    // server the user is already on -- the same figure for every row.
    final bool canMeasure = !state.tunnelEstablished;
    final List<AvailableServer> servers = sortByLatency(state.servers, latency);

    final String? serverCode = _serverCode ?? state.selectedServerCode;
    final AvailableServer? server = _serverIn(state, serverCode);
    final String? profileCode = _profileCode ?? state.selectedProfileCode;

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(AppText.of(context).serversTitle),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Expanded(
                child: ListView(
                  children: <Widget>[
                    const SizedBox(height: 8),
                    _LatencyHeader(
                      // What the account may use: links added on this device
                      // are listed too but are no one's permission -- 123
                      // "permitted" was one server and 122 links.
                      count: ref.watch(freeModeProvider)
                          ? state.servers.fold<int>(
                              0,
                              (int n, AvailableServer s) =>
                                  n + s.profiles.length,
                            )
                          : state.servers
                                .where(
                                  (AvailableServer s) => !isOwnLinkCode(s.code),
                                )
                                .length,
                      freeMode: ref.watch(freeModeProvider),
                      latency: latency,
                      canMeasure: canMeasure,
                      onMeasure: () => ref
                          .read(serverLatencyProvider.notifier)
                          .measure(state.servers),
                    ),
                    const SizedBox(height: 4),
                    for (final AvailableServer candidate in servers)
                      PanelListRow(
                        title: candidate.displayName,
                        meta: _serverMeta(AppText.of(context), candidate),
                        // Absent until something has actually been measured.
                        // A placeholder here would read as a reading.
                        trailing: latency
                            .forServer(candidate.code)
                            ?.label(AppText.of(context)),
                        metaColor: _latencyColor(
                          latency.forServer(candidate.code),
                          palette,
                        ),
                        selected: candidate.code == serverCode,
                        onTap: () => setState(() {
                          _serverCode = candidate.code;
                          // A protocol chosen on the previous server may not
                          // exist on this one; the app chooses until the
                          // person does.
                          _profileCode = automaticProfileCode;
                        }),
                      ),
                    if (server != null) ...<Widget>[
                      const SizedBox(height: 28),
                      // Every protocol is listed, working from here or not:
                      // one blocked on this network can work on another, or
                      // on another server. The test beside the heading says
                      // which answer right now, by sending a real request
                      // through each -- v2ray's "real delay".
                      _ProtocolHeader(
                        title: AppText.of(
                          context,
                        ).protocolForServer(server.displayName),
                        pinging:
                            state.pinging &&
                            state.protocolDelaysServer == server.code,
                        tested: state.delaysFor(server.code).isNotEmpty,
                        canMeasure: canMeasure,
                        onTest: () => ref
                            .read(devicesControllerProvider.notifier)
                            .pingProtocols(
                              ref.read(deviceIdStoreProvider).read() ?? '',
                              server: server,
                            ),
                      ),
                      const SizedBox(height: 12),
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: <Widget>[
                          // First and the default: the app tries the
                          // protocols below in this order until one works.
                          PanelChip(
                            label: AppText.of(context).protocolAutomatic,
                            selected: profileCode == automaticProfileCode,
                            onTap: () => setState(
                              () => _profileCode = automaticProfileCode,
                            ),
                          ),
                          for (final AvailableProfile profile
                              in orderedProfiles(
                                server.profiles,
                                state.delaysFor(server.code),
                                pinging:
                                    state.pinging &&
                                    state.protocolDelaysServer == server.code,
                              ))
                            PanelChip(
                              label: _chipLabel(
                                AppText.of(context),
                                state.profileLabel(profile.code),
                                state.delaysFor(server.code)[profile.code],
                              ),
                              selected: profile.code == profileCode,
                              onTap: () =>
                                  setState(() => _profileCode = profile.code),
                            ),
                        ],
                      ),
                    ],
                    const SizedBox(height: 24),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.only(bottom: 16),
                child: PanelCta(
                  label: server == null
                      ? AppText.of(context).useServer
                      : AppText.of(context).useNamedServer(server.displayName),
                  onPressed: server == null
                      ? null
                      : () {
                          final DevicesController controller = ref.read(
                            devicesControllerProvider.notifier,
                          );
                          controller.selectServer(server.code);
                          if (profileCode != null) {
                            controller.selectProfile(profileCode);
                          }
                          Navigator.of(context).maybePop();
                        },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  static AvailableServer? _serverIn(DevicesState state, String? code) {
    if (code == null) {
      return null;
    }
    for (final AvailableServer server in state.servers) {
      if (server.code == code) {
        return server;
      }
    }
    return null;
  }

  /// Unreachable servers are dimmed rather than hidden. The user is still
  /// entitled to them, and dropping one from the list would look like the
  /// account had lost access rather than like a port being blocked today.
  static Color? _latencyColor(ServerLatency? latency, NebulaPalette palette) {
    if (latency == null || latency.status == LatencyStatus.reachable) {
      return null;
    }
    return palette.textMuted;
  }

  /// `de-fra-1 · 3 protocols`, pluralised, because "1 protocols" is the kind
  /// of thing that makes a careful design look careless.
  static String _serverMeta(AppText text, AvailableServer server) {
    if (server.maintenance) {
      return '${server.code} · ${text.serverUnderMaintenance}';
    }
    // A group of this device's own links: how many, not an internal code.
    if (isOwnLinkCode(server.code) && server.publicHost.isEmpty) {
      return text.freeSubscriptionCount(server.profiles.length);
    }
    return '${server.code} · ${text.protocolCount(server.profiles.length)}';
  }
}

/// A protocol's name with its last test result, as v2ray shows it: the
/// delay in milliseconds, or -1 ms when no answer came back.
String _chipLabel(AppText text, String code, ProtocolDelay? delay) {
  if (delay == null || delay.outcome == DelayOutcome.testing) {
    return code;
  }
  final String latency =
      '$code · ${text.latencyMilliseconds(delay.milliseconds ?? -1)}';
  final double? megabits = delay.megabits;
  if (megabits == null) {
    return latency;
  }
  // Nothing arrived: 0, the figure that says why the route does not work.
  final double shown = megabits < 0 ? 0 : megabits;
  return '$latency · ${text.speedMegabits(shown < 10 ? shown.toStringAsFixed(1) : shown.round().toString())}';
}

/// The protocol section's heading, doubling as the control that tests every
/// protocol listed under it.
class _ProtocolHeader extends StatelessWidget {
  const _ProtocolHeader({
    required this.title,
    required this.pinging,
    required this.tested,
    required this.canMeasure,
    required this.onTest,
  });

  final String title;
  final bool pinging;
  final bool tested;
  final bool canMeasure;
  final VoidCallback onTest;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return Row(
      children: <Widget>[
        Expanded(child: SectionHeader(title)),
        if (pinging)
          const SizedBox(
            height: 14,
            width: 14,
            child: CircularProgressIndicator(strokeWidth: 2),
          )
        else
          TextButton(
            // Same rule as the server test above: with the tunnel up, a
            // request could go through it and report on the wrong path.
            onPressed: canMeasure ? onTest : null,
            child: Text(
              canMeasure
                  ? (tested
                        ? AppText.of(context).latencyTestAgain
                        : AppText.of(context).latencyTest)
                  : AppText.of(context).latencyDisconnectToTest,
              style: TextStyle(
                color: canMeasure ? palette.blueText : palette.textMuted,
              ),
            ),
          ),
      ],
    );
  }
}

/// The list header, doubling as the control that measures.
///
/// One line rather than a button in the app bar: measuring is something a
/// user does while looking at this list and comparing rows, so the trigger
/// belongs beside the thing it changes.
class _LatencyHeader extends StatelessWidget {
  const _LatencyHeader({
    required this.count,
    required this.freeMode,
    required this.latency,
    required this.canMeasure,
    required this.onMeasure,
  });

  final int count;

  /// Nothing is "permitted" without an account: the relays and lists here
  /// are simply available.
  final bool freeMode;
  final ServerLatencyState latency;
  final bool canMeasure;
  final VoidCallback onMeasure;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return Row(
      children: <Widget>[
        Expanded(
          child: SectionHeader(
            freeMode
                ? AppText.of(context).serversAvailable(count)
                : AppText.of(context).serversPermitted(count),
          ),
        ),
        if (latency.isMeasuring)
          const SizedBox(
            height: 14,
            width: 14,
            child: CircularProgressIndicator(strokeWidth: 2),
          )
        else
          TextButton(
            // Disabled rather than hidden while connected, so the control
            // does not appear and vanish as the tunnel comes up.
            onPressed: canMeasure ? onMeasure : null,
            child: Text(
              canMeasure
                  ? (latency.hasResults
                        ? AppText.of(context).latencyTestAgain
                        : AppText.of(context).latencyTest)
                  : AppText.of(context).latencyDisconnectToTest,
              style: TextStyle(
                color: canMeasure ? palette.blueText : palette.textMuted,
              ),
            ),
          ),
      ],
    );
  }
}
