import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/servers/server_repository.dart';
import '../../core/storage/storage_providers.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/theme/type_scale.dart';
import '../../core/widgets/panel/panel_atoms.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/panel/panel_row.dart';
import '../../l10n/app_localizations.dart';
import '../devices/devices_controller.dart';
import '../devices/devices_state.dart';
import 'client_summary.dart';

/// What the server provisioned, for the peer-only state.
///
/// Reached from the "Configuration" row when a device is registered but has
/// no tunnel. Its job is to make an unusable state useful: the client exists
/// and is valid, so hand it over in a form that can be pasted into something
/// that *can* run it, rather than leaving the user with a dead screen.
class ConfigurationScreen extends ConsumerWidget {
  const ConfigurationScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final DevicesState state = ref.watch(devicesControllerProvider);
    final NebulaPalette palette = context.palette;
    final XrayClientResult? client = state.xrayClient;

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(AppText.of(context).configurationTitle),
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
                    const _PeerOnlyNotice(),
                    const SizedBox(height: 24),
                    if (client == null)
                      Text(
                        AppText.of(context).noClientConfiguration,
                        style: context.type.rowLabel.copyWith(
                          color: palette.textMuted,
                        ),
                      )
                    else ...<Widget>[
                      SectionHeader(AppText.of(context).xrayClient),
                      const SizedBox(height: 4),
                      PanelRowGroup(
                        rows: <PanelRow>[
                          PanelRow(
                            label: AppText.of(context).rowAddress,
                            value: '${client.serverAddress} : ${client.port}',
                          ),
                          PanelRow(label: 'SNI', value: client.sni),
                          PanelRow(
                            label: AppText.of(context).rowTransport,
                            value:
                                '${client.transport} / ${client.transportSecurity}',
                          ),
                          if (client.path != null)
                            PanelRow(
                              label: AppText.of(context).rowPath,
                              value: client.path!,
                            ),
                          PanelRow(
                            label: 'UUID',
                            value: truncateUuid(client.uuid),
                          ),
                        ],
                      ),
                    ],
                    const SizedBox(height: 24),
                  ],
                ),
              ),
              if (client != null)
                Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: PanelCta(
                    label: AppText.of(context).copy,
                    icon: Icons.content_copy,
                    style: CtaStyle.warning,
                    onPressed: () => _copy(context, client),
                  ),
                ),
              Padding(
                padding: const EdgeInsets.only(bottom: 16),
                child: TextButton(
                  onPressed: () => _releasePeer(context, ref, state),
                  child: Text(AppText.of(context).releasePeer),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  static Future<void> _copy(
    BuildContext context,
    XrayClientResult client,
  ) async {
    await Clipboard.setData(ClipboardData(text: clientSummary(client)));
    if (!context.mounted) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(AppText.of(context).configurationCopied)),
    );
  }

  /// Releasing is destructive and not obviously so from the button, so it
  /// confirms first. The device keeps working until the next refresh, which
  /// is exactly the kind of delay that makes an accidental tap hard to
  /// connect to its consequence later.
  static Future<void> _releasePeer(
    BuildContext context,
    WidgetRef ref,
    DevicesState state,
  ) async {
    final bool? confirmed = await showDialog<bool>(
      context: context,
      builder: (BuildContext context) => AlertDialog(
        title: Text(AppText.of(context).releasePeerQuestion),
        content: Text(AppText.of(context).releasePeerBody),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(AppText.of(context).cancel),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(AppText.of(context).release),
          ),
        ],
      ),
    );

    if (confirmed != true || !context.mounted) {
      return;
    }
    final String? deviceId = ref.read(deviceIdStoreProvider).read();
    if (deviceId == null) {
      return;
    }
    await ref.read(devicesControllerProvider.notifier).disconnect(deviceId);
    if (context.mounted) {
      Navigator.of(context).maybePop();
    }
  }
}

/// The dashed amber box that says why this screen exists.
class _PeerOnlyNotice extends StatelessWidget {
  const _PeerOnlyNotice();

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return DecoratedBox(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: palette.amber.withValues(alpha: 0.5)),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Icon(Icons.warning_amber_rounded, size: 20, color: palette.amber),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                AppText.of(context).peerOnlyNotice,
                style: context.type.rowLabel.copyWith(
                  color: palette.amberText,
                  height: 19 / 13,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
