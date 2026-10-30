import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/split_tunnel/installed_apps.dart';
import '../../core/split_tunnel/split_tunnel_controller.dart';
import '../../core/theme/color_tokens.dart';
import '../../l10n/app_localizations.dart';

/// Choose which apps go around the tunnel instead of through it.
///
/// The list is of exclusions, not inclusions. A person who wants their bank's
/// app outside the tunnel wants everything else inside it, and an inclusion
/// list quietly stops covering anything installed afterwards -- so a newly
/// installed app is protected here by default, which is the safer direction
/// for a tool whose whole job is to carry traffic.
///
/// Changes apply to the next connection. Android fixes the disallow list when
/// the VpnService is established, so a running tunnel cannot be re-scoped
/// without tearing it down, and pretending otherwise would leave somebody
/// believing an app had been excluded while its traffic still went through.
class SplitTunnelScreen extends ConsumerStatefulWidget {
  const SplitTunnelScreen({super.key});

  @override
  ConsumerState<SplitTunnelScreen> createState() => _SplitTunnelScreenState();
}

class _SplitTunnelScreenState extends ConsumerState<SplitTunnelScreen> {
  String _query = '';

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final AsyncValue<List<InstalledApp>> apps = ref.watch(
      installedAppsProvider,
    );
    final Set<String> excluded = ref.watch(splitTunnelControllerProvider);

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(AppText.of(context).splitTunneling),
        actions: <Widget>[
          if (excluded.isNotEmpty)
            TextButton(
              onPressed: () =>
                  ref.read(splitTunnelControllerProvider.notifier).clear(),
              child: Text(AppText.of(context).clear),
            ),
        ],
      ),
      body: SafeArea(
        child: apps.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (Object error, StackTrace _) => _Message(
            // Named plainly. The likely cause is a platform that has no
            // per-app routing at all, and "something went wrong" would send
            // somebody looking for a fault that is not there.
            text: AppText.of(context).appsUnreadable,
          ),
          data: (List<InstalledApp> all) {
            final List<InstalledApp> visible = _matching(all, _query);
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: <Widget>[
                Padding(
                  padding: const EdgeInsets.fromLTRB(24, 12, 24, 4),
                  child: Text(
                    excluded.isEmpty
                        ? AppText.of(context).everyAppTunnelled
                        : AppText.of(context).appsBypassTunnel(excluded.length),
                    style: TextStyle(color: palette.textMuted, fontSize: 13),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 24,
                    vertical: 8,
                  ),
                  child: TextField(
                    // Not a credential: no password manager offering one here.
                    autofillHints: null,
                    decoration: InputDecoration(
                      isDense: true,
                      prefixIcon: const Icon(Icons.search, size: 18),
                      hintText: AppText.of(context).searchApps,
                      border: const OutlineInputBorder(),
                    ),
                    onChanged: (String value) => setState(() => _query = value),
                  ),
                ),
                if (visible.isEmpty)
                  Expanded(
                    child: _Message(text: AppText.of(context).noAppsMatch),
                  )
                else
                  Expanded(
                    child: ListView.builder(
                      padding: const EdgeInsets.symmetric(horizontal: 16),
                      itemCount: visible.length,
                      itemBuilder: (BuildContext context, int index) {
                        final InstalledApp app = visible[index];
                        return _AppRow(
                          app: app,
                          excluded: excluded.contains(app.packageName),
                          onChanged: (bool value) => ref
                              .read(splitTunnelControllerProvider.notifier)
                              .setExcluded(app.packageName, excluded: value),
                        );
                      },
                    ),
                  ),
              ],
            );
          },
        ),
      ),
    );
  }

  /// Matches the label and the package name both. People search for "gmail"
  /// but also paste "com.google.android.gm" off a support page.
  static List<InstalledApp> _matching(List<InstalledApp> all, String query) {
    final String needle = query.trim().toLowerCase();
    if (needle.isEmpty) {
      return all;
    }
    return all
        .where(
          (InstalledApp app) =>
              app.label.toLowerCase().contains(needle) ||
              app.packageName.toLowerCase().contains(needle),
        )
        .toList();
  }
}

class _AppRow extends ConsumerWidget {
  const _AppRow({
    required this.app,
    required this.excluded,
    required this.onChanged,
  });

  final InstalledApp app;
  final bool excluded;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final NebulaPalette palette = context.palette;
    final AsyncValue<Uint8List?> icon = ref.watch(
      appIconProvider(app.packageName),
    );

    return SwitchListTile(
      value: excluded,
      onChanged: onChanged,
      title: Text(app.label, overflow: TextOverflow.ellipsis),
      subtitle: Text(
        app.packageName,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(color: palette.textMuted, fontSize: 11),
      ),
      secondary: SizedBox(
        width: 32,
        height: 32,
        // A missing icon leaves the space rather than collapsing the row,
        // so the list does not jump as icons arrive one at a time.
        child: icon.maybeWhen(
          data: (Uint8List? bytes) =>
              bytes == null ? null : Image.memory(bytes, gaplessPlayback: true),
          orElse: () => null,
        ),
      ),
    );
  }
}

class _Message extends StatelessWidget {
  const _Message({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Text(
          text,
          textAlign: TextAlign.center,
          style: TextStyle(color: context.palette.textMuted),
        ),
      ),
    );
  }
}
