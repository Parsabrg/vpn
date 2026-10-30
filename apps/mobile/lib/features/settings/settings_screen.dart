import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/app_info.dart';
import '../../core/routing/route_paths.dart';
import '../../core/settings/advanced_settings_controller.dart';
import '../../core/settings/locale_controller.dart';
import '../../core/settings/protection_controller.dart';
import '../../core/split_tunnel/split_tunnel_controller.dart';
import '../../core/storage/advanced_settings_store.dart';
import '../../core/storage/protection_preference_store.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/theme/theme_mode_controller.dart';
import '../../core/theme/type_scale.dart';
import '../../core/updates/update_check.dart';
import '../../core/widgets/panel/panel_atoms.dart';
import '../../core/widgets/panel/panel_controls.dart';
import '../../core/window/login_item.dart';
import '../../core/wireguard/native_tunnel_channel.dart';
import '../../l10n/app_localizations.dart';

/// Three sections: appearance, protection, about.
///
/// The kill switch is a row here rather than the two-paragraph explanation it
/// replaces. The explanation was correct and nobody read it; the row states
/// the platform's current answer -- `Android setting · off` -- and opens the
/// screen where it can actually be changed. The reasoning moves into the sheet
/// behind the row, for whoever wants it.
class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final AppText text = AppText.of(context);
    final NebulaPalette palette = context.palette;
    final ThemeMode mode = ref.watch(themeModeProvider);
    final ProtectionPreferences protection = ref.watch(
      protectionControllerProvider,
    );
    final ProtectionController controller = ref.read(
      protectionControllerProvider.notifier,
    );

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: AppBar(title: Text(text.settingsTitle)),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          children: <Widget>[
            const SizedBox(height: 8),
            SectionHeader(text.sectionAppearance),
            const SizedBox(height: 12),
            PanelSegmented<ThemeMode>(
              semanticsLabel: text.themeModeLabel,
              segments: <(ThemeMode, String)>[
                (ThemeMode.light, text.themeLight),
                (ThemeMode.dark, text.themeDark),
                (ThemeMode.system, text.themeSystem),
              ],
              selected: mode,
              onChanged: (ThemeMode next) =>
                  ref.read(themeModeProvider.notifier).setMode(next),
            ),
            const SizedBox(height: 12),
            _LanguageRow(text: text),

            const SizedBox(height: 28),
            SectionHeader(text.sectionProtection),
            const SizedBox(height: 4),
            PanelToggleRow(
              title: text.connectOnLaunch,
              meta: text.connectOnLaunchMeta,
              value: protection.connectOnLaunch,
              onChanged: (bool enabled) =>
                  controller.setConnectOnLaunch(enabled: enabled),
            ),
            if (defaultTargetPlatform == TargetPlatform.android)
              PanelToggleRow(
                title: text.reconnectAfterRestart,
                meta: text.reconnectAfterRestartMeta,
                value: protection.reconnectAfterRestart,
                onChanged: (bool enabled) =>
                    controller.setReconnectAfterRestart(enabled: enabled),
              )
            else
              // Windows and Linux have no restart receiver; the system
              // starts the app at sign-in instead, and holds the setting.
              PanelToggleRow(
                title: text.startAtLogin,
                meta: text.startAtLoginMeta,
                value: ref.watch(loginItemEnabledProvider).value ?? false,
                onChanged: (bool enabled) async {
                  await ref.read(loginItemProvider).set(enabled: enabled);
                  ref.invalidate(loginItemEnabledProvider);
                },
              ),
            PanelToggleRow(
              title: text.notificationSpeed,
              meta: text.notificationSpeedMeta,
              value: protection.notificationSpeed,
              onChanged: (bool enabled) =>
                  controller.setNotificationSpeed(enabled: enabled),
            ),
            PanelToggleRow(
              title: text.allowLocalNetwork,
              meta: text.allowLocalNetworkMeta,
              value: protection.bypassLocalNetwork,
              onChanged: (bool enabled) =>
                  controller.setBypassLocalNetwork(enabled: enabled),
            ),
            PanelExternalRow(
              title: text.splitTunneling,
              meta: _splitTunnelMeta(
                text,
                ref.watch(splitTunnelControllerProvider),
              ),
              onTap: () => context.push(RoutePaths.homeSplitTunnel),
            ),
            PanelToggleRow(
              title: text.iranDirect,
              meta: text.iranDirectMeta,
              value: ref.watch(advancedSettingsControllerProvider).iranDirect,
              onChanged: (bool enabled) => ref
                  .read(advancedSettingsControllerProvider.notifier)
                  .setIranDirect(enabled: enabled),
            ),
            PanelExternalRow(
              title: text.bypassDomains,
              meta: _bypassDomainsMeta(
                text,
                ref.watch(advancedSettingsControllerProvider).bypassDomains,
              ),
              onTap: () => context.push(RoutePaths.homeBypassDomains),
            ),
            PanelToggleRow(
              title: text.localProxyMode,
              meta: text.localProxyModeMeta,
              value:
                  ref
                      .watch(advancedSettingsControllerProvider)
                      .connectionMode ==
                  ConnectionMode.localProxy,
              onChanged: (bool enabled) => ref
                  .read(advancedSettingsControllerProvider.notifier)
                  .setConnectionMode(
                    enabled ? ConnectionMode.localProxy : ConnectionMode.vpn,
                  ),
            ),
            if (ref.watch(advancedSettingsControllerProvider).connectionMode ==
                ConnectionMode.localProxy)
              const _LocalProxyPortRow(),
            PanelToggleRow(
              title: text.routingSanctionsOnly,
              meta: text.routingSanctionsOnlyMeta,
              value:
                  ref.watch(advancedSettingsControllerProvider).routingMode ==
                  RoutingMode.sanctionedOnly,
              onChanged: (bool enabled) => ref
                  .read(advancedSettingsControllerProvider.notifier)
                  .setRoutingMode(
                    enabled
                        ? RoutingMode.sanctionedOnly
                        : RoutingMode.everything,
                  ),
            ),
            if (defaultTargetPlatform == TargetPlatform.android)
              _AndroidKillSwitchRow(onTap: () => _openKillSwitch(context, text))
            else
              // Windows and Linux: the app's own, through the elevated
              // helper. Takes effect from the next connection.
              PanelToggleRow(
                title: text.killSwitch,
                meta: text.killSwitchDesktopMeta,
                value: protection.blockWhenVpnDrops,
                isLast: true,
                onChanged: (bool enabled) =>
                    controller.setBlockWhenVpnDrops(enabled: enabled),
              ),

            const SizedBox(height: 28),
            SectionHeader(text.sectionDiagnostics),
            const SizedBox(height: 4),
            PanelExternalRow(
              title: text.connectionLog,
              meta: text.connectionLogMeta,
              onTap: () => context.push(RoutePaths.homeConnectionLog),
            ),
            PanelExternalRow(
              title: text.sectionDiagnostics,
              meta: text.diagnosticsMeta,
              isLast: true,
              onTap: () => context.push(RoutePaths.homeDiagnostics),
            ),

            const SizedBox(height: 28),
            SectionHeader(text.sectionAdvanced),
            const SizedBox(height: 4),
            PanelExternalRow(
              title: text.tunnelOptions,
              meta: ref.watch(advancedSettingsControllerProvider).isDefault
                  ? text.tunnelOptionsDefault
                  : text.tunnelOptionsCustomised,
              onTap: () => context.push(RoutePaths.homeAdvanced),
            ),
            PanelExternalRow(
              title: text.cleanIp,
              meta:
                  ref.watch(advancedSettingsControllerProvider).cleanIp ??
                  text.cleanIpAutomatic,
              isLast: true,
              onTap: () => context.push(RoutePaths.homeCleanIp),
            ),

            const SizedBox(height: 28),
            SectionHeader(text.sectionAbout),
            const SizedBox(height: 4),
            PanelToggleRow(
              title: text.checkForUpdates,
              meta: text.checkForUpdatesMeta,
              value: ref.watch(updateChecksProvider),
              onChanged: (bool enabled) => ref
                  .read(updateChecksProvider.notifier)
                  .setEnabled(enabled: enabled),
            ),
            PanelExternalRow(
              title: text.openSourceLicenses,
              meta: text.openSourceLicensesMeta,
              onTap: () => showLicensePage(
                context: context,
                applicationName: 'Nebula VPN',
                applicationLegalese: 'GPL-3.0-or-later',
              ),
            ),
            const _VersionRow(),
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }

  /// Explains first, then opens Android's own screen.
  ///
  /// The explanation is not optional detail: Android's always-on and
  /// block-without-VPN switches are the only real kill switch, no ordinary app
  /// can turn them on for itself, and a user who taps this expecting a toggle
  /// needs to know why they are being sent elsewhere before they get there.
  static Future<void> _openKillSwitch(
    BuildContext context,
    AppText text,
  ) async {
    final ScaffoldMessengerState messenger = ScaffoldMessenger.of(context);

    final bool? proceed = await showModalBottomSheet<bool>(
      context: context,
      // Without this the sheet is capped at 9/16 of the screen and this
      // explanation overflows it -- which clips the buttons rather than
      // scrolling, so the sheet becomes impossible to dismiss on a short
      // screen or at a large text scale.
      isScrollControlled: true,
      backgroundColor: context.palette.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(14)),
      ),
      builder: (BuildContext context) => const _KillSwitchSheet(),
    );

    if (proceed != true) {
      return;
    }
    final bool opened = await const NativeTunnelChannel().openVpnSettings();
    if (!opened) {
      messenger.showSnackBar(
        SnackBar(content: Text(text.killSwitchCouldNotOpen)),
      );
    }
  }
}

/// Android's always-on and block-without-VPN switches for this app, read
/// from Android each time the row is built or the app comes back to the
/// front (from Android's VPN settings, typically).
final androidKillSwitchProvider =
    FutureProvider.autoDispose<({bool alwaysOn, bool lockdown})?>(
      (Ref ref) => const NativeTunnelChannel().killSwitch(),
    );

/// The Android kill switch row: what Android has switched on, never assumed.
/// It used to say "off" while the owner's phone had both switches on, and
/// then "on" after they were turned off.
class _AndroidKillSwitchRow extends ConsumerStatefulWidget {
  const _AndroidKillSwitchRow({required this.onTap});

  final VoidCallback onTap;

  @override
  ConsumerState<_AndroidKillSwitchRow> createState() =>
      _AndroidKillSwitchRowState();
}

class _AndroidKillSwitchRowState extends ConsumerState<_AndroidKillSwitchRow> {
  late final AppLifecycleListener _lifecycle;

  @override
  void initState() {
    super.initState();
    _lifecycle = AppLifecycleListener(
      onResume: () => ref.invalidate(androidKillSwitchProvider),
    );
  }

  @override
  void dispose() {
    _lifecycle.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    final NebulaPalette palette = context.palette;
    final ({bool alwaysOn, bool lockdown})? state = ref
        .watch(androidKillSwitchProvider)
        .value;
    return PanelExternalRow(
      title: text.killSwitch,
      meta: switch (state) {
        (alwaysOn: true, lockdown: true) => text.killSwitchMetaOn,
        (alwaysOn: true, lockdown: false) => text.killSwitchMetaAlwaysOn,
        (alwaysOn: false, lockdown: _) => text.killSwitchMeta,
        null => text.killSwitchMetaUnknown,
      },
      // Amber until Android blocks traffic without the VPN -- the one
      // protection the app cannot switch on itself.
      metaColor: state?.lockdown == true ? palette.textMuted : palette.amberDim,
      isLast: true,
      onTap: widget.onTap,
    );
  }
}

class _KillSwitchSheet extends StatelessWidget {
  const _KillSwitchSheet();

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    return SafeArea(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(24, 24, 24, 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Text(
              text.killSwitch,
              style: type.navTitle.copyWith(color: palette.textPrimary),
            ),
            const SizedBox(height: 12),
            Text(
              text.killSwitchBody,
              style: type.rowLabel.copyWith(
                color: palette.textMuted,
                height: 19 / 13,
              ),
            ),
            const SizedBox(height: 20),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: Text(text.killSwitchOpen),
            ),
            const SizedBox(height: 8),
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: Text(text.killSwitchNotNow),
            ),
          ],
        ),
      ),
    );
  }
}

/// The app's version, read from the build rather than written down.
///
/// A hardcoded string here is wrong within one release, and a stale version in
/// a bug report costs more than the row is worth.
class _VersionRow extends StatelessWidget {
  const _VersionRow();

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    return Container(
      decoration: BoxDecoration(
        border: Border(
          top: BorderSide(color: palette.hairline),
          bottom: BorderSide(color: palette.hairline),
        ),
      ),
      padding: const EdgeInsets.symmetric(vertical: 18),
      child: Row(
        children: <Widget>[
          Text(
            AppText.of(context).version,
            style: type.rowLabel.copyWith(color: palette.textMuted),
          ),
          const Spacer(),
          Text(
            kClientVersion,
            style: type.rowValue.copyWith(color: palette.textPrimary),
          ),
        ],
      ),
    );
  }
}

/// `off` rather than a blank when nothing is excluded: an empty meta line
/// reads as "not implemented yet", and this is a setting with a real state.
String _bypassDomainsMeta(AppText text, List<String> domains) {
  return domains.isEmpty
      ? text.bypassDomainsNone
      : text.bypassDomainsCount(domains.length);
}

String _splitTunnelMeta(AppText text, Set<String> excluded) {
  if (excluded.isEmpty) {
    return text.splitTunnelingOff;
  }
  // Pluralised by the localisation rather than by an inline ternary: the rule
  // is not the same in every language, and "1 apps" is the kind of thing that
  // makes a careful design look careless.
  return text.splitTunnelingCount(excluded.length);
}

/// Choosing the language, and the one row that must stay findable.
///
/// Each language is named in its own words -- English, فارسی -- so somebody
/// who has landed in a language they cannot read can still recognise the way
/// out. A list that said "Persian" and "انگلیسی" would be unreadable to
/// exactly the person who needs it.
class _LanguageRow extends ConsumerWidget {
  const _LanguageRow({required this.text});

  final AppText text;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final AppLanguage? chosen = ref.watch(localeControllerProvider);

    return PanelExternalRow(
      title: text.language,
      meta: chosen?.endonym ?? text.languageFollowsDevice,
      isLast: true,
      onTap: () => _choose(context, ref, chosen),
    );
  }

  Future<void> _choose(
    BuildContext context,
    WidgetRef ref,
    AppLanguage? chosen,
  ) async {
    // A one-field record, so "follow the device" (a record holding null) is
    // distinguishable from dismissing the sheet (no record at all). With a
    // bare nullable both came back as null, and tapping outside the sheet
    // to cancel quietly reset the language to the device's.
    final (AppLanguage?,)? picked = await showModalBottomSheet<(AppLanguage?,)>(
      context: context,
      backgroundColor: context.palette.surface,
      // Ten languages and the device option are taller than a sheet's
      // default height; scrolling beats clipping the last few.
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(14)),
      ),
      builder: (BuildContext context) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          children: <Widget>[
            // "Follow the device" is an option rather than an absence, so
            // going back to it is as easy as leaving it.
            _LanguageOption(
              label: text.languageSystem,
              selected: chosen == null,
              onTap: () => Navigator.of(context).pop((null,)),
            ),
            for (final AppLanguage language in AppLanguage.values)
              _LanguageOption(
                label: language.endonym,
                selected: chosen == language,
                onTap: () => Navigator.of(context).pop((language,)),
              ),
            const SizedBox(height: 8),
          ],
        ),
      ),
    );
    if (picked != null && context.mounted) {
      await ref.read(localeControllerProvider.notifier).choose(picked.$1);
    }
  }
}

/// One language in the sheet.
///
/// A tick rather than a radio: the deprecated group API aside, the list is
/// short enough that the selected row reads faster with a mark beside it than
/// with a column of empty circles.
class _LanguageOption extends StatelessWidget {
  const _LanguageOption({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return ListTile(
      title: Text(label, style: TextStyle(color: palette.textPrimary)),
      trailing: selected ? Icon(Icons.check, color: palette.blueText) : null,
      onTap: onTap,
    );
  }
}

/// The local proxy's port, chosen by hand the way other clients let you.
///
/// Apps are set up with this number, so it is the person's to pick rather than
/// the app's. Checked before it is kept: a port no app can be pointed at would
/// only surface later, as a proxy that never starts.
class _LocalProxyPortRow extends ConsumerWidget {
  const _LocalProxyPortRow();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final int port = ref
        .watch(advancedSettingsControllerProvider)
        .localProxyPort;
    return PanelExternalRow(
      title: AppText.of(context).localProxyPort,
      meta: '127.0.0.1:$port',
      onTap: () => _edit(context, ref, port),
    );
  }

  Future<void> _edit(BuildContext context, WidgetRef ref, int current) async {
    final TextEditingController field = TextEditingController(text: '$current');
    String? error;
    await showDialog<void>(
      context: context,
      builder: (BuildContext context) {
        final AppText text = AppText.of(context);
        return StatefulBuilder(
          builder: (BuildContext context, StateSetter setState) {
            Future<void> save() async {
              final int? port = int.tryParse(field.text.trim());
              final bool taken =
                  port != null &&
                  await ref
                      .read(advancedSettingsControllerProvider.notifier)
                      .setLocalProxyPort(port);
              if (!context.mounted) {
                return;
              }
              if (taken) {
                Navigator.of(context).pop();
              } else {
                setState(() => error = text.localProxyPortInvalid);
              }
            }

            return AlertDialog(
              title: Text(text.localProxyPort),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: <Widget>[
                  Text(
                    text.localProxyPortHelp,
                    style: const TextStyle(fontSize: 13),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    // Not a credential: no password manager offering one here.
                    autofillHints: null,
                    controller: field,
                    autofocus: true,
                    keyboardType: TextInputType.number,
                    decoration: InputDecoration(
                      border: const OutlineInputBorder(),
                      errorText: error,
                      // It is a sentence; one line cut it off at "1024 ...".
                      errorMaxLines: 3,
                    ),
                    onSubmitted: (_) => save(),
                  ),
                ],
              ),
              actions: <Widget>[
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: Text(text.cancel),
                ),
                TextButton(onPressed: save, child: Text(text.save)),
              ],
            );
          },
        );
      },
    );
    field.dispose();
  }
}
