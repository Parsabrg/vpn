import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/account/account_repository.dart';
import '../../core/format/dates.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/theme/type_scale.dart';
import '../../core/widgets/panel/panel_atoms.dart';
import '../../core/widgets/panel/panel_list_row.dart';
import '../../core/widgets/refresh_while_visible.dart';
import '../../l10n/app_localizations.dart';
import '../account/account_controller.dart';

/// View and revoke the devices on this account.
///
/// Scope is deliberately those two things. No renaming, no connecting another
/// device, no reading another device's configuration -- a screen that can act
/// on a device you are not holding should be able to do as little as possible.
class DevicesScreen extends ConsumerStatefulWidget {
  const DevicesScreen({super.key});

  @override
  ConsumerState<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends ConsumerState<DevicesScreen>
    with RefreshWhileVisible<DevicesScreen> {
  // Loaded once, in initState, the list went on showing devices revoked
  // elsewhere for as long as the app stayed open. See RefreshWhileVisible.
  @override
  Duration get refreshInterval => ref.read(accountRefreshIntervalProvider);

  @override
  void refresh() {
    unawaited(ref.read(accountControllerProvider.notifier).refresh());
  }

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    final AccountState state = ref.watch(accountControllerProvider);
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    ref.listen<AccountState>(accountControllerProvider, (
      AccountState? previous,
      AccountState next,
    ) {
      final String? message = next.actionErrorMessage;
      if (message != null && message != previous?.actionErrorMessage) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(message)));
      }
    });

    return Scaffold(
      backgroundColor: palette.bg,
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Padding(
                padding: const EdgeInsets.only(top: 28, bottom: 20),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.baseline,
                  textBaseline: TextBaseline.alphabetic,
                  children: <Widget>[
                    Text(
                      text.devicesHeading,
                      style: type.wordmark.copyWith(color: palette.textMuted),
                    ),
                    const Spacer(),
                    if (state.account != null)
                      Text(
                        text.devicesInUseOfLimit(
                          state.account!.devicesInUse,
                          state.account!.deviceLimit,
                        ),
                        style: type.topBarMeta.copyWith(
                          color: palette.textMuted,
                        ),
                      ),
                  ],
                ),
              ),
              Expanded(child: _body(context, state)),
            ],
          ),
        ),
      ),
    );
  }

  Widget _body(BuildContext context, AccountState state) {
    final AppText text = AppText.of(context);
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    switch (state.loadStatus) {
      case AccountLoadStatus.loading:
        return const Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[_SkeletonDeviceRow(), _SkeletonDeviceRow()],
        );

      case AccountLoadStatus.failed:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            StatusLine(tone: StatusTone.error, text: text.statusNoConnection),
            const SizedBox(height: 12),
            Text(
              state.loadErrorMessage ?? text.couldNotLoadDevices,
              style: type.rowLabel.copyWith(color: palette.textMuted),
            ),
            const SizedBox(height: 20),
            TextButton(
              onPressed: () =>
                  ref.read(accountControllerProvider.notifier).load(),
              child: Text(text.ctaTryAgain),
            ),
          ],
        );

      case AccountLoadStatus.loaded:
        return ListView(
          children: <Widget>[
            for (final AccountDevice device in state.devices)
              PanelListRow(
                title: device.name,
                leading: _platformIcon(device.platform),
                meta: _meta(context, text, device),
                metaColor: device.isCurrent
                    ? palette.blueText
                    : palette.textMuted,
                // The current device has no Revoke: revoking the device you
                // are holding would drop your own tunnel, and the server
                // refuses it anyway.
                action: device.isCurrent
                    ? null
                    : _RevokeAction(
                        device: device,
                        busy: state.revokingDeviceId == device.id,
                      ),
              ),
            const SizedBox(height: 16),
            Text(
              text.revokeFootnote,
              style: type.listMeta.copyWith(color: palette.textMuted),
            ),
            const SizedBox(height: 24),
          ],
        );
    }
  }

  /// `this device · tunnelling` or `peer on de-fra-1 · registered 2 Sep`.
  ///
  /// Says what the server actually reports. A device with no live credential
  /// says so rather than being described as connected somewhere.
  static String _meta(
    BuildContext context,
    AppText text,
    AccountDevice device,
  ) {
    final String where = device.serverCodes.isEmpty
        ? text.deviceNoPeer
        : text.devicePeerOn(device.serverCodes.join(', '));
    if (device.isCurrent) {
      return text.deviceThisDevice(where);
    }
    return text.deviceRegistered(
      where,
      formatShortDate(context, device.registeredAt),
    );
  }

  static IconData _platformIcon(String platform) {
    switch (platform) {
      case 'android':
        return Icons.smartphone;
      case 'windows':
        return Icons.laptop_windows;
      default:
        return Icons.devices_other;
    }
  }
}

class _RevokeAction extends ConsumerWidget {
  const _RevokeAction({required this.device, required this.busy});

  final AccountDevice device;
  final bool busy;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (busy) {
      return SizedBox(
        width: 18,
        height: 18,
        child: CircularProgressIndicator(
          strokeWidth: 2,
          color: context.palette.textMuted,
        ),
      );
    }
    return TextButton(
      onPressed: () => _confirm(context, ref),
      child: Text(AppText.of(context).revoke),
    );
  }

  Future<void> _confirm(BuildContext context, WidgetRef ref) async {
    final bool? confirmed = await showDialog<bool>(
      context: context,
      builder: (BuildContext context) => AlertDialog(
        title: Text(AppText.of(context).revokeDeviceQuestion(device.name)),
        content: Text(AppText.of(context).revokeDeviceBody),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(AppText.of(context).cancel),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(AppText.of(context).revoke),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await ref
          .read(accountControllerProvider.notifier)
          .revokeDevice(device.id);
    }
  }
}

class _SkeletonDeviceRow extends StatelessWidget {
  const _SkeletonDeviceRow();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        border: Border(top: BorderSide(color: context.palette.hairline)),
      ),
      padding: const EdgeInsets.symmetric(vertical: 16),
      child: const Row(
        children: <Widget>[
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              SkeletonBar(width: 120, height: 14),
              SizedBox(height: 6),
              SkeletonBar(width: 168, height: 10),
            ],
          ),
        ],
      ),
    );
  }
}
