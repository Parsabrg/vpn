import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/account/account_repository.dart';
import '../../core/auth/auth_notifier.dart';
import '../../core/auth/auth_state.dart';
import '../../core/auth/user_principal.dart';
import '../../core/format/bidi.dart';
import '../../core/format/bytes.dart';
import '../../core/format/dates.dart';
import '../../core/routing/route_paths.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/theme/type_scale.dart';
import '../../core/updates/update_check.dart';
import '../../core/widgets/panel/panel_atoms.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/panel/panel_row.dart';
import '../../core/widgets/refresh_while_visible.dart';
import '../../core/wireguard/native_tunnel_channel.dart';
import '../../l10n/app_localizations.dart';
import '../devices/devices_controller.dart';
import 'account_controller.dart';

/// The account: who you are, what you have used, until when, and the way out.
///
/// The usage figures are measured on the server, every minute, and fetched
/// again while this screen is showing -- see _AccountScreenState.
class AccountScreen extends ConsumerStatefulWidget {
  const AccountScreen({super.key});

  @override
  ConsumerState<AccountScreen> createState() => _AccountScreenState();
}

class _AccountScreenState extends ConsumerState<AccountScreen>
    with RefreshWhileVisible<AccountScreen> {
  @override
  Duration get refreshInterval => ref.read(accountRefreshIntervalProvider);

  @override
  void refresh() {
    unawaited(ref.read(accountControllerProvider.notifier).refresh());
  }

  @override
  Widget build(BuildContext context) {
    final AccountState state = ref.watch(accountControllerProvider);
    final NebulaPalette palette = context.palette;

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
                child: Text(
                  AppText.of(context).accountHeading,
                  style: context.type.wordmark.copyWith(
                    color: palette.textMuted,
                  ),
                ),
              ),
              Expanded(child: _body(context, state)),
              Padding(
                padding: const EdgeInsets.only(bottom: 16),
                child: PanelCta(
                  label: AppText.of(context).signOut,
                  style: CtaStyle.secondary,
                  onPressed: () async {
                    // Disconnect while the session can still tell the server.
                    await ref
                        .read(devicesControllerProvider.notifier)
                        .disconnectBeforeSignOut();
                    await ref.read(authNotifierProvider.notifier).logout();
                  },
                ),
              ),
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
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            SkeletonBar(width: 180, height: 34),
            SizedBox(height: 32),
            _SkeletonRow(),
            _SkeletonRow(),
            _SkeletonRow(),
          ],
        );

      case AccountLoadStatus.failed:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            StatusLine(tone: StatusTone.error, text: text.statusNoConnection),
            const SizedBox(height: 12),
            Text(
              state.loadErrorMessage ?? text.couldNotLoadAccount,
              style: type.rowLabel.copyWith(color: palette.textMuted),
            ),
            const SizedBox(height: 20),
            TextButton(
              onPressed: () =>
                  ref.read(accountControllerProvider.notifier).load(),
              child: Text(text.ctaTryAgain),
            ),
            // Settings live on this device and need no server, so they stay
            // reachable when the account cannot load. They used to vanish with
            // it -- when the server is unreachable, which is exactly when
            // someone needs them (fragment, DNS, the local network). Seen on
            // a phone.
            const SizedBox(height: 28),
            PanelRowGroup(
              rows: <PanelRow>[
                PanelRow(
                  label: text.rowSettings,
                  value: text.open,
                  onTap: () => context.push(RoutePaths.homeSettings),
                ),
              ],
            ),
          ],
        );

      case AccountLoadStatus.loaded:
        return _Details(account: state.account!);
    }
  }
}

class _Details extends ConsumerWidget {
  const _Details({required this.account});

  final AccountSummary account;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final AppText text = AppText.of(context);
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    final AuthState authState = ref.watch(authNotifierProvider);
    final UserPrincipal? me = authState is AuthAuthenticated
        ? authState.me
        : null;

    final bool expired = account.hasExpiredAt(DateTime.now());
    final AvailableUpdate? update = ref.watch(availableUpdateProvider).value;

    return ListView(
      children: <Widget>[
        Text(
          account.username ?? account.email,
          style: type.authTitle.copyWith(color: palette.textPrimary),
        ),
        const SizedBox(height: 8),
        Text(
          text.devicesOfLimit(account.devicesInUse, account.deviceLimit),
          style: type.topBarMeta.copyWith(color: palette.textMuted),
        ),
        const SizedBox(height: 28),
        _UsageBlock(account: account),
        const SizedBox(height: 28),
        PanelRowGroup(
          rows: <PanelRow>[
            PanelRow(
              label: text.rowAccessUntil,
              // Three different things, and they must not collapse into one
              // reassuring string: an expiry in the future, one that has
              // passed, and no expiry at all.
              value: account.expiresAt == null
                  ? text.noExpiry
                  : formatLongDate(context, account.expiresAt!),
              valueColor: expired ? palette.amberText : null,
            ),
            PanelRow(
              label: text.rowEmail,
              value: account.email,
              valueIsMono: false,
            ),
            PanelRow(
              label: text.rowStatus,
              value: _stateLabel(text, account.state),
            ),
            if (me != null)
              PanelRow(
                label: text.rowSessionId,
                value: _truncate(me.sessionId),
              ),
            if (update != null)
              PanelRow(
                label: text.rowUpdate,
                value: text.updateAvailable(update.version),
                valueColor: palette.blueText,
                onTap: () => const NativeTunnelChannel().openUrl(update.page),
              ),
            PanelRow(
              label: text.rowPassword,
              value: text.change,
              onTap: () => context.push(RoutePaths.homeChangePassword),
            ),
            // Settings is not a tab -- this is the way in.
            PanelRow(
              label: text.rowSettings,
              value: text.open,
              onTap: () => context.push(RoutePaths.homeSettings),
            ),
          ],
        ),
        const SizedBox(height: 16),
        PanelRowGroup(
          rows: <PanelRow>[
            PanelRow(
              label: text.deleteAccountRow,
              value: text.open,
              onTap: () => context.push(RoutePaths.homeDeleteAccount),
            ),
          ],
        ),
        if (expired) ...<Widget>[
          const SizedBox(height: 16),
          Text(
            text.accessExpired,
            style: type.listMeta.copyWith(color: palette.amberDim),
          ),
        ],
        const SizedBox(height: 24),
      ],
    );
  }

  /// The account's state as a person would say it. The server sends a
  /// code; an unrecognised one is shown as sent rather than hidden, so a
  /// state added later still appears.
  static String _stateLabel(AppText text, String state) => switch (state) {
    'active' => text.accountStateActive,
    'pending_activation' => text.accountStatePendingActivation,
    'suspended' => text.accountStateSuspended,
    'disabled' => text.accountStateDisabled,
    _ => state,
  };

  /// Session ids are long and the whole value is never needed on screen.
  static String _truncate(String value) {
    if (value.length <= 13) {
      return value;
    }
    return '${value.substring(0, 8)}…${value.substring(value.length - 4)}';
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
          SkeletonBar(width: 72, height: 12),
          Spacer(),
          SkeletonBar(width: 120, height: 12),
        ],
      ),
    );
  }
}

/// What this account has used, and what is left of its allowance.
///
/// Two shapes, because an unmetered account has no "left" to show. Rendering
/// a bar for it -- full or empty -- would state something untrue about a limit
/// that does not exist, so the metered case gets the figure and the bar and
/// the unmetered case gets the total on its own.
///
/// The total is everything the account has ever used, on every device. The
/// allowance figures are measured from where the allowance began, so a metered
/// account whose total is more than that says so on a line of its own.
class _UsageBlock extends StatelessWidget {
  const _UsageBlock({required this.account});

  final AccountSummary account;

  @override
  Widget build(BuildContext context) {
    final AppText text = AppText.of(context);
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;

    if (!account.isMetered) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(
            formatBytes(account.lifetimeBytes),
            textDirection: TextDirection.ltr,
            style: type.quotaFigure.copyWith(color: palette.textPrimary),
          ),
          const SizedBox(height: 4),
          Text(
            text.usedNoLimit,
            style: type.topBarMeta.copyWith(color: palette.textMuted),
          ),
        ],
      );
    }

    final int remaining = account.remainingBytes ?? 0;
    final double fraction = account.usedFraction ?? 0;
    // Amber once the allowance is gone. Nothing else on this screen changes:
    // running out of traffic is not an error, it is a state worth noticing.
    final bool exhausted = remaining == 0;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        Text(
          formatBytes(remaining),
          // Drawn "KB 8.9" on the phone under Persian without this.
          textDirection: TextDirection.ltr,
          style: type.quotaFigure.copyWith(
            color: exhausted ? palette.amberText : palette.textPrimary,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          exhausted ? text.quotaNothingLeft : text.quotaLeft,
          style: type.topBarMeta.copyWith(
            color: exhausted ? palette.amberDim : palette.textMuted,
          ),
        ),
        const SizedBox(height: 18),
        ClipRRect(
          borderRadius: BorderRadius.circular(2),
          child: LinearProgressIndicator(
            value: fraction,
            minHeight: 4,
            backgroundColor: palette.hairline,
            valueColor: AlwaysStoppedAnimation<Color>(
              exhausted ? palette.amber : palette.blue,
            ),
          ),
        ),
        const SizedBox(height: 10),
        Row(
          children: <Widget>[
            Text(
              text.quotaUsed(
                embedLeftToRight(
                  context,
                  formatBytePair(account.usedBytes, account.quotaBytes!),
                ),
              ),
              style: type.listMeta.copyWith(color: palette.textMuted),
            ),
          ],
        ),
        // Only when it says something the line above does not: until an
        // allowance is granted on top of earlier use, the two are the same.
        if (account.lifetimeBytes > account.usedBytes) ...<Widget>[
          const SizedBox(height: 4),
          Text(
            text.usedInTotal(
              embedLeftToRight(context, formatBytes(account.lifetimeBytes)),
            ),
            style: type.listMeta.copyWith(color: palette.textMuted),
          ),
        ],
      ],
    );
  }
}
