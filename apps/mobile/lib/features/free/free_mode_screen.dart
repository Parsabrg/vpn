import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/free/free_mode.dart';
import '../../core/free/subscriptions.dart';
import '../../core/routing/route_paths.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/theme/type_scale.dart';
import '../../core/widgets/panel/panel_cta.dart';
import '../../core/widgets/panel/panel_row.dart';
import '../../l10n/app_localizations.dart';
import '../devices/devices_controller.dart';

/// The third tab with no server: the relays this app connects through, where
/// one's own is added, and the way back to a server.
class FreeModeScreen extends ConsumerStatefulWidget {
  const FreeModeScreen({super.key, this.ownLinks = false});

  /// Signed in to a server: the same links and subscriptions, kept beside
  /// that server's list, without what only free mode has -- its shared
  /// relays, its introduction, and the way back to the door.
  final bool ownLinks;

  @override
  ConsumerState<FreeModeScreen> createState() => _FreeModeScreenState();
}

class _FreeModeScreenState extends ConsumerState<FreeModeScreen> {
  final TextEditingController _field = TextEditingController();
  final TextEditingController _subscriptionField = TextEditingController();
  bool _invalid = false;
  bool _subscriptionInvalid = false;
  bool _refreshing = false;
  late final AppLifecycleListener _lifecycle;

  @override
  void initState() {
    super.initState();
    // What is due, not everything: opening this screen often must not mean
    // asking every list's host each time. Quietly -- no spinner for a check
    // nobody asked for. Again whenever the app comes back to the front: the
    // screen stays built for days, and a list fetched once at build time was
    // never refreshed again, though the screen says "a few times a day".
    unawaited(_refreshDue());
    _lifecycle = AppLifecycleListener(onResume: () => unawaited(_refreshDue()));
  }

  @override
  void dispose() {
    _lifecycle.dispose();
    _field.dispose();
    _subscriptionField.dispose();
    super.dispose();
  }

  Future<void> _refreshDue() async {
    try {
      await ref.read(subscriptionsProvider.notifier).refresh();
      if (mounted) {
        await _reload();
      }
    } catch (_) {
      // A list that could not be refreshed keeps its last good copy.
    }
  }

  Future<void> _refreshSubscriptions({required bool force}) async {
    setState(() => _refreshing = true);
    try {
      await ref.read(subscriptionsProvider.notifier).refresh(force: force);
      await _reload();
    } finally {
      if (mounted) {
        setState(() => _refreshing = false);
      }
    }
  }

  Future<void> _addSubscription() async {
    setState(() => _refreshing = true);
    try {
      final bool taken = await ref
          .read(subscriptionsProvider.notifier)
          .add(_subscriptionField.text);
      if (!mounted) {
        return;
      }
      setState(() => _subscriptionInvalid = !taken);
      if (taken) {
        _subscriptionField.clear();
        await _reload();
      }
    } finally {
      if (mounted) {
        setState(() => _refreshing = false);
      }
    }
  }

  /// Its name in Servers. Empty goes back to the address's host.
  Future<void> _renameSubscription(Subscription subscription) async {
    final AppText text = AppText.of(context);
    final TextEditingController field = TextEditingController(
      text: subscription.label ?? '',
    );
    final String? name = await showDialog<String>(
      context: context,
      builder: (BuildContext context) => AlertDialog(
        title: Text(text.subscriptionRename),
        content: TextField(
          // Not a credential: no password manager offering one here.
          autofillHints: null,
          controller: field,
          autofocus: true,
          maxLength: 40,
          decoration: InputDecoration(
            hintText: Uri.tryParse(subscription.url)?.host,
          ),
          onSubmitted: (String value) => Navigator.of(context).pop(value),
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(MaterialLocalizations.of(context).cancelButtonLabel),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(field.text),
            child: Text(MaterialLocalizations.of(context).okButtonLabel),
          ),
        ],
      ),
    );
    field.dispose();
    if (name == null) {
      return;
    }
    await ref
        .read(subscriptionsProvider.notifier)
        .rename(subscription.url, name);
    await _reload();
  }

  Future<void> _removeSubscription(Subscription subscription) async {
    await ref.read(subscriptionsProvider.notifier).remove(subscription.url);
    await _reload();
  }

  String _subscriptionStatus(AppText text, Subscription s) {
    final String? failure = switch (s.failure) {
      null => null,
      SubscriptionError.unreachable => text.freeSubscriptionUnreachable,
      SubscriptionError.refused => text.freeSubscriptionRefused,
      SubscriptionError.tooLarge => text.freeSubscriptionTooLarge,
      SubscriptionError.empty => text.freeSubscriptionEmpty,
    };
    final MaterialLocalizations local = MaterialLocalizations.of(context);
    final DateTime? at = s.checkedAt?.toLocal();
    final List<String> parts = <String>[
      if (s.links.isNotEmpty || failure == null)
        text.freeSubscriptionCount(s.links.length),
      if (at != null)
        text.freeSubscriptionUpdated(
          '${local.formatShortDate(at)} '
          '${local.formatTimeOfDay(TimeOfDay.fromDateTime(at))}',
        ),
      ?failure,
      if (s.skipped.isNotEmpty)
        text.freeSubscriptionSkipped(
          s.skipped.values.fold<int>(0, (int sum, int n) => sum + n),
        ),
    ];
    return s.checkedAt == null && failure == null
        ? text.freeSubscriptionNotYet
        : parts.join(' · ');
  }

  /// The connect screen's list is the controller's; it is read again so a
  /// relay added here is there to choose.
  Future<void> _reload() => ref.read(devicesControllerProvider.notifier).load();

  Future<void> _add() async {
    final bool taken = await ref
        .read(freeProfilesProvider.notifier)
        .add(_field.text);
    if (!mounted) {
      return;
    }
    setState(() => _invalid = !taken);
    if (taken) {
      _field.clear();
      await _reload();
    }
  }

  Future<void> _remove(FreeProfile profile) async {
    await ref.read(freeProfilesProvider.notifier).remove(profile.link);
    await _reload();
  }

  Future<void> _leave() async {
    await ref
        .read(devicesControllerProvider.notifier)
        .disconnectBeforeSignOut();
    await ref.read(freeModeProvider.notifier).leave();
  }

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final NebulaTypography type = context.type;
    final AppText text = AppText.of(context);
    // A subscription's connections are summed up in its own row below; the
    // list here is the build's and the person's own.
    final List<FreeProfile> profiles =
        (ref.watch(freeProfilesProvider).value ?? const <FreeProfile>[])
            .where(
              (FreeProfile p) =>
                  p.sources.isEmpty && !(widget.ownLinks && p.builtIn),
            )
            .toList();
    final List<Subscription> subscriptions =
        ref.watch(subscriptionsProvider).value ?? const <Subscription>[];

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: widget.ownLinks
          ? AppBar(
              leading: IconButton(
                icon: const Icon(Icons.arrow_back),
                onPressed: () => Navigator.of(context).maybePop(),
              ),
              title: Text(text.ownLinksTitle),
            )
          : null,
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              if (!widget.ownLinks)
                Padding(
                  padding: const EdgeInsets.only(top: 28, bottom: 20),
                  child: Text(
                    text.freeHeading,
                    style: type.wordmark.copyWith(color: palette.textMuted),
                  ),
                ),
              Expanded(
                child: ListView(
                  children: <Widget>[
                    Text(
                      widget.ownLinks ? text.ownLinksIntro : text.freeIntro,
                      style: TextStyle(color: palette.textMuted, height: 1.5),
                    ),
                    const SizedBox(height: 20),
                    if (!widget.ownLinks &&
                        profiles.isEmpty &&
                        subscriptions.isEmpty)
                      Text(
                        text.freeNoRelays,
                        style: TextStyle(color: palette.amberText, height: 1.5),
                      ),
                    for (final FreeProfile profile in profiles)
                      Container(
                        decoration: BoxDecoration(
                          border: Border(
                            bottom: BorderSide(color: palette.hairline),
                          ),
                        ),
                        child: ListTile(
                          contentPadding: EdgeInsets.zero,
                          title: Text(
                            profile.name,
                            style: TextStyle(color: palette.textPrimary),
                          ),
                          subtitle: Text(
                            profile.builtIn
                                ? text.freeRelayBuiltIn
                                : text.freeRelayYours,
                            style: TextStyle(color: palette.textMuted),
                          ),
                          // The build's own cannot be removed: it comes back
                          // at the next launch.
                          trailing: profile.builtIn
                              ? null
                              : IconButton(
                                  tooltip: text.freeRemove,
                                  icon: const Icon(Icons.close),
                                  onPressed: () => _remove(profile),
                                ),
                        ),
                      ),
                    const SizedBox(height: 24),
                    Text(
                      text.freeAddIntro,
                      style: TextStyle(color: palette.textMuted, height: 1.5),
                    ),
                    const SizedBox(height: 12),
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        Expanded(
                          child: TextField(
                            // Not a credential: no password manager offering one here.
                            autofillHints: null,
                            controller: _field,
                            keyboardType: TextInputType.url,
                            autocorrect: false,
                            enableSuggestions: false,
                            textInputAction: TextInputAction.done,
                            onSubmitted: (_) => _add(),
                            decoration: InputDecoration(
                              hintText: 'vless:// trojan:// ss:// hysteria2://',
                              errorText: _invalid ? text.freeAddInvalid : null,
                              // The whole sentence: cut at three lines it
                              // lost the part about refused links.
                              errorMaxLines: 6,
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        FilledButton(
                          // The theme's buttons are as wide as they are
                          // allowed to be; beside a field that took the
                          // whole row.
                          style: FilledButton.styleFrom(
                            minimumSize: const Size(0, 56),
                          ),
                          onPressed: _add,
                          child: Text(text.freeAdd),
                        ),
                      ],
                    ),
                    const SizedBox(height: 32),
                    Row(
                      children: <Widget>[
                        Expanded(
                          child: Text(
                            text.freeSubscriptions,
                            style: TextStyle(
                              color: palette.textMax,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                        if (subscriptions.isNotEmpty)
                          TextButton(
                            onPressed: _refreshing
                                ? null
                                : () => _refreshSubscriptions(force: true),
                            child: Text(text.freeSubscriptionsRefresh),
                          ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      text.freeSubscriptionsIntro,
                      style: TextStyle(color: palette.textMuted, height: 1.5),
                    ),
                    for (final Subscription subscription in subscriptions)
                      Container(
                        decoration: BoxDecoration(
                          border: Border(
                            bottom: BorderSide(color: palette.hairline),
                          ),
                        ),
                        child: ListTile(
                          contentPadding: EdgeInsets.zero,
                          title: Text(
                            subscription.name,
                            style: TextStyle(color: palette.textPrimary),
                          ),
                          subtitle: Text(
                            _subscriptionStatus(text, subscription),
                            style: TextStyle(
                              color: subscription.failure == null
                                  ? palette.textMuted
                                  : palette.amberText,
                            ),
                          ),
                          trailing: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: <Widget>[
                              IconButton(
                                tooltip: text.subscriptionRename,
                                icon: const Icon(Icons.edit_outlined),
                                onPressed: () =>
                                    _renameSubscription(subscription),
                              ),
                              IconButton(
                                tooltip: text.freeRemove,
                                icon: const Icon(Icons.close),
                                onPressed: () =>
                                    _removeSubscription(subscription),
                              ),
                            ],
                          ),
                        ),
                      ),
                    const SizedBox(height: 12),
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        Expanded(
                          child: TextField(
                            // Not a credential: no password manager offering one here.
                            autofillHints: null,
                            controller: _subscriptionField,
                            keyboardType: TextInputType.url,
                            autocorrect: false,
                            enableSuggestions: false,
                            textInputAction: TextInputAction.done,
                            onSubmitted: (_) => _addSubscription(),
                            decoration: InputDecoration(
                              hintText: 'https://',
                              errorText: _subscriptionInvalid
                                  ? text.freeSubscriptionInvalid
                                  : null,
                              errorMaxLines: 3,
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        FilledButton(
                          style: FilledButton.styleFrom(
                            minimumSize: const Size(0, 56),
                          ),
                          onPressed: _refreshing ? null : _addSubscription,
                          child: _refreshing
                              ? const SizedBox.square(
                                  dimension: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                  ),
                                )
                              : Text(text.freeAdd),
                        ),
                      ],
                    ),
                    if (!widget.ownLinks) ...<Widget>[
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
                    const SizedBox(height: 16),
                  ],
                ),
              ),
              if (!widget.ownLinks)
                Padding(
                  padding: const EdgeInsets.only(bottom: 16),
                  child: PanelCta(
                    label: text.freeLeave,
                    style: CtaStyle.secondary,
                    onPressed: _leave,
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
