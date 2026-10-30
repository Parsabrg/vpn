import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/settings/advanced_settings_controller.dart';
import '../../core/settings/protection_controller.dart';
import '../../core/theme/color_tokens.dart';
import '../../l10n/app_localizations.dart';

/// Websites that connect directly instead of through the VPN: a local bank
/// or service that refuses foreign addresses. Each entry covers its
/// subdomains. Applies from the next connection, to Xray protocols.
class BypassDomainsScreen extends ConsumerStatefulWidget {
  const BypassDomainsScreen({super.key});

  @override
  ConsumerState<BypassDomainsScreen> createState() =>
      _BypassDomainsScreenState();
}

class _BypassDomainsScreenState extends ConsumerState<BypassDomainsScreen> {
  final TextEditingController _field = TextEditingController();
  bool _invalid = false;

  @override
  void dispose() {
    _field.dispose();
    super.dispose();
  }

  Future<void> _add() async {
    final bool taken = await ref
        .read(advancedSettingsControllerProvider.notifier)
        .addBypassDomain(_field.text);
    if (!mounted) {
      return;
    }
    setState(() => _invalid = !taken);
    if (taken) {
      _field.clear();
    }
  }

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final AppText text = AppText.of(context);
    final List<String> domains = ref.watch(
      advancedSettingsControllerProvider.select((s) => s.bypassDomains),
    );

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(text.bypassDomains),
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: <Widget>[
            Text(
              text.bypassDomainsIntro,
              style: TextStyle(color: palette.textMuted, height: 1.5),
            ),
            const SizedBox(height: 16),
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
                    textInputAction: TextInputAction.done,
                    onSubmitted: (_) => _add(),
                    decoration: InputDecoration(
                      hintText: 'example.com',
                      errorText: _invalid ? text.bypassDomainsInvalid : null,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                FilledButton(
                  // The theme's buttons are as wide as they are allowed to
                  // be; beside a field that took the whole row.
                  style: FilledButton.styleFrom(minimumSize: const Size(0, 56)),
                  onPressed: _add,
                  child: Text(text.bypassDomainsAdd),
                ),
              ],
            ),
            const SizedBox(height: 16),
            for (final String domain in domains)
              Container(
                decoration: BoxDecoration(
                  border: Border(bottom: BorderSide(color: palette.hairline)),
                ),
                child: ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(
                    domain,
                    style: TextStyle(color: palette.textPrimary),
                  ),
                  trailing: IconButton(
                    tooltip: text.bypassDomainsRemove,
                    icon: const Icon(Icons.close),
                    onPressed: () => ref
                        .read(advancedSettingsControllerProvider.notifier)
                        .removeBypassDomain(domain),
                  ),
                ),
              ),
            const SizedBox(height: 16),
            Text(
              text.bypassDomainsNote,
              style: TextStyle(color: palette.textMuted, height: 1.5),
            ),
            if (defaultTargetPlatform == TargetPlatform.windows &&
                ref
                    .watch(protectionControllerProvider)
                    .blockWhenVpnDrops) ...<Widget>[
              const SizedBox(height: 12),
              Text(
                text.bypassDomainsKillSwitchWindows,
                style: TextStyle(color: palette.amberText, height: 1.5),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
