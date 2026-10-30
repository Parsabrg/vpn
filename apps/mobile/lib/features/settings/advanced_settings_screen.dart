import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/settings/advanced_settings_controller.dart';
import '../../core/storage/advanced_settings_store.dart';
import '../../core/theme/color_tokens.dart';
import '../../core/widgets/panel/panel_atoms.dart';
import '../../core/widgets/panel/panel_controls.dart';
import '../../l10n/app_localizations.dart';

/// The knobs that change what the tunnel core is told to do.
///
/// Everything here is off or at its shipped value by default, and turning
/// nothing on produces byte-for-byte the config the app generated before this
/// screen existed. That matters more than it sounds: the people using this
/// have no way to tell an app update apart from a change in what their network
/// is blocking, so a setting that quietly alters a working tunnel costs them
/// a day of guessing.
///
/// Each control says what it actually does rather than naming the field it
/// writes. "Multiplexing" means nothing to somebody whose connection is slow;
/// what they need to know is when it helps and when it hurts.
class AdvancedSettingsScreen extends ConsumerWidget {
  const AdvancedSettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final NebulaPalette palette = context.palette;
    final AdvancedSettings settings = ref.watch(
      advancedSettingsControllerProvider,
    );
    final AdvancedSettingsController controller = ref.read(
      advancedSettingsControllerProvider.notifier,
    );

    final AppText text = AppText.of(context);

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(text.advancedTitle),
        actions: <Widget>[
          if (!settings.isDefault)
            TextButton(
              onPressed: controller.restoreDefaults,
              child: Text(text.reset),
            ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          children: <Widget>[
            const SizedBox(height: 12),
            Text(
              text.advancedIntro,
              style: TextStyle(color: palette.textMuted, fontSize: 13),
            ),

            const SizedBox(height: 24),
            SectionHeader(text.sectionNameResolution),
            const SizedBox(height: 4),
            _DnsRow(servers: settings.dnsServers, controller: controller),

            const SizedBox(height: 28),
            SectionHeader(text.sectionConnection),
            const SizedBox(height: 4),
            PanelToggleRow(
              title: text.multiplexing,
              meta: settings.muxEnabled
                  ? text.muxStreams(settings.muxConcurrency)
                  : text.muxOff,
              value: settings.muxEnabled,
              onChanged: (bool enabled) =>
                  controller.setMuxEnabled(enabled: enabled),
              isLast: !settings.muxEnabled,
            ),
            if (settings.muxEnabled)
              _ConcurrencyRow(
                value: settings.muxConcurrency,
                onChanged: controller.setMuxConcurrency,
              ),

            const SizedBox(height: 28),
            SectionHeader(text.sectionDomainMatching),
            const SizedBox(height: 12),
            PanelSegmented<SniffingMode>(
              semanticsLabel: text.readHostnames,
              segments: <(SniffingMode, String)>[
                (SniffingMode.whenRoutingNeedsIt, text.sniffAuto),
                (SniffingMode.always, text.sniffAlways),
                (SniffingMode.never, text.sniffNever),
              ],
              selected: settings.sniffing,
              onChanged: controller.setSniffing,
            ),
            const SizedBox(height: 8),
            Text(
              _sniffingExplanation(text, settings.sniffing),
              style: TextStyle(color: palette.textMuted, fontSize: 12),
            ),

            const SizedBox(height: 28),
            SectionHeader(text.sectionGettingThrough),
            const SizedBox(height: 4),
            PanelToggleRow(
              title: text.splitTlsHandshake,
              meta: settings.fragment.enabled
                  ? text.fragmentMeta(
                      settings.fragment.packets,
                      settings.fragment.length,
                    )
                  : text.off,
              value: settings.fragment.enabled,
              onChanged: (bool enabled) =>
                  controller.setFragmentEnabled(enabled: enabled),
              isLast: !settings.fragment.enabled,
            ),
            if (settings.fragment.enabled) ...<Widget>[
              const SizedBox(height: 8),
              PanelSegmented<String>(
                semanticsLabel: text.whichPacketsToSplit,
                segments: <(String, String)>[
                  ('tlshello', text.fragmentHandshakeOnly),
                  ('1-3', text.fragmentFirstPackets),
                ],
                selected: settings.fragment.packets,
                onChanged: controller.setFragmentPackets,
              ),
              const SizedBox(height: 12),
              _RangeField(
                label: text.bytesPerPiece,
                value: settings.fragment.length,
                onSubmitted: controller.setFragmentLength,
              ),
              _RangeField(
                label: text.gapMilliseconds,
                value: settings.fragment.interval,
                onSubmitted: controller.setFragmentInterval,
              ),
            ],
            const SizedBox(height: 8),
            Text(
              settings.fragment.enabled
                  ? text.fragmentOnExplain
                  : text.fragmentOffExplain,
              style: TextStyle(color: palette.textMuted, fontSize: 12),
            ),

            const SizedBox(height: 28),
            SectionHeader(text.sectionLogging),
            const SizedBox(height: 12),
            PanelSegmented<XrayLogLevel>(
              semanticsLabel: text.logLevel,
              segments: <(XrayLogLevel, String)>[
                (XrayLogLevel.none, text.logOff),
                (XrayLogLevel.error, text.logErrors),
                (XrayLogLevel.warning, text.logWarnings),
                (XrayLogLevel.info, text.logEverything),
              ],
              selected: settings.logLevel,
              onChanged: controller.setLogLevel,
            ),
            const SizedBox(height: 8),
            Text(
              settings.logLevel.recordsDestinations
                  ? text.logRecordsDestinations
                  : text.logFaultsOnly,
              style: TextStyle(
                color: settings.logLevel.recordsDestinations
                    ? palette.amberText
                    : palette.textMuted,
                fontSize: 12,
              ),
            ),
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }

  static String _sniffingExplanation(AppText text, SniffingMode mode) {
    return switch (mode) {
      SniffingMode.whenRoutingNeedsIt => text.sniffAutoExplain,
      SniffingMode.always => text.sniffAlwaysExplain,
      SniffingMode.never => text.sniffNeverExplain,
    };
  }
}

/// The resolver list, edited as text.
///
/// A text field rather than a picker of named providers: the reason somebody
/// opens this is that the shipped resolver is not reachable from where they
/// are, and a fixed list cannot anticipate what is.
class _DnsRow extends StatelessWidget {
  const _DnsRow({required this.servers, required this.controller});

  final List<String> servers;
  final AdvancedSettingsController controller;

  @override
  Widget build(BuildContext context) {
    return PanelExternalRow(
      title: AppText.of(context).dnsServers,
      meta: servers.isEmpty
          ? AppText.of(context).dnsDefault
          : servers.join(', '),
      isLast: true,
      onTap: () => _edit(context),
    );
  }

  Future<void> _edit(BuildContext context) async {
    final TextEditingController field = TextEditingController(
      text: servers.join(', '),
    );
    final String? entered = await showDialog<String>(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text(AppText.of(context).dnsServers),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Text(
                AppText.of(context).dnsEditHelp,
                style: const TextStyle(fontSize: 13),
              ),
              const SizedBox(height: 12),
              TextField(
                // Not a credential: no password manager offering one here.
                autofillHints: null,
                controller: field,
                autofocus: true,
                decoration: const InputDecoration(
                  hintText: '1.1.1.1, 9.9.9.9',
                  border: OutlineInputBorder(),
                ),
              ),
            ],
          ),
          actions: <Widget>[
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: Text(AppText.of(context).cancel),
            ),
            TextButton(
              onPressed: () => Navigator.of(context).pop(field.text),
              child: Text(AppText.of(context).save),
            ),
          ],
        );
      },
    );
    if (entered != null) {
      await controller.setDnsServers(entered.split(','));
    }
    field.dispose();
  }
}

class _ConcurrencyRow extends StatelessWidget {
  const _ConcurrencyRow({required this.value, required this.onChanged});

  final int value;
  final ValueChanged<int> onChanged;

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: <Widget>[
          Expanded(
            child: Text(
              AppText.of(context).streams,
              style: TextStyle(color: palette.textPrimary),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.remove),
            onPressed: value > 1 ? () => onChanged(value - 1) : null,
          ),
          SizedBox(
            width: 32,
            child: Text(
              '$value',
              textAlign: TextAlign.center,
              style: TextStyle(
                color: palette.textPrimary,
                fontFeatures: const <FontFeature>[FontFeature.tabularFigures()],
              ),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.add),
            onPressed: value < 128 ? () => onChanged(value + 1) : null,
          ),
        ],
      ),
    );
  }
}

/// One of the two fragment ranges, typed rather than chosen.
///
/// What works varies by network and changes over time, so a fixed set of
/// presets would go stale. Validated on submit and refused rather than stored
/// when the core would not accept it: storing a bad value means finding out
/// at connect time, as a tunnel that will not start with nothing pointing
/// back at this box.
class _RangeField extends StatefulWidget {
  const _RangeField({
    required this.label,
    required this.value,
    required this.onSubmitted,
  });

  final String label;
  final String value;
  final Future<bool> Function(String) onSubmitted;

  @override
  State<_RangeField> createState() => _RangeFieldState();
}

class _RangeFieldState extends State<_RangeField> {
  late final TextEditingController _field = TextEditingController(
    text: widget.value,
  );
  String? _error;

  @override
  void dispose() {
    _field.dispose();
    super.dispose();
  }

  Future<void> _submit(String value) async {
    final bool accepted = await widget.onSubmitted(value.trim());
    if (!mounted) {
      return;
    }
    setState(() {
      // Put back what was actually kept, so the box never shows a value the
      // tunnel is not using.
      _error = accepted ? null : AppText.of(context).rangeInvalid;
      if (!accepted) {
        _field.text = widget.value;
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: TextField(
        // Not a credential: no password manager offering one here.
        autofillHints: null,
        controller: _field,
        keyboardType: TextInputType.text,
        decoration: InputDecoration(
          isDense: true,
          labelText: widget.label,
          errorText: _error,
          border: const OutlineInputBorder(),
        ),
        onSubmitted: _submit,
        onTapOutside: (PointerDownEvent _) => _submit(_field.text),
      ),
    );
  }
}
