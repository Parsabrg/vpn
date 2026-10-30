import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/theme/color_tokens.dart';
import '../../core/xray/xray_tunnel_controller.dart';
import '../../l10n/app_localizations.dart';

/// What the tunnel core has said about itself.
///
/// The one question this app could not answer was "it says connected but
/// nothing loads, why". Every other signal available to the user -- the
/// status text, the byte counters -- reports the tunnel as fine in exactly
/// that case, because from the app's side it is: the service is running and
/// the socket is open. What went wrong is in the core, and until now there
/// was no way to see it without a cable and adb.
///
/// The core runs at warning level, so this is faults, not a record of what
/// was visited. That is deliberate and worth keeping: raising it to info
/// would turn this screen into a list of every domain the person opened,
/// sitting on a device that may be inspected. Nothing here leaves the phone
/// on its own -- copying is a deliberate act, and there is no upload.
class ConnectionLogScreen extends ConsumerStatefulWidget {
  const ConnectionLogScreen({super.key});

  @override
  ConsumerState<ConnectionLogScreen> createState() =>
      _ConnectionLogScreenState();
}

class _ConnectionLogScreenState extends ConsumerState<ConnectionLogScreen> {
  List<String>? _lines;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final List<String> lines = await ref
          .read(xrayTunnelControllerProvider)
          .logs();
      if (mounted) {
        setState(() {
          _lines = lines;
          _error = null;
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() => _error = error);
      }
    }
  }

  Future<void> _clear() async {
    await ref.read(xrayTunnelControllerProvider).clearLogs();
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    final NebulaPalette palette = context.palette;
    final List<String>? lines = _lines;

    return Scaffold(
      backgroundColor: palette.bg,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(AppText.of(context).connectionLog),
        actions: <Widget>[
          IconButton(
            tooltip: AppText.of(context).ctaRefresh,
            icon: const Icon(Icons.refresh),
            onPressed: _load,
          ),
          if (lines != null && lines.isNotEmpty) ...<Widget>[
            IconButton(
              tooltip: AppText.of(context).copy,
              icon: const Icon(Icons.copy_all),
              onPressed: () => _copy(lines),
            ),
            IconButton(
              tooltip: AppText.of(context).clear,
              icon: const Icon(Icons.delete_outline),
              onPressed: _clear,
            ),
          ],
        ],
      ),
      body: SafeArea(child: _body(lines, palette)),
    );
  }

  Widget _body(List<String>? lines, NebulaPalette palette) {
    if (_error != null) {
      return _Message(
        text: AppText.of(context).logUnreadable,
        palette: palette,
      );
    }
    if (lines == null) {
      return const Center(child: CircularProgressIndicator());
    }
    if (lines.isEmpty) {
      // An empty log is the healthy state, and saying so matters: "nothing
      // here" otherwise reads as the screen being broken, which is the last
      // thing somebody already debugging a connection needs to wonder about.
      return _Message(text: AppText.of(context).logEmpty, palette: palette);
    }
    return ListView.builder(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      itemCount: lines.length,
      itemBuilder: (BuildContext context, int index) {
        return Padding(
          padding: const EdgeInsets.symmetric(vertical: 3),
          child: SelectableText(
            lines[index],
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 11,
              height: 1.35,
              color: _lineColor(lines[index], palette),
            ),
          ),
        );
      },
    );
  }

  /// Errors carry the colour; everything else stays quiet.
  ///
  /// A log where every line is red is a log nobody reads, and the point of
  /// opening this screen is to find the one line that matters among the
  /// routine ones.
  static Color _lineColor(String line, NebulaPalette palette) {
    final String lowered = line.toLowerCase();
    if (lowered.contains('error') ||
        lowered.contains('failed') ||
        lowered.contains('refused')) {
      return palette.redText;
    }
    if (lowered.contains('warning')) {
      return palette.amberText;
    }
    return palette.textMuted;
  }

  Future<void> _copy(List<String> lines) async {
    await Clipboard.setData(ClipboardData(text: lines.join('\n')));
    if (mounted) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(AppText.of(context).logCopied)));
    }
  }
}

class _Message extends StatelessWidget {
  const _Message({required this.text, required this.palette});

  final String text;
  final NebulaPalette palette;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Text(
          text,
          textAlign: TextAlign.center,
          style: TextStyle(color: palette.textMuted, height: 1.5),
        ),
      ),
    );
  }
}
