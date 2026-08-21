import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/servers/server_repository.dart';
import '../../core/storage/storage_providers.dart';
import '../../core/widgets/empty_state.dart';
import 'devices_controller.dart';
import 'devices_state.dart';

class DevicesScreen extends ConsumerStatefulWidget {
  const DevicesScreen({super.key});

  @override
  ConsumerState<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends ConsumerState<DevicesScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(devicesControllerProvider.notifier).load();
    });
  }

  @override
  Widget build(BuildContext context) {
    final DevicesState state = ref.watch(devicesControllerProvider);
    final String? deviceId = ref.watch(deviceIdStoreProvider).read();

    return Scaffold(
      appBar: AppBar(title: const Text('Devices')),
      body: SafeArea(child: _body(context, state, deviceId)),
    );
  }

  Widget _body(BuildContext context, DevicesState state, String? deviceId) {
    if (state.loadStatus == DevicesLoadStatus.loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (state.loadStatus == DevicesLoadStatus.failed) {
      return _LoadFailed(
        message: state.loadErrorMessage ?? 'Something went wrong.',
        onRetry: () => ref.read(devicesControllerProvider.notifier).load(),
      );
    }
    if (state.servers.isEmpty) {
      return const EmptyState(
        icon: Icons.vpn_lock_outlined,
        title: 'No servers assigned yet',
        message:
            "You aren't assigned to a VPN server yet. Ask an "
            'administrator to grant you access, then come back here.',
      );
    }
    // Narrows deviceId to a non-null String for the rest of this method --
    // a switch expression's `when` guards don't carry that promotion across
    // branches the way this early return does.
    final String? currentDeviceId = deviceId;
    if (currentDeviceId == null) {
      return const EmptyState(
        icon: Icons.error_outline,
        title: "Couldn't identify this device",
        message: 'Try signing out and back in.',
      );
    }
    return state.isConnected
        ? _ConnectedView(state: state, deviceId: currentDeviceId)
        : _PickerView(state: state, deviceId: currentDeviceId);
  }
}

class _LoadFailed extends StatelessWidget {
  const _LoadFailed({required this.message, required this.onRetry});

  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            Icon(
              Icons.cloud_off,
              size: 48,
              color: Theme.of(context).colorScheme.error,
            ),
            const SizedBox(height: 16),
            Text(message, textAlign: TextAlign.center),
            const SizedBox(height: 16),
            FilledButton(onPressed: onRetry, child: const Text('Try again')),
          ],
        ),
      ),
    );
  }
}

class _PickerView extends ConsumerWidget {
  const _PickerView({required this.state, required this.deviceId});

  final DevicesState state;
  final String deviceId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final AvailableServer? selectedServer = state.selectedServer;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: <Widget>[
        Text('Server', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        DropdownButtonFormField<String>(
          initialValue: state.selectedServerCode,
          hint: const Text('Choose a server'),
          items: state.servers
              .map(
                (AvailableServer server) => DropdownMenuItem<String>(
                  value: server.code,
                  child: Text(server.displayName),
                ),
              )
              .toList(),
          onChanged: (String? code) {
            if (code != null) {
              ref.read(devicesControllerProvider.notifier).selectServer(code);
            }
          },
        ),
        const SizedBox(height: 16),
        if (selectedServer != null) ...<Widget>[
          Text('Profile', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          DropdownButtonFormField<String>(
            initialValue: state.selectedProfileCode,
            hint: const Text('Choose a profile'),
            items: selectedServer.profiles
                .map(
                  (AvailableProfile profile) => DropdownMenuItem<String>(
                    value: profile.code,
                    child: Text(profile.displayName),
                  ),
                )
                .toList(),
            onChanged: (String? code) {
              if (code != null) {
                ref
                    .read(devicesControllerProvider.notifier)
                    .selectProfile(code);
              }
            },
          ),
        ],
        if (state.actionErrorMessage != null) ...<Widget>[
          const SizedBox(height: 16),
          Semantics(
            liveRegion: true,
            child: Text(
              state.actionErrorMessage!,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        ],
        const SizedBox(height: 24),
        FilledButton(
          onPressed:
              state.isSubmitting ||
                  state.selectedServerCode == null ||
                  state.selectedProfileCode == null
              ? null
              : () => ref
                    .read(devicesControllerProvider.notifier)
                    .connect(deviceId),
          child: state.isSubmitting
              ? const SizedBox(
                  height: 20,
                  width: 20,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Connect'),
        ),
      ],
    );
  }
}

class _ConnectedView extends ConsumerWidget {
  const _ConnectedView({required this.state, required this.deviceId});

  final DevicesState state;
  final String deviceId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final WireGuardPeerResult peer = state.peer!;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: <Widget>[
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Row(
                  children: <Widget>[
                    Icon(
                      Icons.check_circle,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'WireGuard peer provisioned',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  'Your device is registered with the server. Nebula VPN '
                  "doesn't establish a live tunnel from this screen yet -- "
                  'that needs native platform integration this app does '
                  "not have. This is your device's WireGuard configuration.",
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const Divider(height: 24),
                _DetailRow(
                  label: 'Assigned address',
                  value: peer.assignedAddress,
                ),
                _DetailRow(
                  label: 'Server public key',
                  value: peer.serverPublicKey,
                ),
                _DetailRow(label: 'Endpoint', value: peer.publicEndpoint),
                _DetailRow(label: 'DNS', value: peer.clientDns),
                _DetailRow(label: 'Allowed IPs', value: peer.clientAllowedIps),
                _DetailRow(
                  label: 'Keepalive',
                  value: '${peer.persistentKeepaliveSeconds}s',
                ),
              ],
            ),
          ),
        ),
        if (state.actionErrorMessage != null) ...<Widget>[
          const SizedBox(height: 16),
          Semantics(
            liveRegion: true,
            child: Text(
              state.actionErrorMessage!,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        ],
        const SizedBox(height: 24),
        FilledButton.tonalIcon(
          onPressed: state.isSubmitting
              ? null
              : () => ref
                    .read(devicesControllerProvider.notifier)
                    .disconnect(deviceId),
          icon: state.isSubmitting
              ? const SizedBox(
                  height: 16,
                  width: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.link_off),
          label: const Text('Disconnect'),
        ),
      ],
    );
  }
}

class _DetailRow extends StatelessWidget {
  const _DetailRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(label, style: Theme.of(context).textTheme.labelMedium),
          SelectableText(value, style: Theme.of(context).textTheme.bodyMedium),
        ],
      ),
    );
  }
}
