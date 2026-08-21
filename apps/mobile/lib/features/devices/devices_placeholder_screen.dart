import 'package:flutter/material.dart';

import '../../core/widgets/empty_state.dart';

/// Honest empty state, not a fake device list or a bare spinner: the API
/// has no public endpoint yet for a user to discover which VPN
/// server/profile they're allowed to use (`POST
/// /v1/devices/{id}/wireguard-peer` requires a `server_code`, and only an
/// admin-only listing route currently exists). This mirrors `apps/admin`'s
/// Phase 1.5 empty-state pattern for permissions/assignments/server-health.
class DevicesPlaceholderScreen extends StatelessWidget {
  const DevicesPlaceholderScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Devices')),
      body: const EmptyState(
        icon: Icons.vpn_lock_outlined,
        title: 'Device connection is coming soon',
        message:
            'Nebula VPN needs a way for the app to find out which server '
            "you're allowed to connect to before it can request a WireGuard "
            'connection on your behalf. That part of the API is not built '
            'yet -- this screen will show your devices and connection '
            'status once it is.',
      ),
    );
  }
}
