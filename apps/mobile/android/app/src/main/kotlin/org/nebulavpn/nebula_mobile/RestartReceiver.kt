package org.nebulavpn.nebula_mobile

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import dev.amirzr.flutter_v2ray_client.v2ray.V2rayController

/**
 * Brings the tunnel back after the phone restarts, or after this app is
 * updated -- installing an update stops the app, tunnel and all.
 *
 * Only a tunnel that was up and was not taken down on purpose: the plugin
 * keeps the running tunnel's config until it is stopped or revoked, and
 * nothing is saved otherwise. That tunnel's client is still live on the
 * server, which only revokes a client on disconnect or with its device, so
 * starting it needs neither the app nor the API.
 *
 * A VPN only while this app still holds VPN consent and no other VPN is up:
 * the person may have switched to another VPN app before restarting. A local
 * proxy needs neither.
 */
class RestartReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }
        // The Flutter shared_preferences file; the setting is written by Dart.
        val preferences = context.getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        if (!preferences.getBoolean("flutter.nebula.reconnect_after_restart", true)) {
            return
        }
        // This app's own VPN is no reason to stay down: right after an update
        // Android can still list the old process's interface for a moment,
        // and asking only for "none" left the phone unprotected after one
        // (seen 2026-10-14). Another app's VPN, or one Android cannot name,
        // still is.
        val owner = VpnState.owner(context)
        val vpnAllowed = VpnState.consentHeld(context) && (owner == "none" || owner == "own")
        try {
            if (V2rayController.restoreSavedTunnel(context, vpnAllowed)) {
                // A new session, begun now. The app's record still carries the
                // start of the one before the restart; this is how a later run
                // tells them apart. Read by TunnelRestoreStore.
                preferences.edit()
                    .putLong("flutter.nebula.tunnel_restored_at", System.currentTimeMillis())
                    .apply()
                Log.i("RestartReceiver", "restored the tunnel after ${intent.action}")
            }
        } catch (error: Exception) {
            Log.w("RestartReceiver", "could not restore the tunnel", error)
        }
    }
}
