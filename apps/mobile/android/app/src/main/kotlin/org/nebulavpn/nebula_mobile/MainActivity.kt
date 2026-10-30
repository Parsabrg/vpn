package org.nebulavpn.nebula_mobile

import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.StringReader

/**
 * Bridges Dart's connect/disconnect calls to the official WireGuard Android
 * tunnel library (wireguard-go via JNI, [GoBackend]) rather than
 * reimplementing the protocol -- the same reuse-the-real-thing approach the
 * Windows client takes by shelling out to the official wireguard.exe.
 */
class MainActivity : FlutterActivity() {
    private val channelName = "org.nebulavpn/wireguard_tunnel"
    private val vpnPrepareRequestCode = 8743

    private lateinit var backend: Backend

    companion object {
        private var sharedBackend: Backend? = null
    }
    private var pendingPrepareResult: MethodChannel.Result? = null
    private var tunnelChannel: MethodChannel? = null

    /**
     * Set when the tunnel notification's Disconnect button opened this
     * activity, until the Dart side takes it.
     *
     * The plugin's button launches the app with [disconnectAction] rather
     * than stopping the service itself, and nothing handled that action, so
     * the button only ever opened the app. Taken rather than pushed alone:
     * on a cold start the tap arrives before Dart is listening.
     */
    private var disconnectRequested = false
    private val disconnectAction = "FROM_DISCONNECT_BTN"

    /** One fixed tunnel identity -- this app manages exactly one WireGuard
     * peer per device, never multiple concurrent tunnels. */
    private object NebulaTunnel : Tunnel {
        override fun getName(): String = "nebula"

        override fun onStateChange(newState: Tunnel.State) {
            // No UI currently reads live tunnel state beyond connect/disconnect
            // completing; add a state stream here if that becomes needed.
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // One backend for the whole process, not one per activity. The
        // backend is what knows which tunnel it brought up, and the tunnel
        // outlives the activity: a fresh backend in a reopened app answered
        // "nothing running" and could not take the tunnel down.
        backend = sharedBackend ?: GoBackend(applicationContext).also { sharedBackend = it }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
            .also { tunnelChannel = it }
            .setMethodCallHandler { call: MethodCall, result: MethodChannel.Result ->
                when (call.method) {
                    "requestPermission" -> requestPermission(result)
                    "hasPermission" -> result.success(VpnState.consentHeld(this))
                    "vpnOwner" -> result.success(VpnState.owner(this))
                    "takeDisconnectRequest" -> {
                        result.success(disconnectRequested)
                        disconnectRequested = false
                    }
                    "connect" -> connect(call.argument("config"), result)
                    "disconnect" -> disconnect(result)
                    "readTraffic" -> readTraffic(result)
                    "wireguardHandshake" -> wireguardHandshake(result)
                    "readTunTraffic" -> readTunTraffic(result)
                    "openVpnSettings" -> openVpnSettings(result)
                    "killSwitch" -> result.success(killSwitchState())
                    "appVersion" -> result.success(
                        packageManager.getPackageInfo(packageName, 0).versionName,
                    )
                    "openUrl" -> openUrl(call.argument("url"), result)
                    "installedApps" -> installedApps(result)
                    // Kept across reinstalls (per signing key and user); the
                    // Dart side hashes it before it leaves the phone.
                    "hardwareId" -> result.success(
                        Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID),
                    )
                    "appIcon" -> appIcon(call.argument("packageName"), result)
                    else -> result.notImplemented()
                }
            }
    }

    /** Android requires per-app, per-install user consent before any
     * VpnService can run -- this must complete (and be granted) before
     * `connect` is ever called. */
    private fun requestPermission(result: MethodChannel.Result) {
        val intent = VpnService.prepare(this)
        if (intent == null) {
            result.success(true)
            return
        }
        pendingPrepareResult = result
        startActivityForResult(intent, vpnPrepareRequestCode)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A recreated activity is handed its original intent again; only a
        // fresh launch can be a tap.
        if (savedInstanceState == null) {
            noteDisconnectRequest(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (noteDisconnectRequest(intent)) {
            // Already running: tell Dart there is something to take.
            tunnelChannel?.invokeMethod("disconnectRequested", null)
        }
    }

    private fun noteDisconnectRequest(intent: Intent?): Boolean {
        if (intent?.action != disconnectAction) {
            return false
        }
        disconnectRequested = true
        intent.action = Intent.ACTION_MAIN
        return true
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == vpnPrepareRequestCode) {
            pendingPrepareResult?.success(resultCode == RESULT_OK)
            pendingPrepareResult = null
            return
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    /**
     * Opens Android's own VPN settings, where the always-on and
     * block-connections-without-VPN switches live.
     *
     * Those two together are the only real kill switch on Android, and an app
     * cannot turn them on for itself: once this app's VpnService is gone there
     * is nothing left of it running to block anything, which is exactly why
     * the platform owns the setting. Only a device-owner/MDM app can set it
     * programmatically. So the honest thing an ordinary app can do is explain
     * the gap and take the user straight to the switch.
     */
    /** Opens an https page in the browser. The caller has already checked
     * where it points; this only refuses anything that is not https. */
    private fun openUrl(url: String?, result: MethodChannel.Result) {
        if (url == null || !url.startsWith("https://")) {
            result.success(false)
            return
        }
        try {
            startActivity(
                Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
            result.success(true)
        } catch (error: ActivityNotFoundException) {
            result.success(false)
        }
    }

    /**
     * Android's always-on and block-without-VPN switches for this app, "1" or
     * "0" each, as the running tunnel service last asked Android -- it does
     * every few seconds. Null while this app's VPN is not up: only that
     * service can ask (the system setting reads back empty to an app, which
     * showed "off" over both switches on), and a reading from an earlier
     * session may be out of date.
     */
    private fun killSwitchState(): String? {
        if (VpnState.owner(this) != "own") {
            return null
        }
        return java.io.File(filesDir, "vpn_kill_switch").takeIf { it.exists() }?.readText()
    }

    private fun openVpnSettings(result: MethodChannel.Result) {
        try {
            startActivity(
                Intent(Settings.ACTION_VPN_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
            result.success(true)
        } catch (error: ActivityNotFoundException) {
            // Some OEM builds do not expose this screen under the standard
            // action; report it rather than crashing so the UI can fall back
            // to telling the user where to look.
            result.success(false)
        }
    }

    private fun connect(configText: String?, result: MethodChannel.Result) {
        if (configText == null) {
            result.error("invalid_argument", "config is required", null)
            return
        }
        val config: Config
        try {
            config = Config.parse(BufferedReader(StringReader(configText)))
        } catch (error: Exception) {
            result.error("invalid_config", error.message, null)
            return
        }
        // GoBackend.setState does JNI/IPC work and must not run on the UI thread.
        Thread {
            try {
                backend.setState(NebulaTunnel, Tunnel.State.UP, config)
                runOnUiThread { result.success(null) }
            } catch (error: Exception) {
                runOnUiThread { result.error("tunnel_error", error.message, null) }
            }
        }.start()
    }

    private fun disconnect(result: MethodChannel.Result) {
        Thread {
            try {
                backend.setState(NebulaTunnel, Tunnel.State.DOWN, null)
                runOnUiThread { result.success(null) }
            } catch (error: Exception) {
                runOnUiThread { result.error("tunnel_error", error.message, null) }
            }
        }.start()
    }

    /**
     * Byte counters for this app, or null when the device will not report them.
     *
     * For transports this app does not run in-process there is nothing to
     * ask: Hysteria2 is a child process, and the Xray core that would hold
     * counters is never started on that path.
     *
     * The first attempt read /proc/net/dev, which counts the tunnel
     * interface exactly and is what the shell sees. It cannot work here:
     * that path is labelled proc_net, apps run as untrusted_app, and
     * Android has denied that combination since API 29. The denial is
     * dontaudit'd, so the read fails silently and every reading came back
     * empty -- which on screen is indistinguishable from a tunnel carrying
     * nothing.
     *
     * TrafficStats is what Android offers instead. It counts what this app's
     * UID moved over the real network, which while a tunnel is up is
     * overwhelmingly that tunnel: tun2socks and the transport child process
     * share this UID, and loopback between them is not counted. Two caveats,
     * both small and neither worth a wrong number instead: it counts wire
     * bytes rather than payload, so it runs a little above what the server
     * records, and it includes this app's own calls to the control plane.
     *
     * Counted since boot, so the caller subtracts a baseline taken when the
     * session began.
     */
    private fun readTunTraffic(result: MethodChannel.Result) {
        val uid = android.os.Process.myUid()
        val rx = TrafficStats.getUidRxBytes(uid)
        val tx = TrafficStats.getUidTxBytes(uid)
        // UNSUPPORTED (-1) on a device that declines to report per-UID
        // figures. Null rather than a zero, so the screen shows no reading
        // instead of claiming nothing was transferred.
        if (rx == TrafficStats.UNSUPPORTED.toLong() || tx == TrafficStats.UNSUPPORTED.toLong()) {
            result.success(null)
            return
        }
        result.success(mapOf("rxBytes" to rx, "txBytes" to tx))
    }

    /**
     * When the running WireGuard tunnel last completed a handshake, in epoch
     * milliseconds: 0 when it never has, null when no tunnel is up.
     *
     * A WireGuard tunnel is "up" on this side the moment its interface
     * exists, whether or not the server ever answered. Only a completed
     * handshake shows that it did -- on a network that drops WireGuard, the
     * interface comes up, every packet goes nowhere, and nothing else says so.
     */
    private fun wireguardHandshake(result: MethodChannel.Result) {
        Thread {
            try {
                val running = backend.runningTunnelNames.contains(NebulaTunnel.getName())
                if (!running) {
                    runOnUiThread { result.success(null) }
                    return@Thread
                }
                val statistics = backend.getStatistics(NebulaTunnel)
                val latest = statistics.peers()
                    .maxOfOrNull { statistics.peer(it)?.latestHandshakeEpochMillis() ?: 0L }
                    ?: 0L
                runOnUiThread { result.success(latest) }
            } catch (error: Exception) {
                runOnUiThread { result.error("tunnel_error", error.message, null) }
            }
        }.start()
    }

    /**
     * Byte counters for the running tunnel, or null when nothing is up.
     *
     * Null rather than zeroes: a tunnel that is down and a tunnel that has
     * carried nothing are different things, and the caller renders them
     * differently. Returning zeroes here would draw a live counter sitting
     * at zero over a tunnel that does not exist.
     *
     * `getStatistics` crosses into wireguard-go over JNI like `setState`
     * does, so it gets the same treatment: off the UI thread, answered back
     * on it.
     */
    private fun readTraffic(result: MethodChannel.Result) {
        Thread {
            try {
                val running = backend.runningTunnelNames.contains(NebulaTunnel.getName())
                if (!running) {
                    runOnUiThread { result.success(null) }
                    return@Thread
                }
                val statistics = backend.getStatistics(NebulaTunnel)
                // Named from this device's side, matching what the Dart layer
                // expects: rx is what arrived here.
                val traffic = mapOf(
                    "rxBytes" to statistics.totalRx(),
                    "txBytes" to statistics.totalTx(),
                )
                runOnUiThread { result.success(traffic) }
            } catch (error: Exception) {
                runOnUiThread { result.error("tunnel_error", error.message, null) }
            }
        }.start()
    }

    /**
     * Every app on the device that can be launched, so a person can choose
     * which ones bypass the tunnel.
     *
     * Launchable rather than simply installed: the full package list on a
     * modern phone is several hundred entries, nearly all of them vendor
     * services nobody recognises, and a picker that long is one nobody
     * finishes reading. Anything without a launcher icon is not something a
     * user thinks of as an app.
     *
     * This app is excluded from its own list. Routing it around the tunnel
     * is already the case -- it has to reach the control plane to fetch the
     * credentials the tunnel is built from -- and offering it as a choice
     * suggests a decision that is not actually available.
     */
    private fun installedApps(result: MethodChannel.Result) {
        val manager: PackageManager = packageManager
        val launchable: Set<String> =
            manager
                .queryIntentActivities(
                    Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),
                    0,
                )
                .mapNotNull { it.activityInfo?.packageName }
                .toSet()

        val apps =
            manager
                .getInstalledApplications(0)
                .asSequence()
                .filter { it.packageName in launchable }
                .filter { it.packageName != packageName }
                .map { info: ApplicationInfo ->
                    mapOf(
                        "packageName" to info.packageName,
                        "label" to manager.getApplicationLabel(info).toString(),
                        // Reported rather than filtered on. A browser that
                        // shipped with the phone is a system app and is also
                        // exactly the kind of thing somebody wants to route
                        // around the tunnel; the caller decides, not this.
                        "isSystem" to ((info.flags and ApplicationInfo.FLAG_SYSTEM) != 0),
                    )
                }
                .sortedBy { (it["label"] as String).lowercase() }
                .toList()

        result.success(apps)
    }

    /**
     * One app's icon as PNG bytes.
     *
     * Fetched per app rather than returned with the list above: several
     * hundred icons is a few megabytes across a method channel, which turns
     * opening the picker into a visible pause. The caller asks for the ones
     * it is about to draw.
     */
    private fun appIcon(requested: String?, result: MethodChannel.Result) {
        val target = requested
        if (target.isNullOrBlank()) {
            result.error("invalid_argument", "packageName is required", null)
            return
        }
        try {
            val drawable: Drawable = packageManager.getApplicationIcon(target)
            result.success(drawable.toPngBytes())
        } catch (_: PackageManager.NameNotFoundException) {
            // Uninstalled between listing and drawing. Not an error worth
            // failing the picker over -- the row simply draws without one.
            result.success(null)
        }
    }

    /**
     * Adaptive icons are not bitmaps, so [BitmapDrawable] casting fails on
     * most modern apps. Drawing the drawable into a bitmap handles both.
     */
    private fun Drawable.toPngBytes(): ByteArray {
        val source = this
        val rendered: Bitmap =
            if (source is BitmapDrawable && source.bitmap != null) {
                source.bitmap
            } else {
                val width = source.intrinsicWidth.coerceAtLeast(1)
                val height = source.intrinsicHeight.coerceAtLeast(1)
                Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).also {
                    val canvas = Canvas(it)
                    source.setBounds(0, 0, canvas.width, canvas.height)
                    source.draw(canvas)
                }
            }
        return ByteArrayOutputStream().use { stream ->
            rendered.compress(Bitmap.CompressFormat.PNG, 100, stream)
            stream.toByteArray()
        }
    }
}
