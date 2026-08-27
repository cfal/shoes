package com.shoesproxy

/**
 * JNI bridge to the shoes native proxy library.
 *
 * Call [init] once before using any other method. The native library is
 * loaded automatically when this object is first accessed.
 *
 * The TUN descriptor belongs to your app. Keep the [android.os.ParcelFileDescriptor]
 * alive for as long as the tunnel runs and close it after [stop] returns — the
 * native side never closes a descriptor it did not open.
 *
 * Example — starting the VPN inside a [android.net.VpnService]:
 * ```kotlin
 * class MyVpnService : VpnService() {
 *
 *     private var shoesHandle: Long = -1
 *     private var tunInterface: ParcelFileDescriptor? = null
 *
 *     override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
 *         ShoesNative.init("info")
 *
 *         val tun = Builder()
 *             .addAddress("10.0.0.1", 24)
 *             .establish() ?: return START_NOT_STICKY
 *         tunInterface = tun
 *
 *         val config = """
 *             tun:
 *               device_fd: ${tun.fd}
 *         """.trimIndent()
 *
 *         shoesHandle = ShoesNative.start(config, { fd -> protect(fd) }) { up, down ->
 *             Log.d("VPN", "Traffic: up=$up down=$down")
 *         }
 *         if (shoesHandle < 0) {
 *             Log.e("VPN", "start failed: ${ShoesNative.getLastError()}")
 *             tun.close()
 *             tunInterface = null
 *             return START_NOT_STICKY
 *         }
 *         return START_STICKY
 *     }
 *
 *     override fun onDestroy() {
 *         // Off the main thread: stop() waits for the engine to let go of the
 *         // TUN descriptor, and the system allows onDestroy about 5 seconds
 *         // before it kills the app for not responding.
 *         thread {
 *             ShoesNative.stop(shoesHandle)
 *             tunInterface?.close()
 *             tunInterface = null
 *         }
 *         super.onDestroy()
 *     }
 * }
 * ```
 *
 * Register a [android.net.ConnectivityManager.NetworkCallback] too and call
 * [networkChanged] from it; see that method for why.
 */
object ShoesNative {

    init {
        System.loadLibrary("shoes")
    }

    /**
     * Functional interface for protecting sockets from VPN routing.
     *
     * Implement this to delegate to [android.net.VpnService.protect], which
     * exempts the socket from being captured by the VPN tunnel — preventing
     * traffic loops.
     */
    fun interface SocketProtector {
        /**
         * Protect the given socket file descriptor.
         *
         * @param fd File descriptor of the socket to protect.
         * @return true if protection succeeded.
         */
        fun protect(fd: Int): Boolean
    }

    /**
     * Functional interface for receiving traffic statistics.
     *
     * Called periodically (~1 second) from the native engine with cumulative
     * byte counts since the last [start] call.
     */
    fun interface TrafficListener {
        /**
         * Called with updated traffic statistics.
         *
         * @param uploadBytes   Total bytes sent from device to proxy since start.
         * @param downloadBytes Total bytes received from proxy to device since start.
         */
        fun onTrafficUpdate(uploadBytes: Long, downloadBytes: Long)
    }

    /**
     * Initialize the shoes library.
     *
     * Must be called once before [start]. Safe to call from any thread.
     * Repeated calls are no-ops.
     *
     * @param logLevel Desired verbosity: "error", "warn", "info", "debug", or "trace".
     * @return 0 on success, -1 on error.
     */
    external fun init(logLevel: String): Int

    /**
     * Get the shoes library version string (e.g. "0.2.8").
     */
    external fun getVersion(): String

    /**
     * Redirect log output to a file.
     *
     * Call after [init] to persist logs to disk.
     *
     * @param logPath Absolute path to the log file.
     * @return 0 on success, -1 on error.
     */
    external fun setLogFile(logPath: String): Int

    /**
     * Change the log level of a running library.
     *
     * Unlike [init], this takes effect on a library that is already running,
     * so support can ask for debug logs without the app being restarted.
     *
     * Release builds are compiled with `release_max_level_info`: "debug" and
     * "trace" behave like "info" unless the native library was built with
     * those levels kept.
     *
     * @param logLevel "error", "warn", "info", "debug", "trace", or "off".
     * @return 0 on success, -1 if the level was not recognised.
     */
    external fun setLogLevel(logLevel: String): Int

    /**
     * Tell the engine that the device's network changed.
     *
     * Call this from [android.net.ConnectivityManager.NetworkCallback] —
     * `onAvailable`, `onLost`, and `onLinkPropertiesChanged` are all worth
     * forwarding. A UDP tunnel bound to an address that no longer exists does
     * not report an error, it just stops carrying traffic, so without this the
     * only recovery is stopping and starting the whole tunnel.
     *
     * Safe from any thread, and safe when nothing is running.
     *
     * @return the number of tunnel endpoints told to rebind.
     */
    external fun networkChanged(): Int

    /**
     * Start the shoes VPN service.
     *
     * Spawns a background async runtime and returns once the configuration has
     * been accepted, so a -1 here means the config was rejected — call
     * [getLastError] for the reason.
     *
     * The [configYaml] must include a `tun` section with `device_fd` set to
     * the TUN file descriptor obtained from
     * [android.net.VpnService.Builder.establish]. That descriptor stays yours:
     * keep the `ParcelFileDescriptor` alive until after [stop] and close it
     * yourself.
     *
     * @param configYaml YAML configuration string.
     * @param protectCallback Called by the engine to exempt outbound sockets
     *                        from VPN routing (pass `this::protect` from your VpnService).
     * @param trafficCallback Called with cumulative traffic byte counts about once a
     *                        second, and not at all while the counts are unchanged.
     * @return A positive handle on success, -1 on error.
     */
    external fun start(
        configYaml: String,
        protectCallback: SocketProtector,
        trafficCallback: TrafficListener,
    ): Long

    /**
     * Stop the VPN service.
     *
     * Signals shutdown and blocks until the engine has released the TUN
     * descriptor — usually a few milliseconds, but bounded at 5 seconds if a
     * task will not wind down. **Do not call this on the main thread**: the
     * system's ANR budget is about the same 5 seconds. Close your
     * `ParcelFileDescriptor` after it returns, not before.
     *
     * @param handle The handle returned by [start].
     */
    external fun stop(handle: Long)

    /**
     * Check whether the VPN service is currently running.
     *
     * @return true if the service is active.
     */
    external fun isRunning(): Boolean

    /**
     * Get the last error message from the shoes service.
     *
     * Returns the error string if the service stopped due to an error,
     * or null if no error has occurred (normal shutdown or still running).
     */
    external fun getLastError(): String?

    /**
     * Read the runtime counters as a JSON string.
     *
     * Returns null only if the native library was built without stats
     * support. Otherwise it is always a document: before [start] every number
     * is zero and `outbounds` is empty, and after [stop] it holds the final
     * figures of the session that just ended until the next [start] resets
     * them. Safe from any thread.
     *
     * The document looks like
     * `{"upload_bytes":0,"download_bytes":0,"active_connections":0,"outbounds":[...]}`.
     * The two top-level byte totals are the same figures [TrafficListener]
     * delivers, and `active_connections` is live TCP connections through the
     * tunnel. Each `outbounds` entry carries `name`, `upload_bytes`,
     * `download_bytes` and `active_connections` measured at that server
     * instead, so it will not agree with the top-level totals to the byte.
     * Later releases may add keys; ignore ones you do not recognise. The full
     * description lives on `shoes_get_stats` in `include/shoes.h`.
     */
    external fun getStats(): String?
}
