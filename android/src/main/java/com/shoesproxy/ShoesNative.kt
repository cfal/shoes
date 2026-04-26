package com.shoesproxy

/**
 * JNI bridge to the shoes native proxy library.
 *
 * Call [init] once before using any other method. The native library is
 * loaded automatically when this object is first accessed.
 *
 * Example — starting the VPN inside a [android.net.VpnService]:
 * ```kotlin
 * class MyVpnService : VpnService() {
 *
 *     private var shoesHandle: Long = -1
 *
 *     override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
 *         ShoesNative.init("info")
 *
 *         val tunFd = Builder()
 *             .addAddress("10.0.0.1", 24)
 *             .establish()!!
 *             .detachFd()
 *
 *         val config = """
 *             tun:
 *               device_fd: $tunFd
 *         """.trimIndent()
 *
 *         shoesHandle = ShoesNative.start(config) { fd -> protect(fd) }
 *         return START_STICKY
 *     }
 *
 *     override fun onDestroy() {
 *         ShoesNative.stop(shoesHandle)
 *         super.onDestroy()
 *     }
 * }
 * ```
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
     * Start the shoes VPN service.
     *
     * Spawns a background async runtime. The [configYaml] must include a
     * `tun` section with `device_fd` set to the TUN file descriptor obtained
     * from [android.net.VpnService.Builder.establish].
     *
     * @param configYaml YAML configuration string.
     * @param protectCallback Called by the engine to exempt outbound sockets
     *                        from VPN routing (pass `this::protect` from your VpnService).
     * @return A positive handle on success, -1 on error.
     */
    external fun start(configYaml: String, protectCallback: SocketProtector): Long

    /**
     * Stop the VPN service.
     *
     * Signals shutdown and blocks until the service has fully stopped.
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
}
