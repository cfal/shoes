/**
 * @file shoes.h
 * @brief C interface for the shoes proxy library.
 *
 * Provides C-compatible functions for embedding the shoes VPN/proxy engine
 * into iOS applications via Swift or Objective-C.
 *
 * Typical usage from a NEPacketTunnelProvider:
 *
 * @code
 * // In Swift bridging header or ObjC:
 * #include "shoes.h"
 *
 * // 1. Initialize once
 * shoes_init("info");
 *
 * // 2. Optionally redirect logs to a file
 * shoes_set_log_file("/path/to/app.log");
 *
 * // 3. Start the VPN with config YAML and a socket-protect callback
 * long handle = shoes_start(configYaml, ^bool(int fd) {
 *     return [self protectSocket:fd];  // NEPacketTunnelProvider method
 * });
 *
 * // 4. Stop the VPN when done
 * shoes_stop(handle);
 * @endcode
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

/**
 * Socket protect callback.
 *
 * Called by the shoes engine to exempt an outgoing socket from VPN routing,
 * preventing traffic loops. The implementation should call the platform's
 * socket protection API (e.g. NEPacketTunnelProvider's socket protection).
 *
 * @param fd File descriptor of the socket to protect.
 * @return true if protection succeeded, false otherwise.
 */
typedef bool (*ShoesProtectSocketCallback)(int fd);

/**
 * Initialize the shoes library.
 *
 * Must be called exactly once before any other shoes function.
 * Subsequent calls are no-ops.
 *
 * @param log_level Desired log verbosity: "error", "warn", "info", "debug",
 *                  or "trace". Pass NULL for the default level ("info").
 * @return 0 on success, -1 on error.
 */
int shoes_init(const char *log_level);

/**
 * Start the shoes VPN service.
 *
 * Spawns a background async runtime and begins processing traffic according
 * to the provided YAML configuration. The configuration must include a TUN
 * device section with the packet-tunnel file descriptor.
 *
 * @param config_yaml  Null-terminated YAML configuration string.
 * @param protect_callback  Callback invoked to protect sockets from VPN routing.
 * @return A positive handle on success, or -1 on error.
 */
long shoes_start(const char *config_yaml, ShoesProtectSocketCallback protect_callback);

/**
 * Stop the shoes VPN service.
 *
 * Signals the running service to shut down and releases all resources.
 * Blocks until the service has stopped.
 *
 * @param handle The handle returned by shoes_start.
 */
void shoes_stop(long handle);

/**
 * Query whether the shoes VPN service is currently running.
 *
 * @return true if the service is active, false otherwise.
 */
bool shoes_is_running(void);

/**
 * Get the shoes library version string.
 *
 * @return A static, null-terminated version string (e.g. "0.2.8").
 *         Do NOT free or modify this pointer.
 */
const char *shoes_get_version(void);

/**
 * Redirect log output to a file.
 *
 * Call after shoes_init. The file is created if it does not exist.
 * Useful for persisting logs from Network Extension processes.
 *
 * @param path Absolute, null-terminated path to the log file.
 * @return 0 on success, -1 on error.
 */
int shoes_set_log_file(const char *path);

#ifdef __cplusplus
}
#endif
