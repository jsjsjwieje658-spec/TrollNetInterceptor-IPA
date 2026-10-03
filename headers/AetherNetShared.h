//
//  AetherNetShared.h
//  AetherNet — TrollStore Low-Level L4 Packet Interceptor & HUD
//
//  Shared memory IPC layout mapped across:
//    1. Main UI App (AetherNet)
//    2. Root Global Floating HUD Daemon (AetherNet -hud)
//    3. Injected Process Payload (libNetHookPayload.dylib)
//
//  Atomic compatibility layer:
//    - C11 mode  : <stdatomic.h> primitives (atomic_load/atomic_store/…)
//    - C++17 mode: std::atomic<T> backend behind the same aether_atomic_* names
//                  (clang on Linux/iOS cross-compiles .mm as C++, where the C11
//                   _Atomic qualifier is unavailable)
//

#ifndef AetherNetShared_h
#define AetherNetShared_h

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
#include <atomic>
#define _Atomic(T) std::atomic<T>
template <class T, class V> inline void      aether_atomic_store(std::atomic<T> *a, V v)        { a->store((T)v); }
template <class T>           inline T        aether_atomic_load(const std::atomic<T> *a)         { return a->load(); }
template <class T, class V> inline T        aether_atomic_exchange(std::atomic<T> *a, V v)      { return a->exchange((T)v); }
template <class T, class V> inline T        aether_atomic_fetch_add(std::atomic<T> *a, V v)     { return a->fetch_add((T)v); }
#else
#include <stdatomic.h>
#define aether_atomic_store    atomic_store
#define aether_atomic_load     atomic_load
#define aether_atomic_exchange atomic_exchange
#define aether_atomic_fetch_add atomic_fetch_add
#endif

#define AETHER_SHM_PATH             "/var/mobile/Library/Caches/com.aethernet.shared.shm"
#define AETHER_HUD_PID_PATH         "/var/mobile/Library/Caches/com.aethernet.hud.pid"
#define AETHER_DYLIB_INSTALL_PATH   "/var/mobile/Library/Caches/libNetHookPayload.dylib"
#define AETHER_SHM_MAGIC            0xAE74E207U
// Daemon handshake: HUD daemon stores its build here every heartbeat; the app
// respawns a stale daemon after an app update. KEEP IN SYNC with build number
// in scripts/crossbuild-linux.sh
#define AETHER_BUILD_NUM            360U

// Darwin Notifications for instant cross-process wakeups
#define kAetherNotifyStateChanged   "com.aethernet.interceptor.state_changed"
#define kAetherNotifyConfigChanged  "com.aethernet.interceptor.config_changed"
#define kAetherNotifyHUDToggle      "com.aethernet.interceptor.hud_toggle"
#define kAetherNotifyHUDDismiss     "com.aethernet.interceptor.hud_dismiss"
#define kAetherNotifyFlushQueue     "com.aethernet.interceptor.flush_queue"

typedef enum : uint8_t {
    AetherDirectionBoth     = 0, // Intercept both Download (RX) & Upload (TX)
    AetherDirectionDownload = 1, // Intercept Download (recv / recvfrom / recvmsg) only
    AetherDirectionUpload   = 2  // Intercept Upload (send / sendto / sendmsg) only
} AetherTrafficDirection;

typedef enum : uint8_t {
    AetherProtoTCPAndUDP    = 0, // Both SOCK_STREAM (TCP) and SOCK_DGRAM (UDP)
    AetherProtoUDPOnly      = 1, // SOCK_DGRAM (UDP) only
    AetherProtoTCPOnly      = 2  // SOCK_STREAM (TCP) only
} AetherProtocolFilter;

typedef enum : uint8_t {
    AetherModeHoldQueue     = 0, // Hold packets in memory buffer until toggled OFF (Freeze/Ghost)
    AetherModeDropPacket    = 1, // Silently drop matching packets (Loss simulation)
    AetherModeDelayJitter   = 2, // Inject artificial latency + jitter + bandwidth cap
    AetherModeCorruptTamper = 3  // Bit-flip / truncate non-header payload bytes
} AetherInterceptMode;

typedef enum : uint8_t {
    AetherPresetCustom      = 0,
    AetherPresetNormal      = 1,
    AetherPresetGhostFreeze = 2, // 98% Upload Hold + 100% UDP Hold
    AetherPresetLagSpike    = 3, // 450ms RTT + 120ms Jitter + 25% UDP Hold
    AetherPresetDegraded3G  = 4, // 280ms RTT + 128 kbps bandwidth cap + 15% loss
    AetherPresetTCPReset    = 5  // Aggressive TCP window throttle + FIN/RST simulation
} AetherNetworkPreset;

typedef struct {
    uint16_t localPort;
    uint16_t remotePort;
    char     remoteAddress[46]; // IPv4 or IPv6 string
    uint8_t  protocol;          // IPPROTO_TCP (6) or IPPROTO_UDP (17)
    uint8_t  state;             // TCP state or 1 for active UDP flow
    uint64_t rxBytes;
    uint64_t txBytes;
} AetherSocketEntry;

#define AETHER_MAX_TRACKED_SOCKETS 32

typedef struct __attribute__((aligned(64))) {
    uint32_t magic;
    uint32_t version;

    // --- Target Process State ---
    _Atomic(pid_t)    targetPID;
    char              targetProcessName[128];
    char              targetBundleID[128];
    char              targetExecutablePath[512];
    _Atomic(bool)     isInjected;
    _Atomic(uint8_t)  injectionMethod; // 0 = None, 1 = Mach dlopen, 2 = Socket/PF Root Engine, 3 = Dopamine-assisted Mach dlopen (PPL bypass)

    // --- Master Interception Switch (Controlled by Floating Button & Home Tab) ---
    // false = Triangle (Play icon ▶) -> Normal pass-through
    // true  = Parallel Bars (Pause icon ⏸) -> Active packet interception/holding
    _Atomic(bool)     interceptionActive;
    _Atomic(bool)     hudVisible;

    // --- Tab 2 (Settings) Interception & Simulation Parameters ---
    _Atomic(uint8_t)  direction;          // AetherTrafficDirection (Download / Upload / Both)
    _Atomic(uint8_t)  protocolFilter;     // AetherProtocolFilter (TCP+UDP / UDP / TCP)
    _Atomic(uint8_t)  interceptMode;      // AetherInterceptMode (Hold / Drop / Delay / Tamper)
    _Atomic(uint8_t)  activePreset;       // AetherNetworkPreset

    _Atomic(uint32_t) captureRatioPercent;   // 0 - 100% packet capture/hold ratio
    _Atomic(uint32_t) downloadHoldPercent;   // 0 - 100% specific download (RX) ratio
    _Atomic(uint32_t) uploadHoldPercent;     // 0 - 100% specific upload (TX) ratio
    _Atomic(uint32_t) simulatedLatencyMs;    // 0 - 3000 ms added delay
    _Atomic(uint32_t) simulatedJitterMs;     // 0 - 1000 ms random variance
    _Atomic(uint32_t) bandwidthLimitKbps;    // 0 = Unlimited, or 16..50000 kbps
    _Atomic(uint32_t) duplicatePacketPercent;// 0 - 50% packet duplication
    _Atomic(uint32_t) autoFlushSeconds;      // 0 = Manual, or 1..30s safety auto-release

    // --- Floating HUD Button Customization (Tab 2 Settings) ---
    _Atomic(float)    floatingButtonSize;    // 40.0f - 88.0f pt (default 58.0f)
    _Atomic(float)    floatingButtonOpacity; // 0.35f - 1.00f (default 0.92f)
    _Atomic(bool)     floatingEdgeSnap;      // Magnetic snap to screen edges
    _Atomic(bool)     floatingLockPosition;  // Lock dragging while active
    _Atomic(bool)     floatingHapticEnabled; // UIImpactFeedbackGenerator on toggle
    _Atomic(float)    floatingPosX;          // Last saved X coordinate
    _Atomic(float)    floatingPosY;          // Last saved Y coordinate
    _Atomic(uint64_t) hudHeartbeatTs;        // HUD daemon writes time(NULL) every 1s
    _Atomic(uint32_t) hudCommand;            // 0 = none, 1 = graceful exit request

    // --- Touch pipeline diagnostics (HUD -> app) ---
    _Atomic(uint32_t) dbgCallbackCount;      // BKSHIDEvent callback invocations
    _Atomic(uint32_t) dbgDeliveredCount;     // touches handed to TSEventFetcher
    _Atomic(uint8_t)  dbgRawReady;           // raw digitizer dlsym resolution ok
    _Atomic(uint32_t) dbgDigCount;           // digitizer-typed events parsed
    _Atomic(uint32_t) dbgBeganCount;         // Began phases computed
    _Atomic(uint32_t) dbgHitCount;           // Began hit-tests landing on our button
    _Atomic(uint32_t) dbgLastX;              // last raw digitizer X
    _Atomic(uint32_t) dbgLastY;              // last raw digitizer Y
    _Atomic(uint8_t)  dbgScale;              // locked transform index (0=none)
    _Atomic(int32_t)  rootFrozenPid;         // pid currently SIGSTOPped (root engine)
    _Atomic(uint32_t) dbgMaxX;               // running max raw X (panel range probe)
    _Atomic(uint32_t) dbgMaxY;               // running max raw Y
    _Atomic(uint32_t) dbgWinW;               // daemon HUD window width
    _Atomic(uint32_t) dbgWinH;               // daemon HUD window height
    _Atomic(uint32_t) dbgBtnX;               // floating button center x (window coords)
    _Atomic(uint32_t) dbgBtnY;               // floating button center y (window coords)
    _Atomic(uint32_t) dbgRing[8];            // last 4 Began raw points (x,y,x,y,…)
    _Atomic(uint32_t) daemonBuild;           // build number of the running HUD daemon

    // --- Live L4 Telemetry Counters (Updated by Injected Dylib & Socket Monitor) ---
    _Atomic(uint32_t) activeTCPSockets;
    _Atomic(uint32_t) activeUDPSockets;
    _Atomic(uint64_t) totalTCPPacketsRX;
    _Atomic(uint64_t) totalTCPPacketsTX;
    _Atomic(uint64_t) totalUDPPacketsRX;
    _Atomic(uint64_t) totalUDPPacketsTX;
    _Atomic(uint64_t) totalBytesRX;
    _Atomic(uint64_t) totalBytesTX;
    _Atomic(uint64_t) heldPacketsCount;      // Currently buffered/held in queue
    _Atomic(uint64_t) droppedPacketsCount;   // Total dropped/intercepted packets
     _Atomic(uint32_t) currentRXRateBps;
    _Atomic(uint32_t) currentTXRateBps;
    _Atomic(uint32_t) currentPacketRatePps;

    // --- BPF Capture Telemetry (root engine fallback) ---
    _Atomic(uint64_t) totalBPFPacketsRX;
    _Atomic(uint64_t) totalBPFPacketsTX;

    // --- Snapshot of Active L4 Connections in Target PID ---
    uint32_t          socketEntryCount;
    AetherSocketEntry activeSockets[AETHER_MAX_TRACKED_SOCKETS];
} AetherSharedState;

#ifdef __cplusplus
extern "C" {
#endif

AetherSharedState *AetherGetSharedState(void);
void AetherResetTelemetryForNewTarget(AetherSharedState *state, pid_t pid, const char *name, const char *bundleID, const char *execPath);

// BPF capture thread — spawn for root-engine-only mode when dylib hooks unavailable
void AetherStartBPFCaptureIfAvailable(void);

#ifdef __cplusplus
}
#endif

#endif /* AetherNetShared_h */
