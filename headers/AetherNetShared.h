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
// Magic bumped to ...208 for the v4 "path-aware" capture engine: the struct
// gained the lane/capability block, so stale state from v3.x is discarded
// instead of being misinterpreted.
#define AETHER_SHM_MAGIC            0xAE74E208U
// Daemon handshake: HUD daemon stores its build here every heartbeat; the app
// respawns a stale daemon after an app update. KEEP IN SYNC with build number
// in scripts/crossbuild-linux.sh
#define AETHER_BUILD_NUM            415U

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
    AetherModeCorruptTamper = 3, // Bit-flip / truncate non-header payload bytes
    AetherModeObserve       = 4  // Capture only: count + log every packet, never
                                 // hold / drop / delay / tamper, never freeze the
                                 // target.  This is what the kernel tap (P3) does
                                 // when there is no injection (P1/P2) available.
} AetherInterceptMode;

// ---------------------------------------------------------------------------
// The four UDP/TCP paths a packet can take from an app into the OS (see
// README §2).  AetherNet can sit on each of them; `activeLanes` below records
// which ones are actually running for the current target.
// ---------------------------------------------------------------------------
typedef enum : uint8_t {
    // P1 — BSD socket syscalls (send/sendto/sendmsg/write …).  In-process
    //      hooks inside the target; needs dylib injection to succeed.
    AetherLaneBSDSocket     = (1u << 0),
    // P2 — Network.framework / NSURLSession (libnetwork.dylib, nw_connection_*).
    //      In-process hooks; this is the default path for every app since iOS 12
    //      and the one a naive send()/recv() hook completely misses.
    AetherLaneLibnetwork    = (1u << 1),
    // P3 — the kernel tap: /dev/bpf on the interface the packets actually leave
    //      on.  Works without any injection and sees BOTH P1 and P2 traffic,
    //      because everything converges on the interface.
    AetherLaneKernelTap     = (1u << 2),
    // Enforcement only (no packet copies): PF/dummynet rules + SIGSTOP freeze.
    AetherLaneShaper        = (1u << 3)
} AetherCaptureLane;

typedef enum : uint8_t {
    AetherMethodNone         = 0, // nothing running
    AetherMethodInProcess    = 1, // dylib injected → BSD + libnetwork lanes
    AetherMethodKernelTap    = 2, // BPF tap only (observe, no control)
    AetherMethodShaper       = 3, // PF / freeze only (control, no visibility)
    AetherMethodTapAndShaper = 4, // BPF + PF/freeze
    AetherMethodFull         = 5  // in-process hooks + BPF (+ shaper on demand)
} AetherCaptureMethod;

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
    // Tap arbitration: the HUD daemon receives raw digitizer events, so a single
    // physical tap is seen BOTH by the floating button and by whatever the app
    // happens to show underneath it — including its own "Remove Floating
    // Button".  The daemon records the taps it consumed (time + screen point)
    // and the app ignores a button press that came from the same gesture.
    _Atomic(uint64_t) hudTapConsumedMs;
    _Atomic(int32_t)  hudTapConsumedX;
    _Atomic(int32_t)  hudTapConsumedY;

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

    // --- Kernel tap (BPF) telemetry + lane bookkeeping (v4) ---
    _Atomic(uint32_t) activeLanes;         // AetherCaptureLane bitmask actually running
    _Atomic(uint32_t) availableLanes;      // …and what this device supports
    _Atomic(uint8_t)  freezeActive;        // target is SIGSTOPped by the shaper
    _Atomic(uint64_t) kernelTapPacketsRX;
    _Atomic(uint64_t) kernelTapPacketsTX;
    _Atomic(uint64_t) kernelTapBytesRX;
    _Atomic(uint64_t) kernelTapBytesTX;
    _Atomic(uint32_t) kernelTapFlows;
    _Atomic(uint32_t) kernelTapDropped;   // kernel buffer overruns (BIOCGSTATS)
    char              kernelTapInterface[32];
    char              engineStatus[192];  // one-line explanation for the UI

    // --- Kernel tap control + diagnostics (v4.0.2) -------------------------
    // The UI app runs as uid 501 and therefore CANNOT signal the root `-bftap`
    // helper it spawned (kill() to a uid-0 process returns EPERM), so the stop
    // request travels through shared memory instead.
    _Atomic(uint32_t) tapStopRequest;      // 1 = parent asks the helper to exit
    _Atomic(uint32_t) tapHelperPid;        // pid of the running helper (0 = in-process)
    _Atomic(uint32_t) tapFramesSeen;       // link-layer records walked
    _Atomic(uint32_t) tapFramesIP;         // …that parsed as IPv4/IPv6 TCP+UDP
    _Atomic(uint32_t) tapFramesMatched;    // …attributed to the target
    // The lanes can run in EITHER process (the app starts them when the toggle
    // comes from the UI, the daemon when it comes from the floating button).
    // Whoever restarts must know whether a live owner already exists — starting
    // a second tap would double count every packet in these shared counters.
    _Atomic(pid_t)    laneOwnerPID;        // process running the lanes, 0 = none
    _Atomic(uint32_t) tapStatsLogged;      // last statistics line (epoch-ish ms)

    // --- Snapshot of Active L4 Connections in Target PID ---
    uint32_t          socketEntryCount;
    AetherSocketEntry activeSockets[AETHER_MAX_TRACKED_SOCKETS];

    // --- Freeze opt-in (v4.1.3) ---------------------------------------------
    // SIGSTOPping the target is the ONLY enforcement primitive iOS leaves when
    // there is neither pfctl/dnctl nor an in-process hook — but a stopped
    // process is a FROZEN APP: no rendering, no FPS, and nothing left for the
    // BPF tap to capture.  Hold/Drop reach it implicitly, so it must never fire
    // on its own: default 0, and AetherShaperApply() only freezes when the
    // user switched this on explicitly.
    _Atomic(uint8_t)  allowFreeze;

    // --- Ping simulation / lag switch (v4.1.5) ------------------------------
    // There is no queue anywhere on this device to hold a packet for N ms (no
    // pfctl, no dnctl, no in-process hook), so the only way to make a game's
    // ping move is to stall the target itself: SIGSTOP for `lagSpikeMs`, then
    // SIGCONT, repeated every `lagCycleMs` — a hardware lag switch in software.
    // lagSpikeMs == 0 (the default) means never stall anything.
    _Atomic(uint32_t) lagSpikeMs;         // length of one stall, 0 = off
    _Atomic(uint32_t) lagCycleMs;         // period between two stalls
} AetherSharedState;

#ifdef __cplusplus
extern "C" {
#endif

AetherSharedState *AetherGetSharedState(void);
void AetherResetTelemetryForNewTarget(AetherSharedState *state, pid_t pid, const char *name, const char *bundleID, const char *execPath);

// ---------------------------------------------------------------------------
// Path-aware capture engine (Core/L4Engine)
// ---------------------------------------------------------------------------

/// Kernel tap lane (P3): opens /dev/bpfN, attaches to the interface(s) the
/// target's traffic leaves on and counts/attributes every TCP+UDP packet.
/// Needs root (persona) + no-sandbox.  Returns 0 on success.
int  AetherKernelLaneStart(pid_t pid, bool primary, char *errBuf, size_t errBufLen);
void AetherKernelLaneStop(void);
bool AetherKernelLaneIsRunning(void);

/// One-shot capability probe: opens a BPF device and immediately closes it so
/// the UI can report whether the tap is usable on this device.
bool AetherKernelLaneIsAvailable(void);

/// Enforcement lane: PF/dummynet rules + SIGSTOP freeze, all executed through
/// a short-lived root helper (posix_spawn persona) because the UI app runs as
/// uid 501 and may not signal/pfctl other processes.
int  AetherShaperApply(pid_t pid, char *errBuf, size_t errBufLen);
int  AetherShaperFlush(char *errBuf, size_t errBufLen);
int  AetherShaperFreeze(pid_t pid, bool freeze, char *errBuf, size_t errBufLen);
/// Bitmask of the enforcement primitives present on this device.
uint32_t AetherShaperCapabilities(void);

#ifdef __cplusplus
}
#endif

#endif /* AetherNetShared_h */
