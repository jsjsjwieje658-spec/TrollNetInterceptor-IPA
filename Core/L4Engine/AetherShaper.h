//
//  AetherShaper.h
//  AetherNet — enforcement lane for the no-injection case
//
//  When the dylib cannot be injected (the normal situation on a plain
//  TrollStore device — see README §2), AetherNet still has to be able to
//  *do* something to the target's packets.  Two primitives survive without
//  touching the target's address space:
//
//    • SIGSTOP / SIGCONT on the target process — a true "freeze": the app
//      stops reading its sockets, the kernel receive buffers fill, the TCP
//      window closes and the peer sees the flow stall.  This is exactly the
//      lag-switch behaviour Intercepter-NG gives you on Android.
//    • PF + dummynet — packet level drop / delay / loss / bandwidth cap,
//      keyed on the target's local ports, installed in the com.apple/aethernet
//      anchor so we never disturb Apple's own ruleset.
//
//  Both need root.  The UI app runs as uid 501, so every action is executed by
//  a short-lived root copy of our own binary (`AetherNet -rootctl …`) spawned
//  with the persona UID 0 trick TrollStore permits.
//

#ifndef AetherShaper_h
#define AetherShaper_h

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AETHER_SHAPER_CAP_PFCTL    (1u << 0)   // /sbin/pfctl (drop / anchor)
#define AETHER_SHAPER_CAP_DUMMYNET (1u << 1)   // dummynet (delay / bw / loss)
#define AETHER_SHAPER_CAP_FREEZE   (1u << 2)   // root helper spawn works

/// Bitmask of AETHER_SHAPER_CAP_* supported on this device (probed once).
uint32_t AetherShaperCapabilities(void);

/// Install PF/dummynet rules (mode dependent) for `pid`.
int AetherShaperApply(pid_t pid, char *errBuf, size_t errBufLen);
/// Remove every rule AetherNet installed and unfreeze the target.
int AetherShaperFlush(char *errBuf, size_t errBufLen);
/// SIGSTOP (freeze = YES) or SIGCONT (freeze = NO) the target.
int AetherShaperFreeze(pid_t pid, bool freeze, char *errBuf, size_t errBufLen);

/// Ping simulation (lag switch): stall the target for `lagSpikeMs` every
/// `lagCycleMs` by alternating SIGSTOP/SIGCONT.  Idle (never stalls) while
/// lagSpikeMs == 0.  Returns 0 once the worker is up.
int  AetherLagSwitchStart(pid_t pid, char *errBuf, size_t errBufLen);
/// Stop stalling and make sure the target is left running (SIGCONT).
void AetherLagSwitchStop(void);
bool AetherLagSwitchIsRunning(void);

/// Entry point of the `-rootctl` mode (see main.mm).  Returns 0 on success.
int AetherRootCtlMain(int argc, char *argv[]);

/// Run one `-rootctl <verb> [args…]` command as root and wait for it.
/// Returns the helper's exit code (or -2 when it could not be spawned) and
/// fills *outOutput with a short description such as "exit=0".
int AetherRunAsRootVerb(NSArray<NSString *> *argv, NSString **outOutput);

/// Spawn our own binary as a **long-lived** root child (persona UID 0) and
/// return immediately, without waiting for it.  `argv` is the argument list
/// without the executable path (e.g. @[ @"-bftap", @"1234", @"1" ]).
/// Returns 0 and fills *outPID on success, otherwise the posix_spawn errno.
int AetherSpawnRootChild(NSArray<NSString *> *argv, pid_t *outPID);

#ifdef __cplusplus
}
#endif

#endif /* AetherShaper_h */
