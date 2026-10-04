//
//  AetherKernelLane.h
//  AetherNet — P3 kernel tap lane (BPF) + per-PID socket inventory
//
//  This lane is the one that keeps AetherNet useful on a plain TrollStore
//  device: it needs no dylib injection, no PPL bypass and no jailbreak — only
//  root (persona spawn) and no-sandbox, both of which TrollStore grants.
//

#ifndef AetherKernelLane_h
#define AetherKernelLane_h

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "AetherPacketCore.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Enumerate the target's AF_INET/AF_INET6 TCP+UDP sockets and collect:
///   • *outPorts  — the set of local ports the target owns (tap matching key)
///   • *outTCP / *outUDP — live socket counts
///   • when `state` is non-NULL, refresh state->activeSockets /
///     socketEntryCount / activeTCPSockets / activeUDPSockets too.
/// Returns 0 on success.
int AetherRefreshSocketInventory(pid_t pid,
                                 AetherPortSet *outPorts,
                                 uint32_t *outTCP,
                                 uint32_t *outUDP,
                                 void *state /* AetherSharedState * */);

// ---------------------------------------------------------------------------
// Root tap helper (`AetherNet -bftap <pid> <primary>`)
//
// The tap needs two privileges the UI app does not have: open("/dev/bpf") and,
// on iOS, proc_pidfdinfo() on another process.  The HUD daemon runs as root
// (persona spawn) and can do both in-process; the app runs as uid 501, so it
// spawns a root copy of itself and supervises it instead.  The helper writes
// straight into the same file-backed shared state, so the UI sees the counters
// either way.
// ---------------------------------------------------------------------------
/// Where the tap reader loop is right now (0 = not in it).  Read by the
/// daemon's fatal-signal handler so a crash is attributable.
int   AetherKernelLanePhase(void);
/// The tap thread's handle: the signal handler compares pthread_self() with
/// it to say which thread actually died.
pthread_t AetherKernelLaneThread(void);

bool AetherKernelLaneRootHelperAlive(void);
int  AetherKernelLaneStartViaRootHelper(pid_t pid, bool primary,
                                        char *errBuf, size_t errBufLen);
void AetherKernelLaneStopRootHelper(void);

/// Entry point of the `-bftap` mode (see main.mm).  Runs until the target
/// exits or the parent sends SIGTERM.
int AetherBpfTapMain(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* AetherKernelLane_h */
