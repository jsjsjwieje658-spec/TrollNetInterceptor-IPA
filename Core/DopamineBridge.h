//
//  DopamineBridge.h
//  AetherNet — Tier 0: Dopamine 3.x (rootless) PPL-Bypass Bridge
//
//  Research basis — opa334/Dopamine branch 3.x (v3.0.10):
//    BaseBin/libjailbreak/src/jbclient_xpc.c      (client wire protocol)
//    BaseBin/launchdhook/src/jbserver/jbdomain_platform.c   (authorization)
//    BaseBin/libjailbreak/src/kernel.c            (cs_allow_invalid — the PPL fix)
//
//  Key insight: Dopamine hosts its jbserver inside launchd and authorizes the
//  PLATFORM domain for ANY process whose csops flags contain CS_PLATFORM_BINARY
//  — which is exactly what the `platform-application` entitlement gives a
//  TrollStore app. Therefore, when Dopamine is installed, this app can request:
//
//    • JBS_SYSTEMWIDE_TRUST_FILE   → add libNetHookPayload.dylib to the kernel
//                                    trust cache (systemwide domain, all procs)
//    • JBS_PLATFORM_SET_PROCESS_DEBUGGED
//           → kernel-side cs_allow_invalid(proc, fully):
//                 proc_csflags_clear(proc, CS_KILL | CS_HARD);
//                 proc_csflags_set(proc, CS_DEBUGGED);
//                 vm_map.flags.cs_debugged = true; switch_protect = false;
//                 pmap_cs_allow_invalid(pmap);   // TXM allowsInvalidCode / wx_allowed
//             — this is Dopamine's PPL/SPTM "fix": after it, the target PID
//               accepts our remotely dlopen'd dylib even on A12+ / iOS 15-17.3.1
//               where PPL would normally block unsigned code.
//

#ifndef DopamineBridge_h
#define DopamineBridge_h

#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns jbroot path (e.g. "/var/jb") when Dopamine 3.x jbserver is alive, NULL otherwise.
// The probe itself doubles as a cheap liveness check (single XPC roundtrip to launchd).
const char *AetherDopamineGetJBRoot(void);
bool AetherDopamineAvailable(void);

// Adds `path` to Dopamine's kernel trust cache (JBS_SYSTEMWIDE_TRUST_FILE).
// Returns 0 on success.
int AetherDopamineTrustFileByPath(const char *path);

// Marks `pid` as CS_DEBUGGED via cs_allow_invalid (JBS_PLATFORM_SET_PROCESS_DEBUGGED).
// `fully` = fullyDebugged (emulate fully on non-arm64e; required for arm64 targets).
// Returns 0 on success.
int AetherDopamineSetProcessDebugged(pid_t pid, bool fully);

// Convenience: full pre-injection pipeline for AetherNet.
// trust dylib + set target debugged. Returns true when both succeeded.
bool AetherDopaminePrepareInjection(pid_t targetPID, const char *dylibPath);

#ifdef __cplusplus
}
#endif

#endif /* DopamineBridge_h */
