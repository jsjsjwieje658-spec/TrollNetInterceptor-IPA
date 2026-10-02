//
//  DopamineBridge.mm
//  AetherNet — Tier 0: Dopamine 3.x (rootless) PPL-Bypass Bridge
//
//  Minimal reimplementation of Dopamine's jbclient XPC wire protocol
//  (no libjailbreak dependency — all private libxpc symbols resolve at
//  runtime through dyld because we link with -undefined dynamic_lookup).
//
//  Wire protocol (from Dopamine 3.x jbclient_xpc.c):
//    xdict["jb-domain"] = uint64 domain
//    xdict["action"]    = uint64 action
//    …action args…
//    → xpc_pipe_routine_with_flags(pipe_to_launchd, xdict, &xreply, 0)
//    xreply["result"] = int64 (0 == success)
//

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "DopamineBridge.h"

// ---------------------------------------------------------------------------
// Private libxpc SPI (resolved via dynamic_lookup at runtime)
// ---------------------------------------------------------------------------
typedef void *xpc_t;

extern "C" {
extern xpc_t    xpc_dictionary_create_empty(void);
extern void     xpc_dictionary_set_uint64(xpc_t, const char *, uint64_t);
extern void     xpc_dictionary_set_bool(xpc_t, const char *, bool);
extern int64_t  xpc_dictionary_get_int64(xpc_t, const char *);
extern const char *xpc_dictionary_get_string(xpc_t, const char *);
extern void     xpc_release(xpc_t);
extern xpc_t    xpc_pipe_create_from_port(mach_port_t, uint64_t flags);
extern int      xpc_pipe_routine_with_flags(xpc_t pipe, xpc_t message, xpc_t *reply, uint32_t flags);
}

// ---------------------------------------------------------------------------
// Dopamine jbserver domains & actions (jbserver_domains.h, branch 3.x)
// ---------------------------------------------------------------------------
#define JBS_DOMAIN_SYSTEMWIDE                  1
#define JBS_DOMAIN_PLATFORM                    2
#define JBS_SYSTEMWIDE_GET_JBROOT              1
#define JBS_SYSTEMWIDE_TRUST_FILE              3
#define JBS_PLATFORM_SET_PROCESS_DEBUGGED      1

static char gCachedJBRoot[1024] = {0};
static bool gJBRootProbed = false;

static kern_return_t AetherGetLaunchdPort(mach_port_t *portOut)
{
    // Dopamine's jbserver is reached through the launchd bootstrap port
    kern_return_t kr = task_get_bootstrap_port(mach_task_self(), portOut);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(*portOut)) {
        // Fallback for processes spawned with a registered-ports array
        mach_port_t *ports = NULL;
        mach_msg_type_number_t count = 0;
        if (mach_ports_lookup(mach_task_self(), &ports, &count) == KERN_SUCCESS && count > 0 && ports[0] != MACH_PORT_NULL) {
            *portOut = ports[0];
            mach_port_deallocate(mach_task_self(), ports[0]);
            vm_deallocate(mach_task_self(), (vm_address_t)ports, count * sizeof(mach_port_t));
            return KERN_SUCCESS;
        }
        return (kr == KERN_SUCCESS) ? KERN_FAILURE : kr;
    }
    return KERN_SUCCESS;
}

static xpc_t AetherJBServerSend(uint64_t domain, uint64_t action, xpc_t xargs)
{
    bool ownsXargs = false;
    if (!xargs) {
        xargs = xpc_dictionary_create_empty();
        ownsXargs = true;
    }
    xpc_dictionary_set_uint64(xargs, "jb-domain", domain);
    xpc_dictionary_set_uint64(xargs, "action", action);

    mach_port_t launchdPort = MACH_PORT_NULL;
    if (AetherGetLaunchdPort(&launchdPort) != KERN_SUCCESS) {
        if (ownsXargs) xpc_release(xargs);
        return NULL;
    }

    xpc_t pipe = xpc_pipe_create_from_port(launchdPort, 0);
    if (!pipe) {
        if (ownsXargs) xpc_release(xargs);
        return NULL;
    }

    xpc_t reply = NULL;
    int err = xpc_pipe_routine_with_flags(pipe, xargs, &reply, 0);
    xpc_release(pipe);
    if (ownsXargs) xpc_release(xargs);

    if (err != 0 || !reply) {
        return NULL;
    }
    return reply;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const char *AetherDopamineGetJBRoot(void)
{
    if (gJBRootProbed) {
        return (gCachedJBRoot[0] != '\0') ? gCachedJBRoot : NULL;
    }
    gJBRootProbed = true;

    xpc_t reply = AetherJBServerSend(JBS_DOMAIN_SYSTEMWIDE, JBS_SYSTEMWIDE_GET_JBROOT, NULL);
    if (reply) {
        const char *rootPath = xpc_dictionary_get_string(reply, "root-path");
        if (rootPath && strlen(rootPath) > 0 && strlen(rootPath) < sizeof(gCachedJBRoot)) {
            strlcpy(gCachedJBRoot, rootPath, sizeof(gCachedJBRoot));
        }
        xpc_release(reply);
    }

    return (gCachedJBRoot[0] != '\0') ? gCachedJBRoot : NULL;
}

bool AetherDopamineAvailable(void)
{
    return AetherDopamineGetJBRoot() != NULL;
}

int AetherDopamineTrustFileByPath(const char *path)
{
    if (!path) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -2;

    // Server side resolves our fd's path via audit token:
    // proc_pidfdinfo(our_pid, fd, PROC_PIDFDVNODEPATHINFO) then re-opens in launchd
    xpc_t xargs = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(xargs, "fd", (uint64_t)fd);

    xpc_t reply = AetherJBServerSend(JBS_DOMAIN_SYSTEMWIDE, JBS_SYSTEMWIDE_TRUST_FILE, xargs);

    int result = -3;
    if (reply) {
        result = (int)xpc_dictionary_get_int64(reply, "result");
        xpc_release(reply);
    }
    close(fd);
    return result;
}

int AetherDopamineSetProcessDebugged(pid_t pid, bool fully)
{
    xpc_t xargs = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(xargs, "pid", (uint64_t)pid);
    xpc_dictionary_set_bool(xargs, "fully-debugged", fully);

    xpc_t reply = AetherJBServerSend(JBS_DOMAIN_PLATFORM, JBS_PLATFORM_SET_PROCESS_DEBUGGED, xargs);

    int result = -1;
    if (reply) {
        result = (int)xpc_dictionary_get_int64(reply, "result");
        xpc_release(reply);
    }
    return result;
}

bool AetherDopaminePrepareInjection(pid_t targetPID, const char *dylibPath)
{
    if (!AetherDopamineAvailable()) return false;

    // 1. Trust the payload dylib in the kernel trust cache (defeats library validation)
    int trustResult = AetherDopamineTrustFileByPath(dylibPath);

    // 2. Flip the target into CS_DEBUGGED via cs_allow_invalid (defeats CS enforcement
    //    + pmap_cs/TXM invalid-code protection — the PPL "fix")
    int debugResult = AetherDopamineSetProcessDebugged(targetPID, true);

    return (debugResult == 0);
}
