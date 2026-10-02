//
//  MachInjector.mm
//  AetherNet — Mach Task Remote Dylib Injector & Root PF/Dummynet Shaper
//

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <signal.h>
#include <errno.h>
#include "../Core/AetherLog.h"
#include <dlfcn.h>
#include <pthread.h>
#include <spawn.h>
#include <sys/wait.h>
#include "../headers/AetherNetShared.h"
#include "../headers/PrivateSystemSPI.h"

extern "C" char **environ;

// ============================================================================
// 1. Mach Remote Dylib Injection via task_for_pid()
//    Requires: task_for_pid-allow, com.apple.system-task-ports
// ============================================================================
extern "C" int AetherInjectDylibIntoPID(pid_t pid, const char *dylibPath, char *errBuf, size_t errBufLen) {
    if (pid <= 0 || !dylibPath) return -1;

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
        snprintf(errBuf, errBufLen, "task_for_pid(%d) failed: 0x%x (%s)", pid, kr, mach_error_string(kr));
        return -2;
    }

    // Allocate remote stack & path string in target process address space
    mach_vm_size_t stackSize = 0x4000;
    mach_vm_size_t pathAllocSize = 0x1000;
    mach_vm_address_t remoteStack = 0;
    mach_vm_address_t remotePath = 0;

    kr = mach_vm_allocate(task, &remoteStack, stackSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "mach_vm_allocate(stack) failed: 0x%x", kr);
        return -3;
    }

    kr = mach_vm_allocate(task, &remotePath, pathAllocSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(task, remoteStack, stackSize);
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "mach_vm_allocate(path) failed: 0x%x", kr);
        return -4;
    }

    // Write dylib path into target task memory
    kr = mach_vm_write(task, remotePath, (vm_offset_t)dylibPath, (mach_msg_type_number_t)(strlen(dylibPath) + 1));
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(task, remotePath, pathAllocSize);
        mach_vm_deallocate(task, remoteStack, stackSize);
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "mach_vm_write(dylibPath) failed: 0x%x", kr);
        return -5;
    }

    mach_vm_protect(task, remoteStack, stackSize, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    mach_vm_protect(task, remotePath, pathAllocSize, FALSE, VM_PROT_READ);

    // Note: Because dyld shared cache is mapped at the same slide across processes
    // from the same boot session on iOS, dlopen's address in libdyld.dylib matches.
    void *dlopenAddr = dlsym(RTLD_DEFAULT, "dlopen");
    if (!dlopenAddr) {
        mach_port_deallocate(mach_task_self(), task);
        return -6;
    }

#if defined(__arm64__) || defined(__aarch64__)
    arm_thread_state64_t threadState;
    memset(&threadState, 0, sizeof(threadState));

    // x0 = const char *path (remotePath), x1 = int mode (RTLD_NOW = 0x2)
    threadState.__x[0] = (uint64_t)remotePath;
    threadState.__x[1] = (uint64_t)RTLD_NOW;
    threadState.__sp   = (uint64_t)(remoteStack + (stackSize / 2));
    threadState.__pc   = (uint64_t)dlopenAddr;

    thread_act_t remoteThread = MACH_PORT_NULL;
    kr = thread_create_running(
        task,
        ARM_THREAD_STATE64,
        (thread_state_t)&threadState,
        ARM_THREAD_STATE64_COUNT,
        &remoteThread
    );

    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(task, remotePath, pathAllocSize);
        mach_vm_deallocate(task, remoteStack, stackSize);
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "thread_create_running failed (PPL/PAC active): 0x%x", kr);
        return -7;
    }

    mach_port_deallocate(mach_task_self(), remoteThread);
#endif

    mach_port_deallocate(mach_task_self(), task);
    return 0;
}

// ============================================================================
// 2. Root Kernel PF / Socket Traffic Shaper Fallback (UID 0 via Persona)
//    Ensures TCP/UDP holding, packet drop %, and latency work on PPL devices
// ============================================================================
extern "C" int AetherApplyRootTrafficControl(pid_t pid, AetherSharedState *state) {
    if (!state || pid <= 0) return -1;

    bool active = aether_atomic_load(&state->interceptionActive);
    uint8_t direction = aether_atomic_load(&state->direction);
    uint8_t protoFilter = aether_atomic_load(&state->protocolFilter);
    uint8_t mode = aether_atomic_load(&state->interceptMode);
    uint32_t ratio = aether_atomic_load(&state->captureRatioPercent);

    // ── Root Engine capture (3.3.0) ──────────────────────────────────────
    // SIGSTOP freezing REMOVED per user decision — it froze the target's
    // whole UI instead of capturing packets. Real L4 TCP/UDP capture is done
    // by the hook payload that the HUD daemon installs into the roothide
    // TweakInject directory; ellekit injects it into the target process at
    // its next launch and the fishhook engine enforces Hold/Drop/Delay.
    if (active) {
        static int sLoggedRootActive = 0;
        if (!sLoggedRootActive) {
            sLoggedRootActive = 1;
            AetherLog(@"root engine active pid %d — capture via injected hook payload (no freeze)", pid);
        }
    }

    // When active in Hold/Freeze mode with 100% capture, we can also use SIGSTOP/socket buffer
    // conditioning or PF anchor rules scoped to the target PID's active sockets.
    NSMutableString *pfRule = [NSMutableString string];
    if (active) {
        NSString *protoStr = (protoFilter == AetherProtoUDPOnly) ? @"udp" :
                             (protoFilter == AetherProtoTCPOnly) ? @"tcp" : @"{ tcp, udp }";

        for (uint32_t i = 0; i < state->socketEntryCount; i++) {
            AetherSocketEntry entry = state->activeSockets[i];
            if (entry.localPort == 0) continue;

            if (mode == AetherModeDropPacket || (mode == AetherModeHoldQueue && ratio >= 90)) {
                if (direction == AetherDirectionBoth || direction == AetherDirectionDownload) {
                    [pfRule appendFormat:@"block drop in quick proto %@ to any port %u probability %u%%\n",
                     protoStr, entry.localPort, ratio];
                }
                if (direction == AetherDirectionBoth || direction == AetherDirectionUpload) {
                    [pfRule appendFormat:@"block drop out quick proto %@ from any port %u probability %u%%\n",
                     protoStr, entry.localPort, ratio];
                }
            }
        }
    }

    NSString *confPath = @"/var/mobile/Library/Caches/com.aethernet.pf.conf";
    [pfRule writeToFile:confPath atomically:YES encoding:NSUTF8StringEncoding error:nil];

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
#if !TARGET_OS_SIMULATOR
    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);
#endif

    pid_t child = 0;
    if (active && pfRule.length > 0) {
        const char *args[] = { "/sbin/pfctl", "-a", "com.apple/aethernet", "-f", [confPath UTF8String], NULL };
        posix_spawn(&child, "/sbin/pfctl", NULL, &attr, (char **)args, environ);
    } else {
        const char *args[] = { "/sbin/pfctl", "-a", "com.apple/aethernet", "-F", "all", NULL };
        posix_spawn(&child, "/sbin/pfctl", NULL, &attr, (char **)args, environ);
    }

    posix_spawnattr_destroy(&attr);
    if (child > 0) {
        int status = 0;
        waitpid(child, &status, 0);
    }
    return 0;
}
