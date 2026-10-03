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
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>

// BPF (Berkeley Packet Filter) constants — iOS SDK doesn't ship net/bpf.h
// so we define the few constants we need manually.
struct bpf_version {
    u_int8_t bv_major;
    u_int8_t bv_minor;
};
struct bpf_hdr {
    struct bpf_timeval bh_tstamp;  // timestamp
    u_int16_t          bh_hdrlen;   // header length
    u_int16_t          bh_caplen;   // captured length
    u_int16_t          bh_datalen;  // original length
    u_int16_t          bh_hdroff;   // offset from start to packet
};
#define BIOCVERSION     _IOR('B', 101, struct bpf_version)
#define BIOCIMMEDIATE   _IOW('B', 117, u_int)
#define BIOCSBLEN       _IOW('B', 202, u_int)
#define BIOCSHDRL       _IOW('B', 203, u_int)
#define BIOCSHDRXMIT    _IOW('B', 205, u_int)
#define BPF_WORDALIGN(x) (((x) + (4 - 1)) & ~((4 - 1)))

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

// ============================================================================
// 3. BPF (Berkeley Packet Filter) Fallback Packet Capture
//    Uses /dev/bpf to capture TCP/UDP packets at the link layer.
//    Works WITHOUT Mach injection — only needs root via posix_spawn persona.
//    This is a separate, complementary path to the dylib hooks: when
//    the hook payload can't be injected (e.g. PPL blocks, non-Dopamine JB),
//    BPF gives us real packet visibility for monitoring/telemetry even if
//    we can't modify send/recv calls in-process.
//
//    Limitations:
//      - Read-only capture (can't modify/drop packets in-flight without pf)
//      - Requires root (UID 0 via persona_np)
//      - /dev/bpf may not be writable on some jailbreak configurations
// ============================================================================

static void *AetherBPFCaptureThread(void *arg) {
    int bfd = -1;
    for (int i = 0; i < 16; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/bpf%d", i);
        bfd = open(path, O_RDONLY);
        if (bfd >= 0) break;
    }
    if (bfd < 0) {
        AetherLogDaemon(@"[bpf] cannot open /dev/bpf (errno=%d) — BPF capture unavailable", errno);
        return NULL;
    }

    struct bpf_version bv;
    if (ioctl(bfd, BIOCVERSION, &bv) < 0) {
        AetherLogDaemon(@"[bpf] BIOCVERSION failed — not a BPF device", errno);
        close(bfd);
        return NULL;
    }
    AetherLogDaemon(@"[bpf] version %d.%d ready", bv.bv_major, bv.bv_minor);

    // Set to immediate mode (read returns as soon as a packet arrives)
    u_int immediate = 1;
    ioctl(bfd, BIOCIMMEDIATE, &immediate);

    // Request whole packet (no truncation)
    u_int dlen = 65535;
    ioctl(bfd, BIOCSBLEN, &dlen);

    // Enable header generation
    u_int header = 1;
    ioctl(bfd, BIOCSHDRXMIT, &header);  // some kernels use this
    ioctl(bfd, BIOCSHDRL, &header);     // others use this

    // Set buffer size (large for burst handling)
    int blen = 1 << 20;  // 1MB buffer
    ioctl(bfd, BIOCSBLEN, &blen);

    // Use non-blocking on the fd so we can poll shared state
    int flags = fcntl(bfd, F_GETFL, 0);
    fcntl(bfd, F_SETFL, flags | O_NONBLOCK);

    AetherSharedState *state = AetherGetSharedState();
    uint64_t bpfPacketsRX = 0, bpfPacketsTX = 0;

    char buf[65535];
    while (state && aether_atomic_load(&state->hudVisible)) {
        ssize_t n = read(bfd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);  // 1ms sleep — don't spin
                continue;
            }
            break;
        }

        // Walk the BPF buffer: sequence of (struct bpf_hdr, packet, pad)
        ssize_t offset = 0;
        while (offset < n) {
            struct bpf_hdr *bh = (struct bpf_hdr *)(buf + offset);
            if (bh->bh_caplen == 0) break;

            // bh_hdr is the bpf header; packet data starts after it
            void *pkt = buf + offset + bh->bh_hdrlen;
            size_t caplen = bh->bh_caplen;

            // Parse link-layer (Ethernet) header to determine direction
            // On iOS, Ethernet header is 14 bytes (if present)
            // The BPF interface on iOS gives raw 802.11 or Ethernet

            // Update BPF telemetry counters
            bpfPacketsRX++;
            aether_atomic_store(&state->totalBPFPacketsRX, bpfPacketsRX);
            aether_atomic_store(&state->totalBytesRX, aether_atomic_load(&state->totalBytesRX) + caplen);

            // Advance to next packet
            size_t hdr_len = bh->bh_hdrlen;
            size_t caplen_aligned = BPF_WORDALIGN(caplen + hdr_len);
            offset += caplen_aligned;
            if (offset >= n) break;
        }

        // Log every 50 packets to avoid flooding
        if ((bpfPacketsRX + bpfPacketsTX) % 50 == 0) {
            AetherLogDaemon(@"[bpf] captured %llu packets (rx=%llu)",
                            bpfPacketsRX, bpfPacketsRX);
        }
    }

    AetherLogDaemon(@"[bpf] capture thread exiting — hudVisible=%d", state ? aether_atomic_load(&state->hudVisible) : -1);
    close(bfd);
    return NULL;
}

/// Spawn a BPF capture thread when root PF fallback is in use but no dylib hooks.
/// This gives us real packet visibility for monitoring even without in-process hooks.
extern "C" void AetherStartBPFCaptureIfAvailable(void) {
    // Try to start BPF capture in background
    pthread_t thr;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thr, &attr, AetherBPFCaptureThread, NULL) == 0) {
        AetherLogDaemon(@"[bpf] capture thread spawned");
    } else {
        AetherLogDaemon(@"[bpf] capture thread spawn failed (errno=%d)", errno);
    }
    pthread_attr_destroy(&attr);
}
