//
//  host_support.c
//  AetherNet — host stand-ins for the shared-memory / logging layer
//

#include "host_support.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Shared state — same file-backed mmap contract as Core/AetherSharedMemory.mm
// ---------------------------------------------------------------------------
static AetherSharedState *gSharedState = NULL;
static AetherSharedState *gAdoptedState = NULL;

extern "C" void AetherSharedStateAdopt(void *region) {
    if (!region) return;
    gAdoptedState = (AetherSharedState *)region;
}

const char *AetherTestShmPath(void) {
    const char *p = getenv("AETHER_TEST_SHM");
    return p ? p : "/tmp/aether-test.shm";
}

extern "C" AetherSharedState *AetherGetSharedState(void) {
    if (gAdoptedState) return gAdoptedState;
    if (gSharedState)  return gSharedState;

    const char *path = AetherTestShmPath();
    int fd = open(path, O_RDWR | O_CREAT, 0666);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) == 0 && (size_t)st.st_size < sizeof(AetherSharedState)) {
        ftruncate(fd, (off_t)sizeof(AetherSharedState));
    }
    void *mapped = mmap(NULL, sizeof(AetherSharedState),
                        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED || mapped == NULL) return NULL;

    gSharedState = (AetherSharedState *)mapped;
    if (gSharedState->magic != AETHER_SHM_MAGIC) {
        // Cast to void *: the region is a C11 <stdatomic.h> layout that the
        // C++ side reinterprets as std::atomic members, and clearing it byte
        // wise is exactly what we want.
        memset((void *)gSharedState, 0, sizeof(AetherSharedState));
        gSharedState->magic   = AETHER_SHM_MAGIC;
        gSharedState->version = AETHER_BUILD_NUM;
    }
    return gSharedState;
}

extern "C" void AetherResetTelemetryForNewTarget(AetherSharedState *state,
                                                 pid_t pid,
                                                 const char *name,
                                                 const char *bundleID,
                                                 const char *execPath) {
    if (!state) return;
    aether_atomic_store(&state->targetPID, pid);
    strncpy(state->targetProcessName, name ? name : "Unknown",
            sizeof(state->targetProcessName) - 1);
    strncpy(state->targetBundleID, bundleID ? bundleID : "com.host.test",
            sizeof(state->targetBundleID) - 1);
    strncpy(state->targetExecutablePath, execPath ? execPath : "",
            sizeof(state->targetExecutablePath) - 1);

    aether_atomic_store(&state->activeTCPSockets, 0);
    aether_atomic_store(&state->activeUDPSockets, 0);
    aether_atomic_store(&state->totalTCPPacketsRX, 0);
    aether_atomic_store(&state->totalTCPPacketsTX, 0);
    aether_atomic_store(&state->totalUDPPacketsRX, 0);
    aether_atomic_store(&state->totalUDPPacketsTX, 0);
    aether_atomic_store(&state->totalBytesRX, 0);
    aether_atomic_store(&state->totalBytesTX, 0);
    aether_atomic_store(&state->heldPacketsCount, 0);
    aether_atomic_store(&state->droppedPacketsCount, 0);
    aether_atomic_store(&state->currentRXRateBps, 0);
    aether_atomic_store(&state->currentTXRateBps, 0);
    aether_atomic_store(&state->currentPacketRatePps, 0);
    aether_atomic_store(&state->kernelTapPacketsRX, 0);
    aether_atomic_store(&state->kernelTapPacketsTX, 0);
    aether_atomic_store(&state->kernelTapBytesRX, 0);
    aether_atomic_store(&state->kernelTapBytesTX, 0);
    aether_atomic_store(&state->kernelTapFlows, 0);
    aether_atomic_store(&state->activeLanes, 0);
    aether_atomic_store(&state->freezeActive, 0);
    state->socketEntryCount = 0;
}

// ---------------------------------------------------------------------------
// Logging — mirrors AetherLogDaemon(): append to a file, never to stdout
// (stdout belongs to the test protocol).
// ---------------------------------------------------------------------------
extern "C" void AetherLogDaemon(const char *fmt, ...) {
    const char *path = getenv("AETHER_TEST_LOG");
    if (!path) return;
    FILE *f = fopen(path, "a");
    if (!f) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fputc('\n', f);
    fclose(f);
}

void AetherHostLogLine(const char *line) {
    AetherLogDaemon("%s", line);
}

// ---------------------------------------------------------------------------
// Policy helpers used by the test programs
// ---------------------------------------------------------------------------
void AetherTestResetState(pid_t targetPID) {
    AetherSharedState *st = AetherGetSharedState();
    if (!st) return;
    AetherResetTelemetryForNewTarget(st, targetPID, "fake_target",
                                     "com.host.fake.target", "/tmp/fake_target");
    aether_atomic_store(&st->isInjected, true);
    aether_atomic_store(&st->injectionMethod, (uint8_t)AetherMethodInProcess);
    aether_atomic_store(&st->interceptionActive, false);
}

void AetherTestApplyPolicy(const AetherTestPolicy *policy) {
    AetherSharedState *st = AetherGetSharedState();
    if (!st || !policy) return;
    aether_atomic_store(&st->direction,        policy->direction);
    aether_atomic_store(&st->protocolFilter,   policy->protocolFilter);
    aether_atomic_store(&st->interceptMode,    policy->mode);
    aether_atomic_store(&st->captureRatioPercent, policy->captureRatio);
    aether_atomic_store(&st->downloadHoldPercent, policy->rxRatio);
    aether_atomic_store(&st->uploadHoldPercent,   policy->txRatio);
    aether_atomic_store(&st->simulatedLatencyMs,  policy->latencyMs);
    aether_atomic_store(&st->simulatedJitterMs,   policy->jitterMs);
    aether_atomic_store(&st->bandwidthLimitKbps,  policy->bandwidthKbps);
    aether_atomic_store(&st->autoFlushSeconds,    policy->autoFlushSeconds);
    aether_atomic_store(&st->duplicatePacketPercent, policy->duplicatePct);
}

void AetherTestSetActive(bool active) {
    AetherSharedState *st = AetherGetSharedState();
    if (!st) return;
    aether_atomic_store(&st->interceptionActive, active);
}

#ifdef __cplusplus
}
#endif
