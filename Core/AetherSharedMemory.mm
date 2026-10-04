//
//  AetherSharedMemory.mm
//  AetherNet — Lock-Free Shared Memory IPC Manager
//

#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "../headers/AetherNetShared.h"

static AetherSharedState *gSharedState = NULL;

// ---------------------------------------------------------------------------
// Injector handoff.
//
// AetherGetSharedState() normally maps a file under /var/mobile/Library/Caches.
// Two problems with that inside an *injected* payload:
//   • App Store apps are sandboxed and cannot open that path;
//   • even when they can, we would rather not depend on the filesystem.
//
// So the injector additionally maps the very same physical pages into the
// target (mach_make_memory_entry_64 + mach_vm_map over the task port) and then
// calls this setter through a remote thread.  Once adopted, the payload uses
// the injected mapping instead of the file.
// ---------------------------------------------------------------------------
static AetherSharedState *gAdoptedState = NULL;

extern "C" void AetherSharedStateAdopt(void *region) {
    if (!region) return;
    gAdoptedState = (AetherSharedState *)region;
}

extern "C" AetherSharedState *AetherGetSharedState(void) {
    if (gAdoptedState != NULL) {
        return gAdoptedState;
    }
    if (gSharedState != NULL) {
        return gSharedState;
    }

    // Ensure directory exists when unsandboxed via TrollStore
    umask(0);
    int fd = open(AETHER_SHM_PATH, O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        // Fallback to NSTemporaryDirectory if running inside Simulator
        NSString *fallbackPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"com.aethernet.shared.shm"];
        fd = open([fallbackPath UTF8String], O_RDWR | O_CREAT, 0666);
        if (fd < 0) {
            return NULL;
        }
    }

    struct stat st;
    if (fstat(fd, &st) == 0 && (size_t)st.st_size < sizeof(AetherSharedState)) {
        ftruncate(fd, sizeof(AetherSharedState));
    }

    void *mapped = mmap(NULL, sizeof(AetherSharedState), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (mapped == MAP_FAILED || mapped == NULL) {
        return NULL;
    }

    gSharedState = (AetherSharedState *)mapped;

    // Initialize default state on first boot
    if (gSharedState->magic != AETHER_SHM_MAGIC) {
        memset(gSharedState, 0, sizeof(AetherSharedState));
        gSharedState->magic = AETHER_SHM_MAGIC;
        gSharedState->version = AETHER_BUILD_NUM;

        aether_atomic_store(&gSharedState->targetPID, 0);
        aether_atomic_store(&gSharedState->isInjected, false);
        aether_atomic_store(&gSharedState->interceptionActive, false);
        aether_atomic_store(&gSharedState->hudVisible, false);

        // Default Interception Settings
        aether_atomic_store(&gSharedState->direction, (uint8_t)AetherDirectionBoth);
        aether_atomic_store(&gSharedState->protocolFilter, (uint8_t)AetherProtoTCPAndUDP);
        aether_atomic_store(&gSharedState->interceptMode, (uint8_t)AetherModeObserve);
        aether_atomic_store(&gSharedState->activePreset, (uint8_t)AetherPresetCustom);
        aether_atomic_store(&gSharedState->allowFreeze, 0);   // never freeze by default
        aether_atomic_store(&gSharedState->lagSpikeMs, 0);     // ping simulation off
        aether_atomic_store(&gSharedState->lagCycleMs, 1000);

        aether_atomic_store(&gSharedState->captureRatioPercent, 100);
        aether_atomic_store(&gSharedState->downloadHoldPercent, 100);
        aether_atomic_store(&gSharedState->uploadHoldPercent, 100);
        aether_atomic_store(&gSharedState->simulatedLatencyMs, 120);
        aether_atomic_store(&gSharedState->simulatedJitterMs, 25);
        aether_atomic_store(&gSharedState->bandwidthLimitKbps, 0); // Unlimited
        aether_atomic_store(&gSharedState->duplicatePacketPercent, 0);
        aether_atomic_store(&gSharedState->autoFlushSeconds, 12);

        // Default Floating HUD Button Settings
        aether_atomic_store(&gSharedState->floatingButtonSize, 58.0f);
        aether_atomic_store(&gSharedState->floatingButtonOpacity, 0.94f);
        aether_atomic_store(&gSharedState->floatingEdgeSnap, true);
        aether_atomic_store(&gSharedState->floatingLockPosition, false);
        aether_atomic_store(&gSharedState->floatingHapticEnabled, true);
        aether_atomic_store(&gSharedState->floatingPosX, 310.0f);
        aether_atomic_store(&gSharedState->floatingPosY, 220.0f);
    } else if (gSharedState->version < AETHER_BUILD_NUM) {
        // Upgrade path.  Shared memory outlives the app (the HUD daemon keeps
        // it alive), so a persisted setting from an older build keeps applying
        // after an update: users who never touched "Intercept mode" stayed on
        // the old default (Hold), which on a device without pfctl means the
        // target gets SIGSTOPped for the whole session.  Migrate defaults that
        // changed meaning; leave everything the user actually set alone.
        // 4.1.3: a persisted Hold/Drop mode made the shaper SIGSTOP the target
        // on devices without pfctl — the app visibly froze (no FPS) and the
        // capture starved with it.  Reset both the mode and the new opt-in to
        // the capture-only defaults; anything the user sets afterwards sticks.
        if (gSharedState->version < 413U) {
            aether_atomic_store(&gSharedState->interceptMode, (uint8_t)AetherModeObserve);
            aether_atomic_store(&gSharedState->allowFreeze, 0);
        }
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
    strncpy(state->targetProcessName, name ? name : "Unknown", sizeof(state->targetProcessName) - 1);
    strncpy(state->targetBundleID, bundleID ? bundleID : "com.apple.unknown", sizeof(state->targetBundleID) - 1);
    strncpy(state->targetExecutablePath, execPath ? execPath : "", sizeof(state->targetExecutablePath) - 1);

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
    aether_atomic_store(&state->kernelTapDropped, 0);
    aether_atomic_store(&state->activeLanes, 0);
    aether_atomic_store(&state->freezeActive, 0);
    if (state->engineStatus[0] != '\0') state->engineStatus[0] = '\0';
    state->socketEntryCount = 0;
}
