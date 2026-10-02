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

extern "C" AetherSharedState *AetherGetSharedState(void) {
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
        gSharedState->version = 240;

        aether_atomic_store(&gSharedState->targetPID, 0);
        aether_atomic_store(&gSharedState->isInjected, false);
        aether_atomic_store(&gSharedState->interceptionActive, false);
        aether_atomic_store(&gSharedState->hudVisible, false);

        // Default Interception Settings
        aether_atomic_store(&gSharedState->direction, (uint8_t)AetherDirectionBoth);
        aether_atomic_store(&gSharedState->protocolFilter, (uint8_t)AetherProtoTCPAndUDP);
        aether_atomic_store(&gSharedState->interceptMode, (uint8_t)AetherModeHoldQueue);
        aether_atomic_store(&gSharedState->activePreset, (uint8_t)AetherPresetCustom);

        aether_atomic_store(&gSharedState->captureRatioPercent, 85);
        aether_atomic_store(&gSharedState->downloadHoldPercent, 85);
        aether_atomic_store(&gSharedState->uploadHoldPercent, 90);
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
    state->socketEntryCount = 0;
}
