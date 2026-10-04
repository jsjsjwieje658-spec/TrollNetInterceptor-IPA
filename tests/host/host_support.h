//
//  host_support.h
//  AetherNet — host (Linux) support layer for the simulation harness
//
//  The iOS build gets AetherGetSharedState() from Core/AetherSharedMemory.mm
//  and logging from Core/AetherLog.mm.  On the build host neither exists, so
//  this file provides byte-compatible stand-ins.  Everything else — the packet
//  core, the hook core, the policy engine — is the *same source* that ships to
//  the device.
//

#ifndef AETHER_HOST_SUPPORT_H
#define AETHER_HOST_SUPPORT_H

#include <stdint.h>
#include <stdbool.h>
#include "../../headers/AetherNetShared.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Path of the shared-state file for the current test (env AETHER_TEST_SHM).
const char *AetherTestShmPath(void);

/// Write a human readable policy into the shared state.
typedef struct {
    uint8_t  direction;
    uint8_t  protocolFilter;
    uint8_t  mode;
    uint32_t captureRatio;
    uint32_t rxRatio;
    uint32_t txRatio;
    uint32_t latencyMs;
    uint32_t jitterMs;
    uint32_t bandwidthKbps;
    uint32_t autoFlushSeconds;
    uint32_t duplicatePct;
} AetherTestPolicy;

void AetherTestResetState(pid_t targetPID);
void AetherTestApplyPolicy(const AetherTestPolicy *policy);
void AetherTestSetActive(bool active);

/// Log callback for AetherHookCoreSetLog() on the host.
void AetherHostLogLine(const char *line);

#ifdef __cplusplus
}
#endif

#endif /* AETHER_HOST_SUPPORT_H */
