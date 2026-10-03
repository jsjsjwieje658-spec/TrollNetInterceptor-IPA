//
//  NECPCapture.h
//  AetherNet — Tier 0: NECP (Network Extension Control Plane) Kernel Packet Filter
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern "C" int AetherNECPStartCapture(pid_t pid, char *errBuf, size_t errBufLen);
extern "C" void AetherNECPStopCapture(void);
extern "C" BOOL AetherNECPIsRunning(void);

NS_ASSUME_NONNULL_END