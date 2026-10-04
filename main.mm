//
//  main.mm
//  AetherNet — Single-binary dispatcher
//
//  (no args) → AetherMainAppMain()  : normal 2-tab UI app
//  -hud      → HUDMain()            : root global floating button daemon
//  -exit     → HUDMain()            : kill HUD daemon
//  -check    → HUDMain()            : HUD liveness probe (exit-code protocol)
//  -rootctl  → AetherRootCtlMain()  : short-lived root helper (freeze/pfctl)
//

#import <Foundation/Foundation.h>
#include <string.h>

#import "Core/AetherLog.h"
#import "Core/L4Engine/AetherShaper.h"
#import "Core/L4Engine/AetherKernelLane.h"
#import "HUD/HUDMain.mm"
#import "UI/MainApp.mm"

BOOL gAetherIsDaemon = NO;

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc > 1) {
            // -rootctl never builds a UI: it is the short-lived root helper the
            // app spawns (persona UID 0) to signal targets and drive pfctl.
            if (strcmp(argv[1], "-rootctl") == 0) {
                // argv[1] is the mode selector, the verb is argv[2].
                return AetherRootCtlMain(argc - 1, argv + 1);
            }
            if (strcmp(argv[1], "-bftap") == 0) {
                // Long-lived root tap helper: "-bftap <pid> <primary>"
                return AetherBpfTapMain(argc - 1, argv + 1);
            }
            gAetherIsDaemon = YES;
            AetherLog(@"daemon launched argc=%d argv1=%s", argc, argc > 1 ? argv[1] : "");
            int hudResult = HUDMain(argc, argv);
            if (hudResult != -1) {
                return hudResult;
            }
        }
        AetherLog(@"app launched");
        return AetherMainAppMain(argc, argv);
    }
}
