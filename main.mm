//
//  main.mm
//  AetherNet — Single-binary dispatcher
//
//  (no args) → AetherMainAppMain()  : normal 2-tab UI app
//  -hud      → HUDMain()            : root global floating button daemon
//  -exit     → HUDMain()            : kill HUD daemon
//  -check    → HUDMain()            : HUD liveness probe (exit-code protocol)
//

#import <Foundation/Foundation.h>
#import "Core/AetherLog.h"
#import "HUD/HUDMain.mm"
#import "UI/MainApp.mm"

BOOL gAetherIsDaemon = NO;

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc > 1) {
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
