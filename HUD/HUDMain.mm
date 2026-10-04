//
//  HUDMain.mm
//  AetherNet — Global HUD Daemon Entry Point
//
//  Touch delivery ported from TrollSpeed (Lessica, MIT):
//    BKSHIDEventRegisterEventCallback → AXEventRepresentation → TSEventFetcher
//    → synthetic UIEvent → UIGestureRecognizers (tap/pan on the floating button)
//
//  Modes:
//    -hud       -> Root plugin-mode UIApplication hosting the global Floating Button
//    -exit      -> Kills the running HUD daemon
//    -check     -> Exit code signals whether HUD is alive (TrollSpeed convention)
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import "../Core/ProcessManager.h"
#import <objc/runtime.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ucontext.h>
#include <pthread.h>
#import "../Core/L4Engine/AetherKernelLane.h"
#include <dlfcn.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>
#include <time.h>
#include <notify.h>
#include "../headers/AetherNetShared.h"
#include "../headers/PrivateSystemSPI.h"
#import "HUDRootApplication.mm"
#import "TSEventFetcher.h"
#import "UITouchKIFAdditions.h"

#pragma mark - AXEventRepresentation private interface (AccessibilityUtilities)

@class AXEventPathInfo;

@interface AXEventRepresentation : NSObject
+ (instancetype)representationWithHIDEvent:(IOHIDEventRef)event
                       hidStreamIdentifier:(NSString *)hidStreamIdentifier;
- (CGPoint)location;
- (BOOL)isTouchDown;
- (BOOL)isMove;
- (BOOL)isCancel;
- (BOOL)isLift;
- (BOOL)isInRange;
- (BOOL)isInRangeLift;
- (NSDictionary *)handInfo;
@end

@interface AXEventHandPathsBox : NSObject
- (NSArray *)paths;
@end

@interface AXEventPathEntry : NSObject
- (NSInteger)pathIdentity;
@end

#import "../Core/AetherLog.h"

//
//  HUDMain.mm — Minimal Hook Payload Installer (Tier 1 fallback only)
//  NECP (Tier 0) requires NO injection. This only stages dylib for Mach injection fallback.
//
#pragma mark - Minimal Hook Payload Installer (Tier 1 fallback only)

static int AetherTryCopy(NSString *src, NSString *dst)
{
    NSData *data = [NSData dataWithContentsOfFile:src];
    if (!data) return -1;
    unlink(dst.fileSystemRepresentation);
    int fd = open(dst.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) return -2;
    const char *bytes = (const char *)[data bytes];
    NSUInteger remaining = [data length];
    while (remaining > 0) {
        ssize_t w = write(fd, bytes, remaining);
        if (w <= 0) { close(fd); return -3; }
        bytes += w; remaining -= (NSUInteger)w;
    }
    close(fd);
    chmod(dst.fileSystemRepresentation, 0755);
    return 0;
}

static void AetherInstallHookPayload(void)
{
    @try {
        char exePath[4096] = {0};
        uint32_t len = sizeof(exePath);
        if (_NSGetExecutablePath(exePath, &len) != 0) return;
        NSString *exe = [NSString stringWithUTF8String:exePath];
        if (!exe) return;
        NSString *srcDylib = [[exe stringByDeletingLastPathComponent]
                              stringByAppendingPathComponent:@"libNetHookPayload.dylib"];
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:srcDylib]) {
            AetherLog(@"[installer] payload missing at %@", srcDylib);
            return;
        }

        // ── Stage signed dylib to world-readable cache for Mach injection (Tier 1) ──
        // NECP (Tier 0) requires NO injection at all. This is ONLY for fallback.
        NSString *cacheDylib = @"/var/mobile/Library/Caches/libNetHookPayload.dylib";
        [fm removeItemAtPath:cacheDylib error:nil];
        BOOL ok = [fm copyItemAtPath:srcDylib toPath:cacheDylib error:nil];
        if (!ok) {
            NSData *raw = [NSData dataWithContentsOfFile:srcDylib];
            ok = [raw writeToFile:cacheDylib atomically:YES];
        }
        if (ok) {
            chmod(cacheDylib.fileSystemRepresentation, 0755);
            AetherLog(@"[installer] staged dylib for Mach fallback -> %@ (%llu bytes)",
                      cacheDylib, (unsigned long long)[[fm attributesOfItemAtPath:cacheDylib error:nil] fileSize]);
        } else {
            AetherLog(@"[installer] failed to stage dylib to cache");
        }
    }
    @catch (NSException *ex) {
        AetherLog(@"[installer] exception: %@", ex.reason);
    }
}


#pragma mark - Raw digitizer touch path (primary — no AXEventRepresentation needed)

// iOS 16 / roothide: AXEventRepresentation selectors may be unavailable, which
// made the floating button inert. Parse IOHIDEvent digitizer trees directly.
// The digitizer coordinate space varies by build (points / pixels / rotated /
// panel units), so every Began is tested against a family of affine
// transforms; the first transform that lands on the button is locked.
static int       (*_IOHIDEventGetType)(void *event);
static int       (*_IOHIDEventGetIntegerValue)(void *event, uint32_t field);
static CFArrayRef (*_IOHIDEventGetChildren)(void *event);
static BOOL gRawDigitizerReady = NO;

#define kAeDigType        11
#define kAeDigBase        (11 << 16)
#define kAeFieldX         (kAeDigBase + 0)
#define kAeFieldY         (kAeDigBase + 1)
#define kAeFieldIdentity  (kAeDigBase + 6)
#define kAeFieldEventMask (kAeDigBase + 7)
#define kAeFieldTouch     (kAeDigBase + 9)
#define kAeDigRange     (1 << 0)
#define kAeDigTouchEvt  (1 << 1)
#define kAeDigPosition  (1 << 2)
#define kAeDigStop      (1 << 3)
#define kAeDigCancel    (1 << 7)

#define kAeTransformCount 8

static uint8_t gPrevTouching[100];
static BOOL    gOurTouch[100];
static NSInteger gLockedTransform = -1; // index into the transform table
static int    gHudLoggedEvents = 0;

extern UIView *gAetherFloatingButtonView;

static void AetherResolveRawDigitizer(void)
{
    _IOHIDEventGetType          = (int (*)(void *))dlsym(RTLD_DEFAULT, "IOHIDEventGetType");
    _IOHIDEventGetIntegerValue  = (int (*)(void *, uint32_t))dlsym(RTLD_DEFAULT, "IOHIDEventGetIntegerValue");
    _IOHIDEventGetChildren      = (CFArrayRef (*)(void *))dlsym(RTLD_DEFAULT, "IOHIDEventGetChildren");
    gRawDigitizerReady = (_IOHIDEventGetType && _IOHIDEventGetIntegerValue && _IOHIDEventGetChildren);
    AetherSharedState *st = AetherGetSharedState();
    if (st) aether_atomic_store(&st->dbgRawReady, gRawDigitizerReady ? 1 : 0);
}

// Synchronous delivery — TrollSpeed style. The BKS HID callback context is
// the same one TrollSpeed injects touches from; never hop to the dispatch
// main queue here (plugin-mode daemons may never drain it — 2.8.0 lesson).
static void AetherDeliverRawTouch(NSInteger pointerId, CGPoint location, UITouchPhase phase)
{
    @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        UIWindow *keyWindow = [UIApplication.sharedApplication keyWindow];
        if (!keyWindow) keyWindow = [UIApplication.sharedApplication windows].firstObject;
#pragma clang diagnostic pop
        if (!keyWindow || !gAetherFloatingButtonView) return;

        if (phase == UITouchPhaseBegan) gOurTouch[pointerId] = YES;
        else if (!gOurTouch[pointerId]) return;
        if (phase == UITouchPhaseEnded || phase == UITouchPhaseCancelled) gOurTouch[pointerId] = NO;

        AetherSharedState *st = AetherGetSharedState();
        if (st) aether_atomic_fetch_add(&st->dbgDeliveredCount, 1);
        [TSEventFetcher receiveAXEventID:pointerId
                      atGlobalCoordinate:location
                          withTouchPhase:phase
                                inWindow:keyWindow
                                  onView:gAetherFloatingButtonView];
    }
    @catch (NSException *exception) { /* never kill the daemon */ }
}

// Build the candidate point table for a raw (x, y) sample.
// Returns the number of candidates written into `out`.
static NSInteger AetherCandidatePoints(int x, int y, CGFloat winW, CGFloat winH, CGPoint *out)
{
    NSInteger n = 0;
    out[n++] = CGPointMake(x, y);                       // 0: identity (points)
    out[n++] = CGPointMake(x / 2.0, y / 2.0);           // 1: native pixels ÷2
    out[n++] = CGPointMake(x / 3.0, y / 3.0);           // 2: native pixels ÷3
    out[n++] = CGPointMake(y, x);                       // 3: rotated
    out[n++] = CGPointMake(y / 2.0, x / 2.0);           // 4: rotated ÷2
    out[n++] = CGPointMake(y / 3.0, x / 3.0);           // 5: rotated ÷3
    AetherSharedState *st = AetherGetSharedState();
    uint32_t mx = st ? aether_atomic_load(&st->dbgMaxX) : 0;
    uint32_t my = st ? aether_atomic_load(&st->dbgMaxY) : 0;
    if (mx > 60 && my > 60 && winW > 60 && winH > 60) { // 6/7: adaptive (panel units)
        out[n++] = CGPointMake((CGFloat)x / (CGFloat)mx * winW, (CGFloat)y / (CGFloat)my * winH);
        out[n++] = CGPointMake((CGFloat)y / (CGFloat)my * winW, (CGFloat)x / (CGFloat)mx * winH);
    }
    return n;
}

static void AetherProcessRawDigitizer(void *handEvent)
{
    if (!_IOHIDEventGetType || !_IOHIDEventGetIntegerValue) return;

    // Locate a digitizer event: root itself, else any digitizer child.
    void *finger = NULL;
    if (_IOHIDEventGetType(handEvent) == kAeDigType) finger = handEvent;
    if (_IOHIDEventGetChildren) {
        CFArrayRef children = _IOHIDEventGetChildren(handEvent);
        if (children) {
            CFIndex count = CFArrayGetCount(children);
            for (CFIndex i = 0; i < count; i++) {
                void *child = (void *)CFArrayGetValueAtIndex(children, i);
                if (child && _IOHIDEventGetType(child) == kAeDigType) { finger = child; break; }
            }
        }
    }
    if (!finger) return; // non-touch HID event

    AetherSharedState *st = AetherGetSharedState();
    if (st) aether_atomic_fetch_add(&st->dbgDigCount, 1);

    int x     = _IOHIDEventGetIntegerValue(finger, kAeFieldX);
    int y     = _IOHIDEventGetIntegerValue(finger, kAeFieldY);
    int mask  = _IOHIDEventGetIntegerValue(finger, kAeFieldEventMask);
    int touch = _IOHIDEventGetIntegerValue(finger, kAeFieldTouch);
    int ident = _IOHIDEventGetIntegerValue(finger, kAeFieldIdentity);

    // Some stacks report contact/mask bits only on the aggregate hand event.
    if (finger == handEvent) {
        int t2 = _IOHIDEventGetIntegerValue(handEvent, kAeFieldTouch);
        int m2 = _IOHIDEventGetIntegerValue(handEvent, kAeFieldEventMask);
        if (t2 != 0) touch = t2;
        mask |= m2;
    }

    if (st) {
        aether_atomic_store(&st->dbgLastX, (uint32_t)x);
        aether_atomic_store(&st->dbgLastY, (uint32_t)y);
        // Track the running max — approximates the panel coordinate range and
        // powers the adaptive transforms.
        uint32_t prevX = aether_atomic_load(&st->dbgMaxX);
        if ((uint32_t)x > prevX) aether_atomic_store(&st->dbgMaxX, (uint32_t)x);
        uint32_t prevY = aether_atomic_load(&st->dbgMaxY);
        if ((uint32_t)y > prevY) aether_atomic_store(&st->dbgMaxY, (uint32_t)y);
    }

    NSInteger pointerId = (NSInteger)MIN(MAX(ident, 1), 98);
    BOOL wasTouching = gPrevTouching[pointerId] != 0;

    UITouchPhase phase;
    if (mask & kAeDigCancel)                                phase = UITouchPhaseCancelled;
    else if (!touch && wasTouching)                         phase = UITouchPhaseEnded;
    else if (touch && !wasTouching)                         phase = UITouchPhaseBegan;
    else if (touch && (mask & (kAeDigPosition|kAeDigTouchEvt|kAeDigRange|kAeDigStop))) phase = UITouchPhaseMoved;
    else return; // stationary duplicate
    gPrevTouching[pointerId] = touch ? 1 : 0;

    if (phase != UITouchPhaseBegan && phase != UITouchPhaseEnded) {
        // Continue an already-accepted touch with the locked transform.
        if (gOurTouch[pointerId] && gLockedTransform >= 0 && st) {
            CGPoint cands[kAeTransformCount];
            CGFloat w = (CGFloat)aether_atomic_load(&st->dbgWinW);
            CGFloat h = (CGFloat)aether_atomic_load(&st->dbgWinH);
            NSInteger n = AetherCandidatePoints(x, y, w, h, cands);
            if (gLockedTransform < n) {
                AetherDeliverRawTouch(pointerId, cands[gLockedTransform], phase);
            }
        }
        return;
    }

    if (st) aether_atomic_fetch_add(&st->dbgBeganCount, 1);

    // ── Began / Ended: resolve the transform and accept only button touches ──
    @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        UIWindow *keyWindow = [UIApplication.sharedApplication keyWindow];
        if (!keyWindow) keyWindow = [UIApplication.sharedApplication windows].firstObject;
#pragma clang diagnostic pop
        if (!keyWindow || !gAetherFloatingButtonView) return;

        CGFloat winW = keyWindow.bounds.size.width;
        CGFloat winH = keyWindow.bounds.size.height;
        // .center lives in the SUPERVIEW's coordinate space. Converting it via
        // the button itself yielded 2*center-origin — the 3.1.x hit-test bug
        // (log showed btn=(591,411) while the real center was (310,220)).
        UIView *btnSuper = gAetherFloatingButtonView.superview;
        CGPoint btnCenter = btnSuper
            ? [btnSuper convertPoint:gAetherFloatingButtonView.center toView:nil]
            : gAetherFloatingButtonView.center;
        CGFloat btnR = MAX(gAetherFloatingButtonView.bounds.size.width,
                           gAetherFloatingButtonView.bounds.size.height) / 2.0 + 26.0;

        if (st) {
            aether_atomic_store(&st->dbgWinW, (uint32_t)winW);
            aether_atomic_store(&st->dbgWinH, (uint32_t)winH);
            aether_atomic_store(&st->dbgBtnX, (uint32_t)btnCenter.x);
            aether_atomic_store(&st->dbgBtnY, (uint32_t)btnCenter.y);
        }

        CGPoint cands[kAeTransformCount];
        NSInteger n = AetherCandidatePoints(x, y, winW, winH, cands);

        if (phase == UITouchPhaseBegan && gHudLoggedEvents < 25) {
            gHudLoggedEvents++;
            AetherLog(@"[pid %d] touch began raw=(%d,%d) btn=(%.0f,%.0f r%.0f) win=%.0fx%.0f",
                      getpid(), x, y, btnCenter.x, btnCenter.y, btnR, winW, winH);
        }
        if (phase == UITouchPhaseBegan && st) {
            uint32_t idx = (aether_atomic_load(&st->dbgBeganCount) % 4) * 2;
            aether_atomic_store(&st->dbgRing[idx],     (uint32_t)x);
            aether_atomic_store(&st->dbgRing[idx + 1], (uint32_t)y);
        }

        // Test the locked transform first, then all others.
        NSInteger order[kAeTransformCount];
        NSInteger m = 0;
        if (gLockedTransform >= 0 && gLockedTransform < n) order[m++] = gLockedTransform;
        for (NSInteger i = 0; i < n; i++) if (i != gLockedTransform) order[m++] = i;

        for (NSInteger k = 0; k < m; k++) {
            NSInteger i = order[k];
            CGPoint pt = cands[i];
            if (pt.x < -40 || pt.y < -40 || pt.x > winW + 40 || pt.y > winH + 40) continue;
            CGFloat dx = pt.x - btnCenter.x, dy = pt.y - btnCenter.y;
            BOOL inside = (dx * dx + dy * dy) <= btnR * btnR;

            if (phase == UITouchPhaseBegan) {
                if (!inside) continue;
                if (gLockedTransform != i) {
                    gLockedTransform = i;
                    AetherLog(@"touch transform LOCKED -> index %ld", (long)i);
                }
                if (st) {
                    aether_atomic_store(&st->dbgScale, (uint8_t)(i + 1));
                    aether_atomic_fetch_add(&st->dbgHitCount, 1);
                }
                AetherDeliverRawTouch(pointerId, pt, UITouchPhaseBegan);
                return;
            } else { // Ended/Cancelled for an accepted touch
                if (!gOurTouch[pointerId]) return;
                AetherDeliverRawTouch(pointerId, pt, phase);
                return;
            }
        }
        if (phase == UITouchPhaseEnded && gOurTouch[pointerId]) {
            AetherDeliverRawTouch(pointerId, CGPointMake(-999, -999), UITouchPhaseEnded);
        }
    }
    @catch (NSException *exception) { /* never kill the daemon */ }
}

#pragma mark - UIApplication singleton subclass (plugin mode)

@interface AetherHUDMainApplication : UIApplication
@end

@implementation AetherHUDMainApplication
@end

#pragma mark - Raw HID event bridge (TrollSpeed _HUDEventCallback equivalent)

// Set by HUDRootApplication when the floating button is created; used by the
// HID callback to early-out on touches that are not ours.
UIView *gAetherFloatingButtonView = nil;

static void AetherHUDMainEventCallback(void *target, void *refcon, IOHIDServiceRef service, IOHIDEventRef event)
{
    static UIApplication *app = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        app = [UIApplication sharedApplication];
    });
    if (app == nil || event == NULL) return;

    AetherSharedState *dbgState = AetherGetSharedState();
    if (dbgState) aether_atomic_fetch_add(&dbgState->dbgCallbackCount, 1);

    // ── Primary path: raw digitizer parsing (works on iOS 16 / roothide where
    //    AXEventRepresentation selectors may be missing).
    if (gRawDigitizerReady) {
        AetherProcessRawDigitizer(event);
        return;
    }

    // iOS < 15.1: raw HID events can be enqueued into UIApplication directly.
    if (@available(iOS 15.1, *)) {}
    else {
        [app _enqueueHIDEvent:event];
    }

    // iOS 15+: bridge via AXEventRepresentation → synthetic UITouch pipeline
    BOOL shouldUseAXEvent = YES;
    BOOL isExactly15 = NO;

    static NSOperatingSystemVersion version = {0, 0, 0};
    static dispatch_once_t vToken;
    dispatch_once(&vToken, ^{
        version = [[NSProcessInfo processInfo] operatingSystemVersion];
    });
    if (version.majorVersion == 15 && version.minorVersion == 0 && version.patchVersion == 0) {
        NSString *deviceModel = nil;
        struct utsname systemInfo;
        if (uname(&systemInfo) == 0) {
            deviceModel = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
        }
        // iPhone 12 & 13 series on exactly iOS 15.0 keep the legacy path (TrollSpeed)
        if (deviceModel && (![deviceModel hasPrefix:@"iPhone13,"] && ![deviceModel hasPrefix:@"iPhone14,"])) {
            isExactly15 = YES;
        }
    }

    if (@available(iOS 15.0, *)) {
        shouldUseAXEvent = !isExactly15;
    } else {
        shouldUseAXEvent = NO;
    }

    if (!shouldUseAXEvent) return;

    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AccessibilityUtilities.framework"] load];
    Class AXEventRepresentationCls = objc_getClass("AXEventRepresentation");
    if (!AXEventRepresentationCls) return;

    AXEventRepresentation *rep = [AXEventRepresentationCls representationWithHIDEvent:event
                                                              hidStreamIdentifier:@"UIApplicationEvents"];
    if (!rep) return;

    // Hard guard: every selector below must exist on this OS build, otherwise
    // struct-return forwarding (CGPoint) aborts the daemon (crash seen 2.5.0).
    if (![rep respondsToSelector:@selector(location)] ||
        ![rep respondsToSelector:@selector(isTouchDown)] ||
        ![rep respondsToSelector:@selector(isMove)] ||
        ![rep respondsToSelector:@selector(isCancel)] ||
        ![rep respondsToSelector:@selector(isLift)]) {
        return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIWindow *keyWindow = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            keyWindow = [app keyWindow];
            if (!keyWindow) keyWindow = [app windows].firstObject;
#pragma clang diagnostic pop
            if (!keyWindow) return;

            CGPoint location = [rep location];

            // Early-out: process touches that land on the floating button only.
            // (HUDMainWindow hit-testing is passthrough — nil for other touches)
            UIView *hitView = [keyWindow hitTest:location withEvent:nil];
            if (!hitView) return;
            if (gAetherFloatingButtonView &&
                hitView != gAetherFloatingButtonView &&
                ![hitView isDescendantOfView:gAetherFloatingButtonView]) return;

            UITouchPhase phase = UITouchPhaseEnded;
            if ([rep isTouchDown])                       phase = UITouchPhaseBegan;
            else if ([rep isMove])                       phase = UITouchPhaseMoved;
            else if ([rep isCancel])                     phase = UITouchPhaseCancelled;
            else if ([rep isLift] || ([rep respondsToSelector:@selector(isInRange)] && [rep isInRange]) ||
                     ([rep respondsToSelector:@selector(isInRangeLift)] && [rep isInRangeLift])) phase = UITouchPhaseEnded;

            NSInteger pointerId = 1;
            if ([rep respondsToSelector:@selector(handInfo)]) {
                NSDictionary *handInfo = [rep handInfo];
                id box = handInfo[@"paths"];
                if (box && [box respondsToSelector:@selector(paths)]) {
                    NSArray *paths = [box performSelector:@selector(paths)];
                    id entry = paths.firstObject;
                    if (entry && [entry respondsToSelector:@selector(pathIdentity)]) {
                        pointerId = [(AXEventPathEntry *)entry pathIdentity];
                    }
                }
            }

            [TSEventFetcher receiveAXEventID:MIN(MAX(pointerId, 1), 98)
                          atGlobalCoordinate:location
                              withTouchPhase:phase
                                    inWindow:keyWindow
                                      onView:hitView];
        }
        @catch (NSException *exception) {
            // Never let a malformed HID event kill the HUD daemon
        }
    });
}

#pragma mark - Private frameworks loader

// Private frameworks are NOT linked at build time (public SDK lacks their TBDs);
// load them explicitly so GSInitialize/BKSDisplayServicesStart and
// SBSAccessibilityWindowHostingController resolve via dyld at runtime.
static void AetherLoadPrivateFrameworks(void)
{
    dlopen("/System/Library/PrivateFrameworks/BackBoardServices.framework/BackBoardServices", RTLD_NOW | RTLD_GLOBAL);
    dlopen("/System/Library/PrivateFrameworks/GraphicsServices.framework/GraphicsServices", RTLD_NOW | RTLD_GLOBAL);
    dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW | RTLD_GLOBAL);
    dlopen("/System/Library/PrivateFrameworks/AccessibilityUtilities.framework/AccessibilityUtilities", RTLD_LAZY);
    dlopen("/System/Library/PrivateFrameworks/UIToolkit.framework/UIToolkit", RTLD_LAZY);
}

#pragma mark - Death reporting

// The HUD daemon dies without a word: jetsam, the iOS main-thread watchdog
// (0x8badf00d) and a fatal signal all arrive as a SIGKILL-equivalent with no
// log line, which is why "the button just disappeared" was undebuggable.
// These handlers leave a note on the way out.  They may only use
// AetherLogRawSync() — signal handlers cannot allocate, take locks or touch
// Objective-C.
static void AetherHUDFatalSignalHandler(int sig, siginfo_t *info, void *uap)
{
    (void)info;
    // pc + lr + the runtime address of one symbol we know (AetherLogRawSync)
    // is enough to work out the slide and locate the crash in the binary
    // without a device-side crash report: pc - (base - static_base).
    ucontext_t *uc = (ucontext_t *)uap;
    unsigned long long pc = 0, lr = 0;
    if (uc) {
#if defined(__arm64__) || defined(__aarch64__)
        pc = (unsigned long long)uc->uc_mcontext->__ss.__pc;
        lr = (unsigned long long)uc->uc_mcontext->__ss.__lr;
#endif
    }
    pthread_t self  = pthread_self();
    pthread_t tapT  = (pthread_t)AetherKernelLaneThread();
    const char *who = (tapT && pthread_equal(self, tapT)) ? "tap"
                    : pthread_main_np() ? "main" : "other";

    char msg[256];
    snprintf(msg, sizeof(msg),
             "[pid %d] FATAL signal %d (%s) pc=0x%llx lr=0x%llx base=0x%llx "
             "phase=%d thread=%s - HUD daemon dying",
             (int)getpid(), sig,
             (sig == SIGSEGV) ? "SIGSEGV" :
             (sig == SIGBUS)  ? "SIGBUS"  :
             (sig == SIGABRT) ? "SIGABRT" :
             (sig == SIGILL)  ? "SIGILL"  :
             (sig == SIGFPE)  ? "SIGFPE"  :
             (sig == SIGKILL) ? "SIGKILL" : "signal",
             pc, lr, (unsigned long long)(uintptr_t)&AetherLogRawSync,
             AetherKernelLanePhase(), who);
    AetherLogRawSync(msg);
    // SA_RESETHAND already restored SIG_DFL: re-raise so the process dies the
    // way it would have died, with the right exit status for the watchdog.
    raise(sig);
}

static void AetherHUDUncaughtExceptionHandler(NSException *exception)
{
    char msg[512];
    snprintf(msg, sizeof(msg),
             "[pid %d] FATAL uncaught %s: %s - HUD daemon dying",
             (int)getpid(),
             exception.name ? [exception.name UTF8String] : "exception",
             exception.reason ? [exception.reason UTF8String] : "(no reason)");
    AetherLogRawSync(msg);
}

static void AetherHUDInstallDeathReporting(void)
{
    static BOOL installed = NO;
    if (installed) return;
    installed = YES;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = AetherHUDFatalSignalHandler;
    sa.sa_flags     = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    NSSetUncaughtExceptionHandler(AetherHUDUncaughtExceptionHandler);
}

#pragma mark - HUD lifecycle

int HUDMain(int argc, char *argv[])
{
    @autoreleasepool {
        if (argc <= 1) {
            return -1; // Not a HUD invocation — fall through to normal app main
        }

        if (strcmp(argv[1], "-hud") == 0) {
            pid_t pid = getpid();

            // Installed before anything else can go wrong: from here on even a
            // crash leaves a line in the log instead of a silent disappearance.
            AetherHUDInstallDeathReporting();

            // Single-instance guard: two daemons mean two overlapping buttons
            // and duplicated HID callbacks. The second instance must exit.
            {
                NSString *oldPidStr = [NSString stringWithContentsOfFile:@AETHER_HUD_PID_PATH
                                                                encoding:NSUTF8StringEncoding
                                                                   error:nil];
                pid_t oldPid = (pid_t)oldPidStr.intValue;
                BOOL otherAlive = NO;
                if (oldPid > 0 && oldPid != pid) {
                    // 1 == really running.  2 == zombie, i.e. a previous daemon
                    // that already exited; its pid is still signallable, and
                    // believing it is what stopped every respawn from starting.
                    if (AetherPIDStateOf(oldPid) == 1) otherAlive = YES;
                }
                AetherSharedState *pre = AetherGetSharedState();
                if (!otherAlive && pre) {
                    uint64_t hb = aether_atomic_load(&pre->hudHeartbeatTs);
                    if (hb > 0 && (uint64_t)time(NULL) - hb <= 3) otherAlive = YES;
                }
                if (otherAlive) {
                    AetherLog(@"[pid %d] another HUD daemon (pid %d) already alive — exiting", pid, oldPid);
                    return 0;
                }
            }

            NSString *pidString = [NSString stringWithFormat:@"%d", pid];
            [pidString writeToFile:@AETHER_HUD_PID_PATH
                        atomically:YES
                          encoding:NSUTF8StringEncoding
                             error:nil];

            AetherLog(@"[pid %d] HUD daemon starting", getpid());
            AetherInstallHookPayload();

            AetherSharedState *state = AetherGetSharedState();
            if (state) {
                aether_atomic_store(&state->hudVisible, true);
            }

            // Self-healing: when the lanes live in THIS process, a daemon
            // restart (update, respring, silent kill) ended the capture while
            // the UI still claimed to be capturing.  Resume it — but only if no
            // other process is still running them, or every packet would be
            // counted twice.
            if (state) {
                pid_t livePID = aether_atomic_load(&state->targetPID);
                pid_t owner   = aether_atomic_load(&state->laneOwnerPID);
                BOOL ownerAlive = (owner != 0) && (kill(owner, 0) == 0 || errno == EPERM);
                if (livePID > 0 && aether_atomic_load(&state->interceptionActive)) {
                    if (ownerAlive && owner != getpid()) {
                        AetherLog(@"[pid %d] capture already owned by pid %d — not starting a "
                                  @"second tap (it would double count)", pid, owner);
                    } else {
                        AetherLog(@"[pid %d] resuming live capture session for pid %d after restart",
                                  pid, livePID);
                        // NOT on this thread and NOT now: the lane start probes
                        // the device and the BPF tap for seconds, and doing
                        // that here blocks the main thread before the run loop
                        // even exists — the classic 0x8badf00d kill.  Wait for
                        // the UI to be up, then do it in the background.
                        [[AetherProcessManager sharedManager] resumeCaptureForPID:livePID];
                    }
                }
            }

            AetherLoadPrivateFrameworks();

            [UIScreen initialize];
            CFRunLoopGetCurrent();

            GSInitialize();
            BKSDisplayServicesStart();
            UIApplicationInitialize();

            UIApplicationInstantiateSingleton(objc_getClass("AetherHUDMainApplication"));
            static id<UIApplicationDelegate> appDelegate =
                [[objc_getClass("AetherHUDApplicationDelegate") alloc] init];
            [UIApplication.sharedApplication setDelegate:appDelegate];
            [UIApplication.sharedApplication _accessibilityInit];

            [NSRunLoop currentRunLoop];
            AetherResolveRawDigitizer();
            BKSHIDEventRegisterEventCallback(AetherHUDMainEventCallback);

            if (@available(iOS 15.0, *)) {
                GSEventInitialize(0);
                GSEventPushRunLoopMode(kCFRunLoopDefaultMode);
            }

            [UIApplication.sharedApplication __completeAndRunAsPlugin];

            // Liveness heartbeat + graceful-exit command channel (shm).
            // Fixes "cannot remove HUD" where the pid file is unreliable across
            // uid 501 <-> root boundaries (roothide path shadowing).
            __block dispatch_source_t hbTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
            dispatch_source_set_timer(hbTimer, DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC, 0.5 * NSEC_PER_SEC);
            dispatch_source_set_event_handler(hbTimer, ^{
                AetherSharedState *st = AetherGetSharedState();
                if (!st) return;
                aether_atomic_store(&st->hudHeartbeatTs, (uint64_t)time(NULL));
                aether_atomic_store(&st->daemonBuild, AETHER_BUILD_NUM);
                if (aether_atomic_load(&st->hudCommand) == 1) {
                    unlink(AETHER_HUD_PID_PATH);
                    AetherLogDaemonSync(@"[pid %d] HUD daemon exiting (remove command)", getpid());
                    exit(0);
                }
            });
            dispatch_resume(hbTimer);
            objc_setAssociatedObject(appDelegate, "hbTimer", hbTimer, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

            // Respring recovery: when SpringBoard relaunches, the overlay context is
            // invalidated — kill this instance; the main app watchdog respawns it.
            static int _springboardBootToken;
            notify_register_dispatch("SBSpringBoardDidLaunchNotification",
                                     &_springboardBootToken,
                                     dispatch_get_main_queue(),
                                     ^(int token) {
                notify_cancel(token);
                AetherLogDaemonSync(@"[pid %d] HUD daemon exiting (SpringBoard relaunched)", pid);
                kill(pid, SIGKILL);
            });

            CFRunLoopRun();
            return EXIT_SUCCESS;
        }
        else if (strcmp(argv[1], "-exit") == 0) {
            NSString *pidString = [NSString stringWithContentsOfFile:@AETHER_HUD_PID_PATH
                                                            encoding:NSUTF8StringEncoding
                                                               error:nil];
            if (pidString) {
                pid_t hudPID = (pid_t)[pidString intValue];
                kill(hudPID, SIGKILL);
                unlink(AETHER_HUD_PID_PATH);
            }
            return EXIT_SUCCESS;
        }
        else if (strcmp(argv[1], "-check") == 0) {
            NSString *pidString = [NSString stringWithContentsOfFile:@AETHER_HUD_PID_PATH
                                                            encoding:NSUTF8StringEncoding
                                                               error:nil];
            if (pidString) {
                pid_t hudPID = (pid_t)[pidString intValue];
                int alive = kill(hudPID, 0);
                // kill() from uid 501 to a ROOT process returns EPERM even for signal 0 —
                // EPERM means the process EXISTS (and is more privileged). (bug fix 2.5.0)
                if (alive == 0 || errno == EPERM) return EXIT_FAILURE; // running
                return EXIT_SUCCESS;                                   // not running
            }
            return EXIT_SUCCESS;
        }
    }
    return -1;
}
