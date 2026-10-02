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
#import <objc/runtime.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
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

#pragma mark - Hook payload installer (roothide TweakInject)

// Installs libNetHookPayload.dylib as a roothide tweak so ellekit injects it
// into every UIKit process at launch; the payload self-gates to the attached
// target (pid or bundle-id match). This replaces remote dlopen (blocked by
// PPL/PAC) as the real L4 capture delivery path.
// Try to copy src->dst with the current process. Returns 0 on success.
static int AetherTryCopy(NSString *src, NSString *dst)
{
    NSData *data = [NSData dataWithContentsOfFile:src];
    if (!data) return -1;
    unlink(dst.fileSystemRepresentation); // clear immutable/leftover first
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
    return (remaining == 0) ? 0 : -3;
}

// Copy by EXECUTING a helper binary that lives INSIDE the jbroot. roothide
// trusts jbroot-resident executables, so its TweakInject write-protection
// (which gives uid-0 processes EPERM) can be bypassed by cp/mv/dd/install.
static int AetherCopyViaJbrootHelper(NSString *jbroot, NSString *src, NSString *dst)
{
    NSArray *candidates = @[@"cp", @"mv", @"install", @"dd"];
    NSString *found = nil;
    for (NSString *name in candidates) {
        NSString *p = [jbroot stringByAppendingPathComponent:
                       [@"usr/bin/" stringByAppendingString:name]];
        if ([[NSFileManager defaultManager] isExecutableFileAtPath:p]) { found = p; break; }
    }
    if (!found) return -1;

    pid_t pid = fork();
    if (pid < 0) return -2;
    if (pid == 0) {
        // child — jbroot-resident helper, inherits root
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); }
        if ([found hasSuffix:@"dd"]) {
            execl(found.fileSystemRepresentation, found.fileSystemRepresentation,
                  [NSString stringWithFormat:@"if=%@", src].UTF8String,
                  [NSString stringWithFormat:@"of=%@", dst].UTF8String, (char *)NULL);
        } else {
            execl(found.fileSystemRepresentation, found.fileSystemRepresentation,
                  src.fileSystemRepresentation, dst.fileSystemRepresentation, (char *)NULL);
        }
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return -3;
    return 0;
}

// fork+exec a helper binary that lives INSIDE the jbroot (trusted context)
static int AetherExecJbrootBinary2(NSString *jbroot, NSString *relPath, NSString *arg1, NSString *arg2)
{
    NSString *tool = [jbroot stringByAppendingPathComponent:relPath];
    if ([[NSFileManager defaultManager] isExecutableFileAtPath:tool] == NO) return -100;
    pid_t pid = fork();
    if (pid < 0) return -101;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); }
        execl(tool.fileSystemRepresentation, tool.fileSystemRepresentation,
              arg1.fileSystemRepresentation, arg2.fileSystemRepresentation, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status)) return -102;
    return WEXITSTATUS(status);
}

static int AetherExecJbrootBinary(NSString *jbroot, NSString *relPath, NSString *arg1)
{
    NSString *tool = [jbroot stringByAppendingPathComponent:relPath];
    if ([[NSFileManager defaultManager] isExecutableFileAtPath:tool] == NO) return -100;
    pid_t pid = fork();
    if (pid < 0) return -101;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); }
        execl(tool.fileSystemRepresentation, tool.fileSystemRepresentation,
              arg1.fileSystemRepresentation, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status)) return -102;
    return WEXITSTATUS(status);
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
        unsigned long long srcSize = [[fm attributesOfItemAtPath:srcDylib error:nil] fileSize];

        // ── Discover the roothide jbroot (hidden .jbroot-<hash> dir) ──
        DIR *d = opendir("/private/var/containers/Bundle/Application");
        if (!d) {
            AetherLog(@"[installer] cannot open Bundle/Application (errno=%d)", errno);
            return;
        }
        NSString *jbroot = nil;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strncmp(ent->d_name, ".jbroot-", 8) == 0) {
                jbroot = [NSString stringWithFormat:@"/private/var/containers/Bundle/Application/%s",
                          ent->d_name];
                break;
            }
        }
        closedir(d);
        if (!jbroot) {
            AetherLog(@"[installer] no .jbroot-* dir found (not roothide?)");
            return;
        }

        // ── AMFI fix (roothide-style, learned from its source): re-sign the
        // payload with jbroot/basebin/fastPathSign (coretrust bug) so STOCK
        // AMFI accepts it inside any process — no trustcache needed. Our
        // ldid-adhoc signature would be rejected by normal apps. ──
        NSString *workCopy = @"/var/mobile/Library/AetherNetHook.signed.dylib";
        [fm removeItemAtPath:workCopy error:nil];
        BOOL copied = [fm copyItemAtPath:srcDylib toPath:workCopy error:nil];
        if (!copied) {
            NSData *raw = [NSData dataWithContentsOfFile:srcDylib];
            copied = [raw writeToFile:workCopy atomically:YES];
        }
        if (!copied) {
            AetherLog(@"[installer] cannot create working copy at %@", workCopy);
            return;
        }
        // Discovery: log what basebin actually contains (3.5.0 guessed the
        // path and got rc=-100). Probe several candidates, then sign.
        {
            DIR *bd = opendir([jbroot stringByAppendingPathComponent:@"basebin"].fileSystemRepresentation);
            if (bd) {
                NSMutableString *listing = [NSMutableString string];
                struct dirent *bent;
                int shown = 0;
                while ((bent = readdir(bd)) != NULL && shown < 15) {
                    [listing appendFormat:@"%s ", bent->d_name]; shown++;
                }
                closedir(bd);
                AetherLog(@"[installer] jbroot/basebin contents: %@", listing);
            } else {
                AetherLog(@"[installer] jbroot/basebin not listable (errno=%d)", errno);
            }
        }
        int signRc = -100;
        for (NSString *cand in @[@"basebin/fastPathSign", @"usr/bin/fastPathSign",
                                 @"basebin/ldid", @"usr/bin/ldid"]) {
            NSString *full = [jbroot stringByAppendingPathComponent:cand];
            if ([fm isExecutableFileAtPath:full]) {
                if ([cand hasSuffix:@"ldid"]) {
                    // ldid needs -S + path → use the generic exec helper with args
                    signRc = AetherExecJbrootBinary2(jbroot, cand, @"-S", workCopy);
                } else {
                    signRc = AetherExecJbrootBinary(jbroot, cand, workCopy);
                }
                AetherLog(@"[installer] signer %@ rc=%d", cand, signRc);
                if (signRc == 0) break;
            }
        }
        unsigned long long signedSize = [[fm attributesOfItemAtPath:workCopy error:nil] fileSize];
        if (signRc == 0 && signedSize > 0) {
            chmod(workCopy.fileSystemRepresentation, 0755);
            // Publish for the app's live-attach path
            [fm removeItemAtPath:@"/var/mobile/Library/Caches/libNetHookPayload.dylib" error:nil];
            [fm copyItemAtPath:workCopy
                        toPath:@"/var/mobile/Library/Caches/libNetHookPayload.dylib" error:nil];
            chmod("/var/mobile/Library/Caches/libNetHookPayload.dylib", 0755);
            AetherLog(@"[installer] fastPathSign OK (%llu -> %llu bytes, coretrust signature published)",
                      srcSize, signedSize);
        } else {
            AetherLog(@"[installer] fastPathSign rc=%d size=%llu — continuing with adhoc signature "
                      @"(may be rejected by App Store targets)", signRc, signedSize);
        }
        NSString *payloadDylib = workCopy; // install the (re)signed copy
        unsigned long long payloadSize = signedSize ?: srcSize;

        // ── Tweak-loader gate: bootstrap.c only loads tweaks when this
        // marker exists — create it if a previous tweak install removed it. ──
        if ([fm fileExistsAtPath:@"/var/mobile/.tweakenabled"] == NO) {
            [@"" writeToFile:@"/var/mobile/.tweakenabled" atomically:YES encoding:NSUTF8StringEncoding error:nil];
            AetherLog(@"[installer] created /var/mobile/.tweakenabled (tweak gate marker)");
        }

        NSString *plist =
            @"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            @"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            @"<plist version=\"1.0\">\n"
            @"<dict>\n"
            @"  <key>Filter</key>\n"
            @"  <dict>\n"
            @"    <key>Bundles</key>\n"
            @"    <array>\n"
            @"      <string>com.apple.UIKit</string>\n"
            @"    </array>\n"
            @"  </dict>\n"
            @"</dict>\n"
            @"</plist>\n";
        NSString *tmpPlist = @"/var/mobile/Library/aethernet-filter.plist";
        [plist writeToFile:tmpPlist atomically:YES encoding:NSUTF8StringEncoding error:nil];

        // ── Candidate tweak dirs: direct jbroot + /var/jb alias ──
        NSMutableArray *tweakDirs = [NSMutableArray array];
        [tweakDirs addObject:[jbroot stringByAppendingPathComponent:@"usr/lib/TweakInject"]];
        struct stat sb;
        if (lstat("/var/jb", &sb) == 0 && S_ISLNK(sb.st_mode)) {
            [tweakDirs addObject:@"/var/jb/usr/lib/TweakInject"];
        }

        for (NSString *tweakDir in tweakDirs) {
            BOOL isDir = NO;
            if (![fm fileExistsAtPath:tweakDir isDirectory:&isDir] || !isDir) {
                AetherLog(@"[installer] TweakInject missing at %@", tweakDir);
                continue;
            }
            NSString *dstDylib = [tweakDir stringByAppendingPathComponent:@"AetherNetHook.dylib"];
            NSString *dstPlist = [tweakDir stringByAppendingPathComponent:@"AetherNetHook.plist"];

            // Attempt 1: direct write (works only for jbroot-resident writers)
            int rc = AetherTryCopy(payloadDylib, dstDylib);
            if (rc == 0) rc = AetherTryCopy(tmpPlist, dstPlist);
            if (rc == 0) {
                chmod(dstDylib.fileSystemRepresentation, 0755);
                chmod(dstPlist.fileSystemRepresentation, 0644);
                AetherLog(@"[installer] payload INSTALLED (direct write) -> %@ — respring the device", dstDylib);
                return;
            }
            AetherLog(@"[installer] direct write failed rc=%d errno=%d — trying jbroot helper", rc, errno);

            // Attempt 2: exec jbroot-resident cp/mv/install/dd (trusted writers)
            NSArray *helpers = @[@"cp", @"mv", @"install", @"dd"];
            NSString *helper = nil;
            for (NSString *h in helpers) {
                NSString *p = [jbroot stringByAppendingPathComponent:
                               [@"usr/bin/" stringByAppendingString:h]];
                if ([fm isExecutableFileAtPath:p]) { helper = p; break; }
            }
            if (helper) {
                AetherLog(@"[installer] using jbroot helper %@", helper.lastPathComponent);
                if (AetherCopyViaJbrootHelper(jbroot, payloadDylib, dstDylib) == 0 &&
                    AetherCopyViaJbrootHelper(jbroot, tmpPlist, dstPlist) == 0) {
                    NSDictionary *a1 = [fm attributesOfItemAtPath:dstDylib error:nil];
                    if ([a1 fileSize] == payloadSize) {
                        chmod(dstDylib.fileSystemRepresentation, 0755);
                        chmod(dstPlist.fileSystemRepresentation, 0644);
                        AetherLog(@"[installer] payload INSTALLED (jbroot helper) -> %@ — respring the device", dstDylib);
                        return;
                    }
                }
            } else {
                AetherLog(@"[installer] no cp/mv/install/dd inside jbroot");
            }
            AetherLog(@"[installer] jbroot-helper copy failed (errno=%d)", errno);
        }

        // ── All automatic strategies failed → export the SIGNED payload ──
        NSString *exportDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                               stringByAppendingPathComponent:@"AetherNetHook-install"];
        [fm createDirectoryAtPath:exportDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *expDylib = [exportDir stringByAppendingPathComponent:@"AetherNetHook.dylib"];
        NSString *expPlist = [exportDir stringByAppendingPathComponent:@"AetherNetHook.plist"];
        [fm removeItemAtPath:expDylib error:nil];
        BOOL ok = [fm copyItemAtPath:payloadDylib toPath:expDylib error:nil];
        [plist writeToFile:expPlist atomically:YES encoding:NSUTF8StringEncoding error:nil];
        AetherLog(@"[installer] AUTO INSTALL BLOCKED (roothide jbroot write protection) — exported SIGNED payload to Documents/AetherNetHook-install/ ok=%d", ok);
        AetherLog(@"[installer] MANUAL (Filza): copy BOTH files into %@ then RESPRING", [tweakDirs firstObject]);
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

#pragma mark - HUD lifecycle

int HUDMain(int argc, char *argv[])
{
    @autoreleasepool {
        if (argc <= 1) {
            return -1; // Not a HUD invocation — fall through to normal app main
        }

        if (strcmp(argv[1], "-hud") == 0) {
            pid_t pid = getpid();

            // Single-instance guard: two daemons mean two overlapping buttons
            // and duplicated HID callbacks. The second instance must exit.
            {
                NSString *oldPidStr = [NSString stringWithContentsOfFile:@AETHER_HUD_PID_PATH
                                                                encoding:NSUTF8StringEncoding
                                                                   error:nil];
                pid_t oldPid = (pid_t)oldPidStr.intValue;
                BOOL otherAlive = NO;
                if (oldPid > 0 && oldPid != pid) {
                    if (kill(oldPid, 0) == 0 || errno == EPERM) otherAlive = YES;
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
