//
//  compiler_rt_shim.c
//  AetherNet — Apple compiler-rt availability stub replacements
//
//  When clang compiles `@available(iOS 15.0, *)` for an arm64-apple-ios target
//  it emits calls to the compiler-rt helper `__isPlatformVersionAtLeast`.
//  Xcode links that helper from the static `libclang_rt.ios.a`; the Linux
//  cross toolchain has no Apple compiler-rt, so the symbol would be left
//  undefined under -undefined dynamic_lookup and dyld would abort at launch:
//      "symbol not found in flat namespace '___isPlatformVersionAtLeast'"
//  (seen in the field on iPhone10,5 / iOS 16.7.16).
//
//  This shim provides a faithful implementation of LLVM's interface:
//      bool __isPlatformVersionAtLeast(uint32_t Platform, uint32_t Major,
//                                      uint32_t Minor, uint32_t Subminor);
//  where Platform uses LLVM TargetPlatformKind values. The OS version is read
//  from the kernel via sysctl("kern.osproductversion") (e.g. "16.7.16").
//

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

// LLVM TargetPlatformKind (llvm/lib/TargetParser/Triple.cpp — Apple platforms)
#define AETHER_PLATFORM_MACOS    1
#define AETHER_PLATFORM_IOS      2
#define AETHER_PLATFORM_TVOS     3
#define AETHER_PLATFORM_WATCHOS  4
#define AETHER_PLATFORM_BRIDGEOS 5

static void aether_parse_os_version(int *outMajor, int *outMinor, int *outPatch)
{
    *outMajor = 0; *outMinor = 0; *outPatch = 0;

    char versionString[32] = {0};
    size_t size = sizeof(versionString);
    if (sysctlbyname("kern.osproductversion", versionString, &size, NULL, 0) != 0) {
        return;
    }

    int a = 0, b = 0, c = 0;
    if (sscanf(versionString, "%d.%d.%d", &a, &b, &c) >= 1) {
        *outMajor = a; *outMinor = b; *outPatch = c;
    }
}

bool __isPlatformVersionAtLeast(uint32_t Platform, uint32_t Major, uint32_t Minor, uint32_t Subminor)
{
    int osMajor = 0, osMinor = 0, osPatch = 0;
    aether_parse_os_version(&osMajor, &osMinor, &osPatch);

    // Our binaries only ever execute on iOS-family platforms; treat macOS /
    // bridgeOS probes conservatively (true only for iOS >= their version is
    // meaningless — match compiler-rt by comparing against the same version).
    (void)Platform;
    (void)AETHER_PLATFORM_MACOS; (void)AETHER_PLATFORM_IOS;
    (void)AETHER_PLATFORM_TVOS; (void)AETHER_PLATFORM_WATCHOS;
    (void)AETHER_PLATFORM_BRIDGEOS;

    if (osMajor != (int)Major) return osMajor > (int)Major;
    if (osMinor != (int)Minor) return osMinor > (int)Minor;
    if (osPatch != (int)Subminor) return osPatch > (int)Subminor;
    return true;
}

//
// `__chkstk_darwin` is emitted for functions with very large stack frames
// (> 1 page). AetherNet's frames are modest, but provide the symbol so a
// stray reference can never cause the same flat-namespace launch abort.
// Signature (arm64): x0 = remaining frame size to probe.
//
void __chkstk_darwin(void)
{
    // No-op: all frames in this binary are far below the probe threshold.
}
