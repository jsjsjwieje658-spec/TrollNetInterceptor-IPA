//
//  PrivateSystemSPI.h
//  AetherNet — Apple Private Frameworks & XNU Kernel SPI Declarations
//
//  Cross-build note (Linux clang + iPhoneOS16.5 SDK):
//    Public iOS SDKs ship neither libproc.h nor sys/proc_info.h, so the
//    per-PID socket inspection structures are declared here verbatim to the
//    XNU layouts — the actual implementations (proc_listpids/proc_pidinfo/
//    proc_pidfdinfo/proc_pidpath) live in libSystem.dylib and resolve at
//    runtime via -Wl,-undefined,dynamic_lookup.
//

#ifndef PrivateSystemSPI_h
#define PrivateSystemSPI_h

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <mach/mach.h>
#include <sys/socket.h>
#include <sys/proc.h>      // MAXCOMLEN
#include <sys/types.h>
#include <spawn.h>         // posix_spawnattr_t (persona SPI)
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 1. POSIX Spawn Persona SPI (Root Privilege Escalation via TrollStore)
// ============================================================================
#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
int posix_spawnattr_set_persona_np(const posix_spawnattr_t * __restrict, uid_t, uint32_t);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t * __restrict, uid_t);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t * __restrict, uid_t);

// ============================================================================
// 2. XNU libproc SPI (Per-PID Socket & File Descriptor Inspection)
// ============================================================================
#ifndef PROC_PIDLISTFDS
#define PROC_PIDLISTFDS 1
#endif
#ifndef PROC_PIDFDSOCKETINFO
#define PROC_PIDFDSOCKETINFO 3
#endif
#ifndef PROX_FDTYPE_SOCKET
#define PROX_FDTYPE_SOCKET 2
#endif

// The XNU proc_info structures live in their own header now: they are plain C
// (so tests/host can static-assert the offsets on the build host) and they are
// transcribed verbatim from XNU bsd/sys/proc_info.h (xnu-8792 = iOS 16.x).
// 4.0.0 declared them inline here and dropped `struct socket_info.soi_stat`,
// which shifted every field: proc_pidfdinfo() then returned a size the caller
// did not recognise and every socket was skipped, so the kernel tap always
// reported "target has no INET TCP/UDP socket yet".
#include "AetherProcInfoLayout.h"

int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int buffersize);
int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

// ============================================================================
// 3. Mach VM & Remote Task SPI (task_for_pid / Remote Dylib Injection)
//    (manual ABI-faithful declarations — trimmed SDKs omit the prototypes;
//     implementations live in libsystem_kernel.dylib)
// ============================================================================
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);

// <mach/mach_vm.h> is deliberately marked unsupported in the iOS SDK, so the
// two calls we need for the shared-state handoff are declared here.  The
// prototypes match XNU exactly; on arm64 all the typedefs involved are
// pointer- or uint64_t-sized, so the ABI is identical.
kern_return_t mach_vm_map(vm_map_t target_task,
                          mach_vm_address_t *address,
                          mach_vm_size_t size,
                          mach_vm_address_t mask,
                          int flags,
                          mach_port_t memory_entry,
                          uint64_t offset,
                          boolean_t copy,
                          vm_prot_t cur_protection,
                          vm_prot_t max_protection,
                          vm_inherit_t inheritance);

// mach_make_memory_entry_64() IS declared by the iOS SDK (<mach/vm_map.h>):
//     kern_return_t mach_make_memory_entry_64(vm_map_t target_task,
//         memory_object_size_t *size, memory_object_offset_t offset,
//         vm_prot_t permission, mach_port_t *object_handle,
//         mem_entry_name_port_t parent_entry);
// — note the last parameter is a port, not a pointer to one.

// ============================================================================
// 4. SpringBoard / BackBoard / GraphicsServices HUD Window Hosting SPI
// ============================================================================
typedef struct __IOHIDEvent *IOHIDEventRef;
typedef struct __IOHIDService *IOHIDServiceRef;
typedef void (*BKSHIDEventCallback)(void *target, void *refcon, IOHIDServiceRef service, IOHIDEventRef event);

void GSInitialize(void);
void GSEventInitialize(Boolean registerPurpleWorkspacePort);
void GSEventPushRunLoopMode(CFStringRef mode);
void BKSDisplayServicesStart(void);
void UIApplicationInitialize(void);
void UIApplicationInstantiateSingleton(Class singletonClass);
void BKSHIDEventRegisterEventCallback(BKSHIDEventCallback callback);

#ifdef __cplusplus
}
#endif

// ============================================================================
// 5. Private Objective-C Interfaces (SpringBoardServices, UIWindow, LSWorkspace)
// ============================================================================
@interface UIWindow (AetherPrivate)
- (unsigned int)_contextId;
+ (BOOL)_isSystemWindow;
- (BOOL)_isWindowServerHostingManaged;
- (BOOL)_ignoresHitTest;
- (BOOL)_isSecure;
- (BOOL)_shouldCreateContextAsSecure;
@end

@interface UIApplication (AetherPrivate)
- (void)_accessibilityInit;
- (void)__completeAndRunAsPlugin;
- (void)_enqueueHIDEvent:(IOHIDEventRef)event;
@end

@interface SBSAccessibilityWindowHostingController : NSObject
- (void)registerWindowWithContextID:(unsigned int)contextID atLevel:(double)level;
- (void)unregisterWindowWithContextID:(unsigned int)contextID;
@end

@interface LSApplicationProxy : NSObject
@property (nonatomic, readonly) NSString *applicationIdentifier;
@property (nonatomic, readonly) NSString *localizedName;
@property (nonatomic, readonly) NSURL *bundleURL;
@property (nonatomic, readonly) NSURL *containerURL;
@property (nonatomic, readonly) NSString *applicationType;
@end

@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (NSArray<LSApplicationProxy *> *)allInstalledApplications;
- (BOOL)openApplicationWithBundleID:(NSString *)bundleID;
@end

@interface UIImage (AetherApplicationIconPrivate)
+ (instancetype)_applicationIconImageForBundleIdentifier:(NSString *)bundleIdentifier format:(int)format scale:(CGFloat)scale;
@end

#endif /* PrivateSystemSPI_h */
