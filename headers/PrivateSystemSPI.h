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

struct proc_fdinfo {
    int32_t  proc_fd;
    uint32_t proc_fdtype;
};

struct in_sockinfo {
    int      insi_fport;
    int      insi_lport;
    uint64_t insi_gencnt;
    uint32_t insi_flags;
    uint32_t insi_flow;
    uint8_t  insi_vflag; // INI_IPV4 = 0x1, INI_IPV6 = 0x2
    uint8_t  insi_ip_ttl;
    uint32_t rfu_1;
    union {
        struct in_addr  ina_46;
        struct in6_addr ina_6;
    } insi_faddr;
    union {
        struct in_addr  ina_46;
        struct in6_addr ina_6;
    } insi_laddr;
};

struct tcp_sockinfo {
    struct in_sockinfo tcpsi_ini;
    int                tcpsi_state;
    int                tcpsi_timer[4];
    int                tcpsi_mss;
    uint32_t           tcpsi_flags;
    uint32_t           rfu_1;
    uint64_t           tcpsi_tp;
};

struct sockbuf_info {
    uint32_t sbi_cc;
    uint32_t sbi_hiwat;
    uint32_t sbi_mbcnt;
    uint32_t sbi_mbmax;
    uint32_t sbi_lowat;
    short    sbi_flags;
    short    sbi_timeo;
};

struct socket_info_layout {
    uint64_t soi_so;
    uint64_t soi_pcb;
    int      soi_type;     // SOCK_STREAM (1), SOCK_DGRAM (2)
    int      soi_protocol; // IPPROTO_TCP (6), IPPROTO_UDP (17)
    int      soi_family;   // AF_INET (2), AF_INET6 (30)
    short    soi_options;
    short    soi_linger;
    short    soi_state;
    short    soi_qlen;
    short    soi_incqlen;
    short    soi_qlimit;
    short    soi_timeo;
    u_short  soi_error;
    uint32_t soi_oobmark;
    struct sockbuf_info soi_rcv;
    struct sockbuf_info soi_snd;
    int      soi_kind;
    uint32_t rfu_1;
    union {
        struct in_sockinfo  pri_in;
        struct tcp_sockinfo pri_tcp;
    } soi_proto;
};

// Layout-compatible with XNU's struct socket_fdinfo; only the psi member is read.
struct aether_socket_fdinfo {
    uint32_t fi_openflags;
    uint32_t fi_status;
    off_t    fi_offset;
    int32_t  fi_type;
    uint32_t fi_guardflags;
    struct socket_info_layout psi;
};

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
