//
//  NECPCapture.mm
//  AetherNet — Tier 0: NECP (Network Extension Control Plane) Kernel Packet Filter
//
//  NECP functions are NOT in the flat namespace on iOS — they live in Network.framework
//  Must resolve via dlsym at runtime from the Network framework.

#import "NECPCapture.h"
#import "AetherLog.h"
#import "../headers/AetherNetShared.h"
#import "../headers/PrivateSystemSPI.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <dlfcn.h>
#include <stdatomic.h>

// NECP function pointers (resolved at runtime)
static int (*g_necp_open)(int) = NULL;
static int (*g_necp_close)(int) = NULL;
static int (*g_necp_client_action)(int, uint32_t, void *, size_t) = NULL;
static int (*g_necp_match_policy)(int, uint32_t *, void *, size_t) = NULL;

static void *g_networkFrameworkHandle = NULL;

// NECP action codes
#define NECP_CLIENT_ACTION_REGISTER   1
#define NECP_CLIENT_ACTION_UNREGISTER 2

// NECP policy parameter structures (matching XNU necp.h)
struct necp_client_parameters {
    uint32_t flags;
    uint32_t reserved;
};

struct necp_fd_data {
    int fd;
    uint32_t flags;
    uint32_t reserved;
};

struct necp_kernel_policy_id {
    uuid_t uuid;
};

struct necp_policy_parameter {
    uint32_t length;
    uint32_t type;
    uint8_t data[];
};

#define NECP_POLICY_PARAMETER_TYPE_UUID           1
#define NECP_POLICY_PARAMETER_TYPE_PROCESS_UUID   2
#define NECP_POLICY_PARAMETER_TYPE_LOCAL_ADDRESS  3
#define NECP_POLICY_PARAMETER_TYPE_REMOTE_ADDRESS 4
#define NECP_POLICY_PARAMETER_TYPE_LOCAL_PORT     5
#define NECP_POLICY_PARAMETER_TYPE_REMOTE_PORT    6
#define NECP_POLICY_PARAMETER_TYPE_PROTOCOL       7
#define NECP_POLICY_PARAMETER_TYPE_ACTION         8

#define NECP_KERNEL_POLICY_ACTION_ALLOW    1
#define NECP_KERNEL_POLICY_ACTION_DROP     2
#define NECP_KERNEL_POLICY_ACTION_DIVERT   3  // Copy packet to userspace socket

// libproc constants (not in iOS SDK headers)
#define PROC_PIDTBSDINFO  3

// Divert socket for receiving packet copies
static int gNECPDivertSocket = -1;
static int gNECPClientId = -1;
static uint32_t gNECPPolicyId = 0;
static pthread_t gNECPThread = 0;
static BOOL gNECPThreadRunning = NO;
static pid_t gNECPTargetPID = 0;

// Resolve NECP symbols from Network.framework at runtime
static BOOL AetherNECPResolveSymbols(void) {
    if (g_networkFrameworkHandle) return YES;
    
    // Try multiple possible locations
    const char *paths[] = {
        "/System/Library/Frameworks/Network.framework/Network",
        "/usr/lib/libnetwork.dylib",
        "/System/Library/PrivateFrameworks/NetworkExtension.framework/NetworkExtension",
        NULL
    };
    
    for (int i = 0; paths[i]; i++) {
        void *handle = dlopen(paths[i], RTLD_LAZY | RTLD_LOCAL);
        if (handle) {
            g_necp_open = dlsym(handle, "necp_open");
            g_necp_close = dlsym(handle, "necp_close");
            g_necp_client_action = dlsym(handle, "necp_client_action");
            g_necp_match_policy = dlsym(handle, "necp_match_policy");
            
            if (g_necp_open && g_necp_close && g_necp_client_action && g_necp_match_policy) {
                g_networkFrameworkHandle = handle;
                AetherLogDaemon(@"[necp] Resolved symbols from %s", paths[i]);
                return YES;
            }
            dlclose(handle);
        }
    }
    
    AetherLogDaemon(@"[necp] Failed to resolve NECP symbols from any framework");
    return NO;
}

static void *AetherNECPWorkerThread(void *arg) {
    AetherLogDaemon(@"[necp] worker thread started");
    
    char buffer[65536];
    struct sockaddr_storage srcAddr;
    socklen_t srcAddrLen = sizeof(srcAddr);
    
    while (gNECPThreadRunning) {
        ssize_t len = recvfrom(gNECPDivertSocket, buffer, sizeof(buffer), MSG_DONTWAIT,
                               (struct sockaddr *)&srcAddr, &srcAddrLen);
        if (len <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);  // 1ms
                continue;
            }
            break;
        }
        
        // Parse IP header
        if (len < sizeof(struct ip)) continue;
        struct ip *iph = (struct ip *)buffer;
        if (iph->ip_v != 4) continue;  // IPv4 only for now
        
        size_t ipHeaderLen = iph->ip_hl * 4;
        if (len < ipHeaderLen) continue;
        
        // Determine protocol
        uint8_t proto = iph->ip_p;
        const char *protoStr = (proto == IPPROTO_TCP) ? "TCP" : (proto == IPPROTO_UDP) ? "UDP" : "OTHER";
        
        // Parse ports for TCP/UDP
        uint16_t srcPort = 0, dstPort = 0;
        if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && len >= ipHeaderLen + 4) {
            uint16_t *ports = (uint16_t *)(buffer + ipHeaderLen);
            srcPort = ntohs(ports[0]);
            dstPort = ntohs(ports[1]);
        }
        
        // Source/dest IP
        char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->ip_src, srcIP, sizeof(srcIP));
        inet_ntop(AF_INET, &iph->ip_dst, dstIP, sizeof(dstIP));
        
        // Log to daemon log (will merge to app Log tab)
        AetherLogDaemon(@"[necp] CAPTURE %s %s:%u -> %s:%u len=%zd",
                        protoStr, srcIP, srcPort, dstIP, dstPort, len);
        
        // Update shared memory counters
        AetherSharedState *state = AetherGetSharedState();
        if (state) {
            if (proto == IPPROTO_TCP) {
                uint64_t v = aether_atomic_load(&state->totalTCPPacketsRX);
                aether_atomic_store(&state->totalTCPPacketsRX, v + 1);
            } else if (proto == IPPROTO_UDP) {
                uint64_t v = aether_atomic_load(&state->totalUDPPacketsRX);
                aether_atomic_store(&state->totalUDPPacketsRX, v + 1);
            }
            uint64_t b = aether_atomic_load(&state->totalBytesRX);
            aether_atomic_store(&state->totalBytesRX, b + len);
        }
    }
    
    AetherLogDaemon(@"[necp] worker thread exiting");
    return NULL;
}

// Get process UUID for NECP matching (via proc_pidinfo)
static BOOL AetherNECPGetProcessUUID(pid_t pid, uuid_t outUUID) {
    // On iOS, process UUID is in proc_bsdinfo.pbi_uuid
    struct proc_bsdinfo {
        uint32_t pbi_flags;
        uint32_t pbi_status;
        uint32_t pbi_xstatus;
        uint32_t pbi_pid;
        uint32_t pbi_ppid;
        uid_t    pbi_uid;
        gid_t    pbi_gid;
        uint32_t pbi_ruid;
        uint32_t pbi_rgid;
        uint32_t pbi_svuid;
        uint32_t pbi_svgid;
        uint32_t rfu_1;
        char     pbi_comm[16];
        char     pbi_name[16];
        uint32_t pbi_nfiles;
        uint32_t pbi_nfilesmax;
        uint32_t pbi_nexecs;
        uint32_t pbi_pgid;
        int32_t  pbi_pjobc;
        uint32_t pbi_tdev;
        uint32_t pbi_tpgid;
        uint32_t pbi_nice;
        uint64_t pbi_start_tvsec;
        uint64_t pbi_start_tvusec;
        uint64_t pbi_cputime;
        uint64_t pbi_utime;
        uint64_t pbi_stime;
        uint64_t pbi_maxrss;
        uint64_t pbi_ixrss;
        uint64_t pbi_idrss;
        uint64_t pbi_isrss;
        uuid_t   pbi_uuid;
    };
    
    struct proc_bsdinfo bsdInfo;
    int rc = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdInfo, sizeof(bsdInfo));
    if (rc == sizeof(bsdInfo)) {
        memcpy(outUUID, bsdInfo.pbi_uuid, sizeof(uuid_t));
        return YES;
    }
    // Fallback: generate from PID (not ideal but works for matching)
    memset(outUUID, 0, sizeof(uuid_t));
    snprintf((char *)outUUID, 16, "AETHER-%05d", pid);
    return NO;
}

extern "C" int AetherNECPStartCapture(pid_t pid, char *errBuf, size_t errBufLen) {
    if (pid <= 0) {
        snprintf(errBuf, errBufLen, "invalid pid");
        return -1;
    }
    
    if (AetherNECPIsRunning()) {
        snprintf(errBuf, errBufLen, "NECP already running");
        return -2;
    }
    
    // Resolve NECP symbols at runtime
    if (!AetherNECPResolveSymbols()) {
        snprintf(errBuf, errBufLen, "NECP symbols not available on this iOS version");
        AetherLogDaemon(@"[necp] NECP symbols not available");
        return -3;
    }
    
    AetherLogDaemon(@"[necp] starting capture for pid %d", pid);
    
    // 1. Open NECP client
    gNECPClientId = g_necp_open(0);
    if (gNECPClientId < 0) {
        snprintf(errBuf, errBufLen, "necp_open failed: %d", errno);
        AetherLogDaemon(@"[necp] necp_open failed: %d", errno);
        return -4;
    }
    
    // 2. Create UDP socket for diverted packets
    gNECPDivertSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (gNECPDivertSocket < 0) {
        snprintf(errBuf, errBufLen, "divert socket failed: %d", errno);
        g_necp_close(gNECPClientId);
        gNECPClientId = -1;
        return -5;
    }
    
    // Bind to localhost ephemeral port
    struct sockaddr_in divertAddr = {0};
    divertAddr.sin_family = AF_INET;
    divertAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    divertAddr.sin_port = 0;
    if (bind(gNECPDivertSocket, (struct sockaddr *)&divertAddr, sizeof(divertAddr)) < 0) {
        snprintf(errBuf, errBufLen, "divert bind failed: %d", errno);
        close(gNECPDivertSocket);
        gNECPDivertSocket = -1;
        g_necp_close(gNECPClientId);
        gNECPClientId = -1;
        return -6;
    }
    
    // Get the bound port
    socklen_t addrLen = sizeof(divertAddr);
    getsockname(gNECPDivertSocket, (struct sockaddr *)&divertAddr, &addrLen);
    uint16_t divertPort = ntohs(divertAddr.sin_port);
    
    // 3. Register NECP client with divert socket
    struct necp_fd_data fdData = {0};
    fdData.fd = gNECPDivertSocket;
    fdData.flags = 0;
    
    if (g_necp_client_action(gNECPClientId, NECP_CLIENT_ACTION_REGISTER, &fdData, sizeof(fdData)) != 0) {
        snprintf(errBuf, errBufLen, "necp_client_action REGISTER failed: %d", errno);
        close(gNECPDivertSocket);
        gNECPDivertSocket = -1;
        g_necp_close(gNECPClientId);
        gNECPClientId = -1;
        return -7;
    }
    
    // 4. Build policy parameters matching target process UUID
    uuid_t procUUID;
    AetherNECPGetProcessUUID(pid, procUUID);
    
    // Allocate parameter buffer
    size_t paramSize = 1024;
    void *params = calloc(1, paramSize);
    if (!params) {
        snprintf(errBuf, errBufLen, "calloc failed");
        return -8;
    }
    
    // Build parameter chain: process UUID + divert action
    struct necp_policy_parameter *param = (struct necp_policy_parameter *)params;
    size_t offset = 0;
    
    // Process UUID parameter
    param = (struct necp_policy_parameter *)((char *)params + offset);
    param->type = NECP_POLICY_PARAMETER_TYPE_PROCESS_UUID;
    param->length = sizeof(param->length) + sizeof(param->type) + sizeof(uuid_t);
    memcpy(param->data, procUUID, sizeof(uuid_t));
    offset += param->length;
    
    // Action = DIVERT
    param = (struct necp_policy_parameter *)((char *)params + offset);
    param->type = NECP_POLICY_PARAMETER_TYPE_ACTION;
    param->length = sizeof(param->length) + sizeof(param->type) + sizeof(uint32_t);
    uint32_t action = NECP_KERNEL_POLICY_ACTION_DIVERT;
    memcpy(param->data, &action, sizeof(action));
    offset += param->length;
    
    // Total length
    ((struct necp_policy_parameter *)params)->length = offset;
    
    // 5. Match policy
    if (g_necp_match_policy(gNECPClientId, &gNECPPolicyId, params, offset) != 0) {
        snprintf(errBuf, errBufLen, "necp_match_policy failed: %d", errno);
        free(params);
        close(gNECPDivertSocket);
        gNECPDivertSocket = -1;
        g_necp_close(gNECPClientId);
        gNECPClientId = -1;
        return -9;
    }
    
    free(params);
    
    // 6. Start worker thread
    gNECPTargetPID = pid;
    gNECPThreadRunning = YES;
    if (pthread_create(&gNECPThread, NULL, AetherNECPWorkerThread, NULL) != 0) {
        snprintf(errBuf, errBufLen, "pthread_create failed: %d", errno);
        gNECPThreadRunning = NO;
        close(gNECPDivertSocket);
        gNECPDivertSocket = -1;
        g_necp_close(gNECPClientId);
        gNECPClientId = -1;
        return -10;
    }
    
    AetherLogDaemon(@"[necp] capture STARTED for pid %d (divert port %u, policy %u)", pid, divertPort, gNECPPolicyId);
    return 0;
}

extern "C" void AetherNECPStopCapture(void) {
    if (!AetherNECPIsRunning()) return;
    
    AetherLogDaemon(@"[necp] stopping capture");
    
    gNECPThreadRunning = NO;
    if (gNECPThread) {
        pthread_join(gNECPThread, NULL);
        gNECPThread = 0;
    }
    
    if (gNECPPolicyId != 0 && gNECPClientId >= 0 && g_necp_client_action) {
        // Unmatch policy (action = unregister)
        g_necp_client_action(gNECPClientId, NECP_CLIENT_ACTION_UNREGISTER, &gNECPPolicyId, sizeof(gNECPPolicyId));
        gNECPPolicyId = 0;
    }
    
    if (gNECPDivertSocket >= 0) {
        close(gNECPDivertSocket);
        gNECPDivertSocket = -1;
    }
    
    if (gNECPClientId >= 0 && g_necp_close) {
        g_necp_close(gNECPClientId);
        gNECPClientId = -1;
    }
    
    gNECPTargetPID = 0;
    AetherLogDaemon(@"[necp] capture STOPPED");
}

extern "C" BOOL AetherNECPIsRunning(void) {
    return gNECPThreadRunning && gNECPClientId >= 0 && gNECPDivertSocket >= 0;
}
