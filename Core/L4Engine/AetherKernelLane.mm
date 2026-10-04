//
//  AetherKernelLane.mm
//  AetherNet — P3 kernel tap lane (BPF) + per-PID socket inventory
//
//  ── Why BPF and not NECP ────────────────────────────────────────────────────
//  The previous revision shipped a "Tier 0 NECP capture".  It could never have
//  worked, for three reasons that are visible in XNU's sources:
//
//    1. NECP is a *policy* engine, not a tap.  It answers "what should happen
//       to this flow?" (allow / drop / socket-divert / scoped).  It never
//       hands packet copies to user space.
//    2. The prototypes were invented.  XNU declares
//           int necp_match_policy(uint8_t *parameters, size_t parameters_size,
//                                 struct necp_aggregate_result *result);   // #460
//           int necp_client_action(int fd, uint32_t action, uuid_t client_id,
//                                  size_t client_id_len, uint8_t *buffer,
//                                  size_t buffer_size);                    // #502
//       — neither matches what the old code called, and necp_match_policy is
//       not exported by any iOS dylib anyway.
//    3. Every privileged NECP action is gated on
//       com.apple.private.necp.[match|policies], which on iOS is restricted to
//       a handful of Apple daemons.  Arbitrary entitlements from TrollStore do
//       not unlock it.
//
//  BPF is the real, documented tap: /dev/bpfN + BIOCSETIF gives you a copy of
//  every frame that crosses an interface, in both directions, regardless of
//  whether the app used BSD sockets (P1) or libnetwork/Skywalk (P2) — because
//  both paths converge on the interface on their way out of the device.
//
//  ── What this file does ────────────────────────────────────────────────────
//   1. Inventory the target's sockets with proc_pidfdinfo(PROC_PIDFDSOCKETINFO)
//      and collect its local ports (the matching key for the tap).
//   2. Open /dev/bpfN, attach to the interfaces the device is actually using,
//      install a small BPF program (ip or ip6) and stream frames.
//   3. Parse each frame with AetherParseLinkFrame, attribute it to the target
//      with AetherClassifyDirection, and feed the shared-memory counters +
//      the flow table.
//

#import <Foundation/Foundation.h>

#import "AetherKernelLane.h"
#import "AetherShaper.h"
#import "AetherPacketCore.h"
#import "../../Core/AetherLog.h"
#import "../../headers/AetherNetShared.h"
#import "../../headers/PrivateSystemSPI.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ---------------------------------------------------------------------------
// BPF declarations.  <net/bpf.h> exists in some SDKs and is missing in others
// (and in the trimmed Linux cross-SDK), so we take it when present and fall
// back to the XNU layout verbatim otherwise.
// ---------------------------------------------------------------------------
#if __has_include(<net/bpf.h>)
#include <net/bpf.h>
typedef struct bpf_hdr aether_bpf_hdr_t;
#else
typedef struct {
    struct timeval bh_tstamp;
    uint32_t       bh_caplen;
    uint32_t       bh_datalen;
    uint16_t       bh_hdrlen;
} aether_bpf_hdr_t;
#define BPF_ALIGNMENT sizeof(uint32_t)
#define BPF_WORDALIGN(x) (((x) + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1))
struct bpf_version { uint16_t bv_major; uint16_t bv_minor; };
struct bpf_program { uint32_t bf_len; struct bpf_insn *bf_insns; };
struct bpf_insn { uint16_t code; uint8_t jt; uint8_t jf; uint32_t k; };
struct bpf_stat { uint32_t bs_recv; uint32_t bs_drop; uint32_t bs_capt;
                  uint32_t bs_padding[13]; };

#define BIOCGBLEN       _IOR('B', 102, uint32_t)
#define BIOCSBLEN       _IOWR('B', 102, uint32_t)
#define BIOCSETF        _IOW('B', 103, struct bpf_program)
#define BIOCFLUSH       _IO('B', 104)
#define BIOCPROMISC     _IO('B', 105)
#define BIOCGDLT        _IOR('B', 106, uint32_t)
#define BIOCGETIF       _IOWR('B', 107, struct ifreq)
#define BIOCSETIF       _IOW('B', 108, struct ifreq)
#define BIOCSRTIMEOUT   _IOW('B', 109, struct timeval)
#define BIOCGSTATS      _IOR('B', 111, struct bpf_stat)
#define BIOCIMMEDIATE   _IOW('B', 112, uint32_t)
#define BIOCVERSION     _IOR('B', 113, struct bpf_version)
// Request struct bpf_hdr_ext records: the kernel stamps every packet with the
// PID / process name / direction of the flow that owns it (xnu-8792.81.2
// bsd/net/bpf.h).  Without it the tap can only guess who owns a packet by
// matching the port inventory built from proc_pidfdinfo.
#define BIOCSEXTHDR     _IOW('B', 124, uint32_t)

#define BPF_STMT(code, k) { (uint16_t)(code), 0, 0, (uint32_t)(k) }
#define BPF_JUMP(code, k, jt, jf) { (uint16_t)(code), (uint8_t)(jt), (uint8_t)(jf), (uint32_t)(k) }

#define BPF_LD   0x00
#define BPF_LDX  0x01
#define BPF_ALU  0x04
#define BPF_JMP  0x05
#define BPF_RET  0x06
#define BPF_W    0x00
#define BPF_H    0x08
#define BPF_B    0x10
#define BPF_ABS  0x20
#define BPF_RSH  0x30
#define BPF_JEQ  0x10
#define BPF_K    0x00
#endif

#ifndef BPF_WORDALIGN
#define BPF_WORDALIGN(x) (((x) + 3) & ~((uintptr_t)3))
#endif

#define AETHER_BPF_MAX_IF     4
// 64 KB, not 256 KB: four devices at 256 KB is 1 MB of WIRED kernel memory
// charged to a small plugin process, and iOS reclaims that kind of thing by
// killing the process.  64 KB still holds ~40 full-size frames per read.
#define AETHER_BPF_BUFSIZE    (64u * 1024u)
#define AETHER_BPF_SNAPLEN    1600u

// ---------------------------------------------------------------------------
// Tap state
// ---------------------------------------------------------------------------
typedef struct {
    int      fd;
    uint32_t dlt;
    uint32_t bufsize;   // XNU requires read() to use EXACTLY this many bytes
    char     name[IFNAMSIZ];
} AetherBPFPort;

static AetherBPFPort   gPorts[AETHER_BPF_MAX_IF];
static int             gPortCount = 0;
static pthread_t       gTapThread = NULL;
static volatile bool   gTapRunning = false;
static pid_t           gTapPID = 0;
// pid of the root `-bftap` helper we spawned (0 when the tap runs in-process)
static pid_t           gHelperPID = 0;
static pid_t           gHelperTargetPID = 0;
static AetherFlowTable *gFlowTable = NULL;
static AetherPortSet   gTargetPorts;
static pthread_mutex_t gPortLock = PTHREAD_MUTEX_INITIALIZER;
// true when the kernel is giving us struct bpf_hdr_ext records (BIOCSEXTHDR)
static bool            gExtHdrEnabled = false;
static uint64_t        gLastInventoryMs = 0;
static uint64_t        gLastStatsMs     = 0;
// When the in-process lanes (P1/P2) are live they already feed the shared
// totals.  Running the tap as a non-primary observer avoids double counting
// while keeping the cross-check.
static bool            gTapPrimary = true;

static uint64_t AetherNowMs(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000ULL);
}

// ===========================================================================
// 1. Socket inventory (proc_pidfdinfo) — shared with the UI telemetry path
// ===========================================================================
int AetherRefreshSocketInventory(pid_t pid,
                                 AetherPortSet *outPorts,
                                 uint32_t *outTCP,
                                 uint32_t *outUDP,
                                 void *state) {
    if (pid <= 0) return -1;

    AetherPortSet localPorts;
    AetherPortSetClear(&localPorts);
    uint32_t tcpCount = 0, udpCount = 0;
    uint32_t entryIdx = 0;

    int bufSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (bufSize <= 0) {
        if (outTCP) *outTCP = 0;
        if (outUDP) *outUDP = 0;
        return -2;                       // no permission, or the pid is gone
    }

    struct aether_proc_fdinfo *fds = (struct aether_proc_fdinfo *)malloc((size_t)bufSize);
    if (!fds) return -3;

    int actual = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, bufSize);
    if (actual <= 0) { free(fds); return -4; }

    int fdCount = actual / (int)sizeof(struct aether_proc_fdinfo);
    AetherSharedState *st = (AetherSharedState *)state;

    // Diagnostics — a silent "no sockets" is indistinguishable from a struct
    // layout regression, so every run reports what it actually saw.
    int    socketFds = 0, infoOk = 0, infoShort = 0;
    int    kernelSize = 0;
    const int needSize = (int)sizeof(struct aether_socket_fdinfo);

    for (int i = 0; i < fdCount; i++) {
        if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        socketFds++;

        struct aether_socket_fdinfo sinfo;
        memset(&sinfo, 0, sizeof(sinfo));
        int rc = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO,
                                &sinfo, (int)sizeof(sinfo));
        if (rc <= 0) { infoShort++; continue; }
        if (rc != needSize) {
            // The kernel and we disagree about the size of struct
            // socket_fdinfo.  Everything we read sits at the FRONT of the
            // structure, so a larger kernel structure is still parseable; a
            // smaller one means we would read garbage, so skip it.
            kernelSize = rc;
            if (rc < needSize) { infoShort++; continue; }
        }
        infoOk++;

        int family = sinfo.psi.soi_family;
        if (family != AF_INET && family != AF_INET6) continue;

        int type = sinfo.psi.soi_type;
        if (type == SOCK_STREAM) tcpCount++;
        else if (type == SOCK_DGRAM) udpCount++;
        else continue;

        struct aether_in_sockinfo *ini = (type == SOCK_STREAM)
            ? &sinfo.psi.soi_proto.pri_tcp.tcpsi_ini
            : &sinfo.psi.soi_proto.pri_in;

        uint16_t lport = ntohs((uint16_t)ini->insi_lport);
        AetherPortSetAdd(&localPorts, lport);

        // NB: only LOCAL ports are matchers.  A foreign port (443, 5228 …) is
        // shared by every app on the device, so matching on it would attribute
        // other processes' traffic to our target.  (It is still reported in the
        // socket table so the UI can show the peer.)
        uint16_t fport = ntohs((uint16_t)ini->insi_fport);

        if (st && entryIdx < AETHER_MAX_TRACKED_SOCKETS) {
            AetherSocketEntry *entry = &st->activeSockets[entryIdx++];
            memset(entry, 0, sizeof(AetherSocketEntry));
            entry->protocol  = (type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
            entry->localPort = lport;
            entry->remotePort = fport;
            entry->state = (type == SOCK_STREAM)
                ? (uint8_t)sinfo.psi.soi_proto.pri_tcp.tcpsi_state : 1;
            entry->rxBytes = sinfo.psi.soi_rcv.sbi_cc;
            entry->txBytes = sinfo.psi.soi_snd.sbi_cc;
            if (family == AF_INET) {
                inet_ntop(AF_INET, &ini->insi_faddr.ina_46,
                          entry->remoteAddress, sizeof(entry->remoteAddress));
            } else {
                inet_ntop(AF_INET6, &ini->insi_faddr.ina_6,
                          entry->remoteAddress, sizeof(entry->remoteAddress));
            }
        }
    }
    free(fds);

    {
        static uint64_t   lastDiagMs = 0;
        static int        lastSig    = -1;
        int sig = (int)(tcpCount * 100000 + udpCount * 1000 + localPorts.count);
        uint64_t now = AetherNowMs();
        if (sig != lastSig || now - lastDiagMs >= 30000) {
            lastSig = sig;
            lastDiagMs = now;
            AetherLogDaemon(@"[inventory] pid %d euid=%u fd=%d socketfd=%d ok=%d skipped=%d size(kernel=%d/ours=%d) tcp=%u udp=%u ports=%u",
                            pid, (unsigned)geteuid(), fdCount, socketFds, infoOk,
                            infoShort, kernelSize, needSize, tcpCount, udpCount,
                            localPorts.count);
        }
    }

    if (st) {
        aether_atomic_store(&st->activeTCPSockets, tcpCount);
        aether_atomic_store(&st->activeUDPSockets, udpCount);
        st->socketEntryCount = entryIdx;
    }
    if (outPorts) *outPorts = localPorts;
    if (outTCP)   *outTCP = tcpCount;
    if (outUDP)   *outUDP = udpCount;
    return 0;
}

// ===========================================================================
// 2. BPF plumbing
// ===========================================================================
static NSArray<NSString *> *AetherCandidateInterfaces(void) {
    NSMutableArray *result = [NSMutableArray array];
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0) return result;

    for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;
        NSString *name = [NSString stringWithUTF8String:ifa->ifa_name];
        if ([result containsObject:name]) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        // awdl0 / llw0 are Apple's peer-to-peer links: chatty, never carry
        // target traffic.  Skip them to keep the tap cheap.
        if ([name hasPrefix:@"awdl"] || [name hasPrefix:@"llw"]) continue;
        [result addObject:name];
    }
    freeifaddrs(ifap);

    // Prefer real data bearers, then tunnels.
    NSArray *priority = @[ @"en0", @"pdp_ip0", @"en1", @"utun0", @"utun1", @"utun2" ];
    NSMutableArray *ordered = [NSMutableArray array];
    for (NSString *p in priority) {
        if ([result containsObject:p]) [ordered addObject:p];
    }
    for (NSString *n in result) {
        if (![ordered containsObject:n]) [ordered addObject:n];
    }
    return ordered;
}

static int AetherBPFOpenDevice(void) {
    char path[64];
    for (int i = 0; i < 64; i++) {
        snprintf(path, sizeof(path), "/dev/bpf%d", i);
        int fd = open(path, O_RDWR);
        if (fd >= 0) return fd;
        if (errno == EBUSY || errno == EACCES || errno == ENOENT) continue;
    }
    return -1;
}

static int AetherBPFAttach(const char *ifname, AetherBPFPort *port) {
    memset(port, 0, sizeof(*port));
    port->fd = AetherBPFOpenDevice();
    if (port->fd < 0) return -1;
    strncpy(port->name, ifname, IFNAMSIZ - 1);
    port->dlt = AETHER_DLT_EN10MB;

    // Buffer size FIRST: XNU's BIOCSBLEN returns EINVAL once an interface is
    // attached ("Interface already attached, unable to change buffers"), which
    // is why the 256 KB request failed and left us with the 4 KB default.
    uint32_t wantBuf = AETHER_BPF_BUFSIZE;
    for (uint32_t tryLen = wantBuf; tryLen >= 32768; tryLen >>= 1) {
        uint32_t v = tryLen;
        if (ioctl(port->fd, BIOCSBLEN, &v) == 0) { wantBuf = tryLen; break; }
        if (tryLen == 32768) wantBuf = 0;   // could not raise it at all
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(port->fd, BIOCSETIF, &ifr) < 0) {
        AetherLogDaemon(@"[tap] BIOCSETIF(%s) failed: %s", ifname, strerror(errno));
        close(port->fd);
        port->fd = -1;
        return -2;
    }

    uint32_t dlt = 0;
    if (ioctl(port->fd, BIOCGDLT, &dlt) == 0) port->dlt = dlt;

    // Immediate mode: read() returns as soon as a packet is available.
    // (A failure here used to be invisible — without it, read() only hands out
    //  data once the store buffer fills, which on a quiet interface is never.)
    uint32_t immediate = 1;
    if (ioctl(port->fd, BIOCIMMEDIATE, &immediate) < 0) {
        AetherLogDaemon(@"[tap] BIOCIMMEDIATE(%s) failed: %s", ifname, strerror(errno));
    }

    // Read timeout so the thread wakes up periodically and can notice a stop.
    struct timeval tv = { 0, 200000 }; // 200 ms
    if (ioctl(port->fd, BIOCSRTIMEOUT, &tv) < 0) {
        AetherLogDaemon(@"[tap] BIOCSRTIMEOUT(%s) failed: %s", ifname, strerror(errno));
    }

    // Belt and braces: the read timeout is a hint, O_NONBLOCK is a guarantee.
    // A read() that can block forever is a tap thread that can never be proved
    // alive or dead — it just goes silent, which is exactly the state 4.0.8
    // shipped in.
    int fl = fcntl(port->fd, F_GETFL, 0);
    if (fl >= 0) {
        if (fcntl(port->fd, F_SETFL, fl | O_NONBLOCK) < 0) {
            AetherLogDaemon(@"[tap] O_NONBLOCK(%s) failed: %s (non-fatal)",
                            ifname, strerror(errno));
        }
    }

    // bpfread() rejects any read whose size is not EXACTLY bd_bufsize
    // ("Restrict application to use a buffer the same size as kernel
    // buffers" — bsd/net/bpf.c), so the length below is not a preference.
    uint32_t realLen = 0;
    if (ioctl(port->fd, BIOCGBLEN, &realLen) != 0 || realLen == 0) {
        realLen = 4096;   // XNU default
    }
    port->bufsize = realLen;
    if (realLen != AETHER_BPF_BUFSIZE) {
        AetherLogDaemon(@"[tap] %s buffer is %u bytes (asked for %u) — read() must use exactly %u",
                        ifname, (unsigned)realLen, (unsigned)AETHER_BPF_BUFSIZE,
                        (unsigned)realLen);
    }

    // Extended header: per-packet PID / comm / direction.  Not fatal if the
    // kernel refuses — we fall back to port attribution.
    uint32_t extHdr = 1;
    if (ioctl(port->fd, BIOCSEXTHDR, &extHdr) < 0) {
        gExtHdrEnabled = false;
        AetherLogDaemon(@"[tap] BIOCSEXTHDR(%s) failed: %s — attributing by port instead",
                        ifname, strerror(errno));
    } else {
        gExtHdrEnabled = true;
    }
    // Promiscuous is not required to see our own traffic, but on some drivers
    // it is what makes inbound frames visible at all.  Non-fatal either way.
    if (ioctl(port->fd, BIOCPROMISC) < 0) {
        AetherLogDaemon(@"[tap] BIOCPROMISC(%s) failed: %s (non-fatal)", ifname, strerror(errno));
    }
    AetherLogDaemon(@"[tap] %s attached dlt=%u buflen=%u immediate=%d",
                    ifname, (unsigned)port->dlt, (unsigned)realLen, 1);

    // Filter: keep IPv4 + IPv6 only. The offsets depend on the DLT, so build
    // the program after BIOCGDLT.
    struct bpf_insn insns[8];
    memset(insns, 0, sizeof(insns));
    struct bpf_program prog;
    prog.bf_len = 0;
    prog.bf_insns = insns;

    if (port->dlt == AETHER_DLT_EN10MB) {
        // ldh [12] ; jeq #0x0800 → accept ; jeq #0x86DD → accept ; reject
        insns[0] = (struct bpf_insn)BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12);
        insns[1] = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 1, 0);
        insns[2] = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86DD, 0, 1);
        insns[3] = (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, (uint32_t)AETHER_BPF_SNAPLEN);
        insns[4] = (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, 0);
        prog.bf_len = 5;
    } else if (port->dlt == AETHER_DLT_NULL || port->dlt == AETHER_DLT_LOOP) {
        // utun0..2 report DLT_NULL here: a 4-byte address family (host order)
        // precedes the IP header.  AF_INET=2, AF_INET6=30 — as a little-endian
        // halfword at offset 0 that is exactly 2 / 30.
        insns[0] = (struct bpf_insn)BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0);
        insns[1] = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, 1, 0);
        insns[2] = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 30, 0, 1);
        insns[3] = (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, (uint32_t)AETHER_BPF_SNAPLEN);
        insns[4] = (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, 0);
        prog.bf_len = 5;
    } else if (port->dlt == AETHER_DLT_RAW) {
        // raw IP: ldb [0] ; rsh #4 ; jeq #4 → accept ; jeq #6 → accept ; reject
        insns[0] = (struct bpf_insn)BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0);
        insns[1] = (struct bpf_insn)BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 4);
        insns[2] = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 1, 0);
        insns[3] = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 1);
        insns[4] = (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, (uint32_t)AETHER_BPF_SNAPLEN);
        insns[5] = (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, 0);
        prog.bf_len = 6;
    } else {
        // Unknown DLT: install no filter at all rather than one built for the
        // wrong framing — a wrong filter silently drops everything.
        AetherLogDaemon(@"[tap] %s dlt=%u is not EN10MB/NULL/RAW — no kernel filter, "
                        @"everything is parsed in user space", ifname, (unsigned)port->dlt);
    }
    if (prog.bf_len && ioctl(port->fd, BIOCSETF, &prog) < 0) {
        // Not fatal — we simply parse everything and discard in user space.
        AetherLogDaemon(@"[tap] BIOCSETF(%s) failed: %s", ifname, strerror(errno));
    }

    return 0;
}

static void AetherBPFCloseAll(void) {
    for (int i = 0; i < gPortCount; i++) {
        if (gPorts[i].fd >= 0) { close(gPorts[i].fd); gPorts[i].fd = -1; }
    }
    gPortCount = 0;
}

bool AetherKernelLaneIsAvailable(void) {
    int fd = AetherBPFOpenDevice();
    if (fd < 0) return false;
    close(fd);
    return true;
}

// ===========================================================================
// 3. Tap thread
// ===========================================================================
static int gCurrentDLT = AETHER_DLT_EN10MB;

static void AetherHandleFrame(const uint8_t *frame, size_t len, int dlt);

// AetherBPFIterate hands us one link-layer record at a time; adapt it to the
// frame handler below, which is also used by the pcap-free raw tests.
static uint32_t gFramesSeen    = 0;
static uint32_t gFramesIP      = 0;
static uint32_t gFramesMatched = 0;
// Read-path health.  On build 403 the statistics said "seen=0 ... poll=1": poll
// claimed a descriptor was ready while not a single record was walked, which
// means the failure is in read() or in the record walk, not in the attach.
// These counters (plus the hex dump below) tell us which.
static uint64_t gReadCalls     = 0;
static uint64_t gReadBytes     = 0;
static uint32_t gReadErrors    = 0;
static uint32_t gReadZero      = 0;
static uint32_t gReadNoFrames  = 0;
static int      gReadLastErrno = 0;
static uint32_t gReadDumpShown = 0;
static uint32_t gFramesMatchedByPID = 0;   // attributed by bh_pid, not by port
static uint32_t gMaxBufSize    = AETHER_BPF_BUFSIZE;
// When nothing matches, "matched=0" alone says nothing about whether the
// target's traffic is even on the wire.  These keep a small top-N of the
// 5-tuples we could not attribute so the log can answer that.
#define AETHER_TOPFLOWS 6
typedef struct {
    uint8_t  proto;
    char     src[56];
    char     dst[56];
    uint64_t count;
} AetherTopFlow;
static AetherTopFlow gTopFlows[AETHER_TOPFLOWS];

static void AetherTopFlowsNote(const AetherParsedPacket *pkt) {
    if (!pkt) return;
    char sbuf[56], dbuf[56];
    AetherFormatEndpoint(pkt, 0, sbuf, sizeof(sbuf));
    AetherFormatEndpoint(pkt, 1, dbuf, sizeof(dbuf));

    for (int i = 0; i < AETHER_TOPFLOWS; i++) {
        if (gTopFlows[i].count && gTopFlows[i].proto == pkt->proto &&
            strncmp(gTopFlows[i].src, sbuf, sizeof(sbuf)) == 0 &&
            strncmp(gTopFlows[i].dst, dbuf, sizeof(dbuf)) == 0) {
            gTopFlows[i].count++;
            return;
        }
    }
    int slot = 0;
    for (int i = 1; i < AETHER_TOPFLOWS; i++) {
        if (gTopFlows[i].count < gTopFlows[slot].count) slot = i;
    }
    gTopFlows[slot].proto = pkt->proto;
    strncpy(gTopFlows[slot].src, sbuf, sizeof(gTopFlows[slot].src) - 1);
    strncpy(gTopFlows[slot].dst, dbuf, sizeof(gTopFlows[slot].dst) - 1);
    gTopFlows[slot].count = 1;
}

// Which process does the kernel itself think each frame belongs to?  With
// BIOCSEXTHDR, bpf stamps bh_pid from the inpcb.  If it is 0 for every single
// frame then the kernel is attributing nothing at all — which means PID-based
// matching is simply unavailable here (multicast/broadcast noise has no owner)
// rather than "the target is silent".  A histogram settles which.
#define AETHER_PIDHIST 4
typedef struct { pid_t pid; uint32_t count; } AetherPIDCount;
static AetherPIDCount gPIDHist[AETHER_PIDHIST];
static uint32_t       gPIDZero = 0;

static void AetherPIDHistNote(pid_t pid, bool hasPID) {
    if (!hasPID) return;
    if (pid == 0) { gPIDZero++; return; }
    for (int i = 0; i < AETHER_PIDHIST; i++) {
        if (gPIDHist[i].count && gPIDHist[i].pid == pid) { gPIDHist[i].count++; return; }
    }
    int slot = 0;
    for (int i = 1; i < AETHER_PIDHIST; i++) {
        if (gPIDHist[i].count < gPIDHist[slot].count) slot = i;
    }
    gPIDHist[slot].pid = pid;
    gPIDHist[slot].count = 1;
}

static NSString *AetherPIDHistDescribe(void) {
    AetherPIDCount sorted[AETHER_PIDHIST];
    memcpy(sorted, gPIDHist, sizeof(sorted));
    for (int i = 1; i < AETHER_PIDHIST; i++) {
        for (int j = i; j > 0 && sorted[j].count > sorted[j - 1].count; j--) {
            AetherPIDCount tmp = sorted[j]; sorted[j] = sorted[j - 1]; sorted[j - 1] = tmp;
        }
    }
    NSMutableString *out = [NSMutableString string];
    for (int i = 0; i < AETHER_PIDHIST; i++) {
        if (!sorted[i].count) continue;
        [out appendFormat:@"%s%d (%u)", [out length] ? "; " : "",
             (int)sorted[i].pid, (unsigned)sorted[i].count];
    }
    if (![out length]) return [NSString stringWithFormat:@"pid=0 x%u (kernel attributed "
                                                          @"nothing)", (unsigned)gPIDZero];
    return [NSString stringWithFormat:@"pid=0 x%u | %@", (unsigned)gPIDZero, out];
}

static NSString *AetherTopFlowsDescribe(void) {
    AetherTopFlow sorted[AETHER_TOPFLOWS];
    memcpy(sorted, gTopFlows, sizeof(sorted));
    for (int i = 1; i < AETHER_TOPFLOWS; i++) {
        for (int j = i; j > 0 && sorted[j].count > sorted[j - 1].count; j--) {
            AetherTopFlow tmp = sorted[j]; sorted[j] = sorted[j - 1]; sorted[j - 1] = tmp;
        }
    }
    NSMutableString *out = [NSMutableString string];
    for (int i = 0; i < AETHER_TOPFLOWS; i++) {
        if (!sorted[i].count) continue;
        [out appendFormat:@"%s%s %s -> %s (%llu)",
             [out length] ? "; " : "",
             sorted[i].proto == AETHER_IPPROTO_TCP ? "TCP" : "UDP",
             sorted[i].src, sorted[i].dst, (unsigned long long)sorted[i].count];
    }
    return [out length] ? out : @"none";
}

static void AetherBPFStats(int fd, uint32_t *recv, uint32_t *drop) {
    if (recv) *recv = 0;
    if (drop) *drop = 0;
    if (fd < 0) return;
    struct bpf_stat bst;
    memset(&bst, 0, sizeof(bst));
    if (ioctl(fd, BIOCGSTATS, &bst) == 0) {
        if (recv) *recv = bst.bs_recv;
        if (drop) *drop = bst.bs_drop;
    }
}

// Metadata of the record currently being handled (set by the walker below).
// With BIOCSEXTHDR the kernel tells us which process owns the flow, so
// attribution no longer depends on the port inventory being complete.
static pid_t gPktPID      = 0;
static bool  gPktHasPID   = false;
static bool  gPktExtHdr   = false;
static bool  gPktIsTX     = false;
static uint32_t gPktTS    = 0;   // timestamp width detected for this batch

// Probe helper: counts how many BPF records a batch actually contains.
static void AetherProbeCountFrame(void *ctx, const uint8_t *frame, size_t len) {
    (void)ctx; (void)frame; (void)len;
}

static void AetherHandleBPFMeta(void *ctx, const AetherBPFMeta *meta,
                                const uint8_t *frame, size_t len) {
    (void)ctx;
    gFramesSeen++;
    gPktExtHdr = meta->extHdr;
    gPktPID    = meta->pid;
    gPktHasPID = meta->hasPID;
    gPktIsTX   = meta->isTX;
    gPktTS     = meta->tsSize;
    AetherPIDHistNote(meta->pid, meta->hasPID);
    AetherHandleFrame(frame, len, gCurrentDLT);
}

static void AetherHandleFrame(const uint8_t *frame, size_t len, int dlt) {
    AetherParsedPacket pkt;
    if (AetherParseLinkFrame(frame, len, dlt, &pkt) != 0) return;
    if (pkt.proto != AETHER_IPPROTO_TCP && pkt.proto != AETHER_IPPROTO_UDP) return;
    gFramesIP++;

    AetherPortSet ports;
    pthread_mutex_lock(&gPortLock);
    ports = gTargetPorts;
    pthread_mutex_unlock(&gPortLock);

    bool isTX = false;
    bool byPort = AetherClassifyDirection(&pkt, &ports, &isTX);
    bool byPID  = (gPktHasPID && gPktPID == gTapPID);
    if (!byPort && !byPID) {
        AetherTopFlowsNote(&pkt);
        return;                                    // not our target
    }
    if (byPID) {
        gFramesMatchedByPID++;
        // The kernel's direction flag beats any heuristic.
        if (gPktExtHdr) isTX = gPktIsTX;
    }
    gFramesMatched++;

    uint64_t now = AetherNowMs();
    uint64_t wireBytes = pkt.ipTotalLen ? pkt.ipTotalLen : len;

    // The first few attributed packets are logged in full: counters alone
    // cannot tell "the tap is dead" apart from "the target is quiet".
    if (gFramesMatched <= 5) {
        char sbuf[64], dbuf[64];
        AetherLogDaemon(@"[tap] match#%u %@ %s -> %s %@ %lluB",
                        gFramesMatched,
                        pkt.proto == AETHER_IPPROTO_TCP ? @"TCP" : @"UDP",
                        AetherFormatEndpoint(&pkt, 0, sbuf, sizeof(sbuf)),
                        AetherFormatEndpoint(&pkt, 1, dbuf, sizeof(dbuf)),
                        isTX ? @"TX" : @"RX",
                        (unsigned long long)wireBytes);
    }

    AetherSharedState *st = AetherGetSharedState();
    if (st) {
        if (isTX) aether_atomic_fetch_add(&st->kernelTapPacketsTX, 1);
        else      aether_atomic_fetch_add(&st->kernelTapPacketsRX, 1);
        if (isTX) aether_atomic_fetch_add(&st->kernelTapBytesTX, wireBytes);
        else      aether_atomic_fetch_add(&st->kernelTapBytesRX, wireBytes);

        if (gTapPrimary) {
            if (pkt.proto == AETHER_IPPROTO_TCP) {
                if (isTX) aether_atomic_fetch_add(&st->totalTCPPacketsTX, 1);
                else      aether_atomic_fetch_add(&st->totalTCPPacketsRX, 1);
            } else {
                if (isTX) aether_atomic_fetch_add(&st->totalUDPPacketsTX, 1);
                else      aether_atomic_fetch_add(&st->totalUDPPacketsRX, 1);
            }
            if (isTX) aether_atomic_fetch_add(&st->totalBytesTX, pkt.l4PayloadLen);
            else      aether_atomic_fetch_add(&st->totalBytesRX, pkt.l4PayloadLen);
        }
    }

    if (gFlowTable) {
        AetherFlowTableRecord(gFlowTable, &pkt, isTX, wireBytes, now);
        if (st) {
            aether_atomic_store(&st->kernelTapFlows, AetherFlowTableCount(gFlowTable));
        }
    }

    // Flow-level visibility in the log (rate limited to avoid drowning it).
    static uint64_t lastLogMs = 0;
    static uint64_t sinceLog = 0;
    sinceLog++;
    if (now - lastLogMs >= 2000 && st) {
        lastLogMs = now;
        char src[64], dst[64];
        AetherFormatEndpoint(&pkt, 0, src, sizeof(src));
        AetherFormatEndpoint(&pkt, 1, dst, sizeof(dst));
        AetherLogDaemon(@"[tap] %s %s -> %s (%u B payload, %llu pkt/2s)",
                        pkt.proto == AETHER_IPPROTO_TCP ? "TCP" : "UDP",
                        src, dst, (unsigned)pkt.l4PayloadLen, (unsigned long long)sinceLog);
        sinceLog = 0;
    }
}

// Where the tap thread currently is.  Written by the reader loop, read by the
// fatal-signal handler so a crash says *where* it happened instead of just
// that it happened.  0 = not in the loop.
static volatile int      gTapPhase      = 0;

extern "C" int       AetherKernelLanePhase(void)   { return gTapPhase; }
extern "C" pthread_t AetherKernelLaneThread(void)  { return gTapThread; }

// Liveness counters sampled by the independent watchdog thread below: they are
// the only way to tell "the reader loop is wedged inside read()" apart from
// "the process is gone".  Both look identical from the outside — silence.
static volatile uint64_t gTapLoops      = 0;
static volatile uint64_t gTapLastReadMs = 0;
static pthread_t         gTapLivenessThread = NULL;

static void *AetherTapLivenessMain(void *arg) {
    (void)arg;
    uint64_t lastLoops = 0, lastFrames = 0;
    while (gTapRunning) {
        for (int i = 0; i < 20 && gTapRunning; i++) usleep(100000);   // 2 s
        if (!gTapRunning) break;
        uint64_t loops  = gTapLoops;
        uint64_t frames = (uint64_t)gFramesSeen;
        uint64_t idle   = gTapLastReadMs ? (AetherNowMs() - gTapLastReadMs) : 0;
        AetherLogDaemon(@"[tap] liveness: loops=%llu (+%llu) frames=%u (+%llu) "
                        @"matched=%u reads=%llu errors=%u zero=%u lastData=%llums",
                        loops, loops - lastLoops,
                        gFramesSeen, frames - lastFrames,
                        gFramesMatched, (unsigned long long)gReadCalls,
                        gReadErrors, gReadZero, (unsigned long long)idle);
        lastLoops  = loops;
        lastFrames = frames;
    }
    return NULL;
}

static void *AetherTapThreadMain(void *arg) {
    (void)arg;
    AetherLogDaemon(@"[tap] reader thread started (pid %d, %d interface(s))",
                    gTapPID, gPortCount);

    size_t maxBuf = AETHER_BPF_BUFSIZE;
    for (int i = 0; i < gPortCount; i++) {
        if (gPorts[i].bufsize > maxBuf) maxBuf = gPorts[i].bufsize;
    }
    uint8_t *buffer = (uint8_t *)malloc(maxBuf + 8192);
    if (!buffer) { gTapRunning = false; return NULL; }

    struct pollfd pfds[AETHER_BPF_MAX_IF];

    gTapThread = pthread_self();
    while (gTapRunning) {
        gTapLoops++;
        gTapPhase = 1;                       // building the poll set
        int n = 0;
        for (int i = 0; i < gPortCount; i++) {
            if (gPorts[i].fd >= 0) {
                pfds[n].fd = gPorts[i].fd;
                pfds[n].events = POLLIN;
                pfds[n].revents = 0;
                n++;
            }
        }
        if (n == 0) { usleep(100000); continue; }

        gTapPhase = 2;                       // polling
        int ready = poll(pfds, n, 200);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready > 0) {
            for (int i = 0; i < n; i++) {
                if (!(pfds[i].revents & POLLIN)) continue;
                int portIdx = -1;
                for (int k = 0; k < gPortCount; k++) {
                    if (gPorts[k].fd == pfds[i].fd) { portIdx = k; break; }
                }
                if (portIdx < 0) continue;
                // bpfread() demands uio_resid == bd_bufsize *exactly*
                // (bsd/net/bpf.c: "Restrict application to use a buffer the
                // same size as kernel buffers"); anything else is EINVAL —
                // which is why every read failed on build 404.
                size_t readLen = gPorts[portIdx].bufsize ? (size_t)gPorts[portIdx].bufsize
                                                         : (size_t)AETHER_BPF_BUFSIZE;
                if (readLen > (size_t)gMaxBufSize) readLen = (size_t)gMaxBufSize;

                gTapPhase = 3;                   // reading a descriptor
                gReadCalls++;
                ssize_t got = read(pfds[i].fd, buffer, readLen);
                if (got < 0) {
                    // EAGAIN is the normal answer of a non-blocking descriptor
                    // with nothing to hand out — not an error.
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        gReadZero++;
                        continue;
                    }
                    gReadErrors++;
                    gReadLastErrno = errno;
                    if (gReadErrors <= 3 || gReadErrors % 200 == 0) {
                        AetherLogDaemon(@"[tap] read(%zu) failed (x%u): %s",
                                        readLen, gReadErrors, strerror(errno));
                    }
                    if (errno == EINTR) continue;
                    // A hard error that repeats with poll() still reporting the
                    // descriptor ready would spin the thread: back off a little.
                    usleep(20000);
                    continue;
                }
                if (got == 0) {
                    gReadZero++;
                    if (gReadZero <= 3 || gReadZero % 200 == 0) {
                        AetherLogDaemon(@"[tap] read() returned 0 bytes with poll() ready (x%u)",
                                        gReadZero);
                    }
                    // poll() claiming readiness with read() returning nothing
                    // would otherwise spin this thread at 100% CPU.
                    usleep(20000);
                    continue;
                }
                gReadBytes += (uint64_t)got;
                gTapLastReadMs = AetherNowMs();

                gCurrentDLT = (int)gPorts[portIdx].dlt;
                gTapPhase = 4;                   // walking BPF records
                // The record stepping lives in the portable core (unit tested on
                // the host) rather than being open-coded here.
                int frames = AetherBPFIterateWithHeader(buffer, (size_t)got, NULL,
                                                        AetherHandleBPFMeta);
                if (frames == 0) {
                    gReadNoFrames++;
                    // Bytes arrived but no record could be walked: either the
                    // kernel's bpf_hdr differs from ours, or the buffer starts
                    // with a partial record.  Dump the head once — it settles it.
                    if (gReadDumpShown < 2) {
                        gReadDumpShown++;
                        NSMutableString *hex = [NSMutableString string];
                        for (int b = 0; b < 32 && b < got; b++) {
                            [hex appendFormat:@"%02x", buffer[b]];
                        }
                        AetherLogDaemon(@"[tap] %zd byte(s) read but no BPF record decoded "
                                        @"(dlt=%d, caplen@16, hdrlen@24): %@",
                                        got, gCurrentDLT, hex);
                    }
                }
            }
        }

        gTapPhase = 5;                       // periodic work
        // --- Periodic work ---------------------------------------------------
        // Both of these used to sit in the "poll() timed out" branch, which
        // never runs on a busy interface: en0 always has background chatter,
        // so the tap printed no statistics at all and the port inventory was
        // never refreshed.  They are time-driven now.
        {
            uint64_t nowMs = AetherNowMs();

            // Statistics: without this the tap is a black box — "running"
            // says nothing about whether a packet was ever attributed.
            if (nowMs - gLastStatsMs >= 5000) {
                gLastStatsMs = nowMs;
                AetherSharedState *stt = AetherGetSharedState();
                AetherPortSet cur;
                pthread_mutex_lock(&gPortLock);
                cur = gTargetPorts;
                pthread_mutex_unlock(&gPortLock);
                uint32_t krecv = 0, kdrop = 0;
                if (gPortCount > 0) AetherBPFStats(gPorts[0].fd, &krecv, &kdrop);
                if (gFramesMatched == 0 && gFramesIP > 0) {
                    AetherLogDaemon(@"[tap] busiest unattributed flows: %@",
                                    AetherTopFlowsDescribe());
                    AetherLogDaemon(@"[tap] kernel frame ownership: %@ (target pid %d)",
                                    AetherPIDHistDescribe(), (int)gTapPID);
                }
                NSMutableString *portDesc = [NSMutableString string];
                uint32_t portShown = cur.count > 8 ? 8 : cur.count;
                for (uint32_t pi = 0; pi < portShown; pi++) {
                    [portDesc appendFormat:@"%s%u", (pi ? "," : ""), cur.ports[pi]];
                }
                if (cur.count > portShown) {
                    [portDesc appendFormat:@",+%u more", cur.count - portShown];
                }
                AetherLogDaemon(@"[tap] seen=%u ip=%u matched=%u | shm rx=%llu tx=%llu flows=%u | ports=%u (%@) | matchedByPID=%u ts=%u | poll=%d read=%llu/%lluB err=%u(%d) zero=%u noframe=%u krecv=%u kdrop=%u",
                                gFramesSeen, gFramesIP, gFramesMatched,
                                stt ? (unsigned long long)aether_atomic_load(&stt->kernelTapPacketsRX) : 0ULL,
                                stt ? (unsigned long long)aether_atomic_load(&stt->kernelTapPacketsTX) : 0ULL,
                                stt ? aether_atomic_load(&stt->kernelTapFlows) : 0u,
                                cur.count,
                                portDesc,
                                gFramesMatchedByPID,
                                gPktTS,
                                ready,
                                (unsigned long long)gReadCalls, (unsigned long long)gReadBytes,
                                gReadErrors, gReadLastErrno, gReadZero, gReadNoFrames,
                                krecv, kdrop);
                if (stt) {
                    aether_atomic_store(&stt->tapFramesSeen, gFramesSeen);
                    aether_atomic_store(&stt->tapFramesIP, gFramesIP);
                    aether_atomic_store(&stt->tapFramesMatched, gFramesMatched);
                    // Liveness heartbeat: the app can tell "tap is alive but
                    // the target is silent" apart from "tap thread is wedged".
                    aether_atomic_store(&stt->tapStatsLogged, (uint32_t)(nowMs & 0xFFFFFFFFu));
                }
            }

            // Refresh the socket inventory so newly opened ports of the target
            // are picked up (a game opening a new UDP flow, …).
            if (nowMs - gLastInventoryMs >= 500) {
                gLastInventoryMs = nowMs;
                gTapPhase = 6;                   // socket inventory refresh
                AetherPortSet fresh;
                uint32_t tcp = 0, udp = 0;
                AetherSharedState *st = AetherGetSharedState();
                if (AetherRefreshSocketInventory(gTapPID, &fresh, &tcp, &udp, st) == 0) {
                    pthread_mutex_lock(&gPortLock);
                    gTargetPorts = fresh;
                    pthread_mutex_unlock(&gPortLock);
                }
            }
        }
    }

    free(buffer);
    gTapPhase = 0;
    gTapRunning = false;
    AetherLogDaemon(@"[tap] reader thread exited");
    return NULL;
}
// Liveness probe: read from every attached interface for `ms` and report how
// many bytes and how many decodable BPF records each one produced.  A device
// can attach successfully and still hand out nothing, so this runs before the
// tap is declared operational.
static void AetherBPFProbe(uint32_t ms, size_t *perIf, size_t *frames, int *errnoOut) {
    for (int i = 0; i < AETHER_BPF_MAX_IF; i++) perIf[i] = 0;
    if (frames)  *frames = 0;
    if (errnoOut) *errnoOut = 0;

    // The kernel demands read()s of exactly bd_bufsize, so the probe buffer has
    // to cover the largest one — 4.0.6 clamped to 64 KB and every probe read
    // failed with EINVAL, which made a perfectly healthy tap look dead.
    size_t maxBuf = 4096;
    for (int i = 0; i < gPortCount; i++) {
        if (gPorts[i].bufsize > maxBuf) maxBuf = gPorts[i].bufsize;
    }
    uint8_t *probe = (uint8_t *)malloc(maxBuf);
    if (!probe) return;

    uint64_t deadline = AetherNowMs() + ms;
    while (AetherNowMs() < deadline) {
        struct pollfd pf[AETHER_BPF_MAX_IF];
        int n = 0;
        for (int i = 0; i < gPortCount; i++) {
            pf[n].fd = gPorts[i].fd; pf[n].events = POLLIN; pf[n].revents = 0; n++;
        }
        if (n == 0) break;
        int r = poll(pf, (unsigned)n, 200);
        if (r > 0) {
            for (int i = 0; i < n; i++) {
                if (!(pf[i].revents & POLLIN)) continue;
                // Same rule as the reader thread: exactly bd_bufsize bytes.
                size_t len = gPorts[i].bufsize ? (size_t)gPorts[i].bufsize : 4096u;
                ssize_t got = read(pf[i].fd, probe, len);
                if (got > 0) {
                    perIf[i] += (size_t)got;
                    if (frames) {
                        *frames += (size_t)AetherBPFIterate(probe, (size_t)got, frames,
                                                            AetherProbeCountFrame);
                    }
                } else if (got < 0 && errnoOut && *errnoOut == 0) {
                    *errnoOut = errno;
                }
            }
        }
    }
    free(probe);
}


// ===========================================================================
// 4. Public API
// ===========================================================================

int AetherKernelLaneStart(pid_t pid, bool primary, char *errBuf, size_t errBufLen) {
    if (pid <= 0) {
        snprintf(errBuf, errBufLen, "invalid pid");
        return -1;
    }
    if (gTapRunning) {
        snprintf(errBuf, errBufLen, "tap already running");
        return -2;
    }

    AetherSharedState *st = AetherGetSharedState();
    if (!st) {
        snprintf(errBuf, errBufLen, "shared state unavailable");
        return -3;
    }

    // 1 — inventory first: without at least one local port the tap cannot
    //     attribute anything.
    AetherPortSet ports;
    uint32_t tcp = 0, udp = 0;
    if (AetherRefreshSocketInventory(pid, &ports, &tcp, &udp, st) != 0) {
        snprintf(errBuf, errBufLen,
                 "socket inventory failed (euid=%u - proc_pidinfo needs root) for pid %d",
                 (unsigned)geteuid(), pid);
        return -4;
    }
    // A target that was attached a moment ago may not have opened its sockets
    // yet, and a backgrounded app owns none until it is foregrounded: retry
    // briefly instead of failing the whole lane on the first empty answer.
    for (int attempt = 0; ports.count == 0 && attempt < 12; attempt++) {
        usleep(250000);
        if (AetherRefreshSocketInventory(pid, &ports, &tcp, &udp, st) != 0) break;
    }
    if (ports.count == 0) {
        // Nothing to key on.  This is the normal state for an app whose
        // traffic runs entirely on the Network.framework / libusrtcp userspace
        // stack: those flows own no BSD socket, so proc_pidfdinfo cannot see
        // them and the tap has no way to attribute packets to this process.
        // Guessing (counting every packet on the interface) would silently
        // charge other apps' traffic to the target, so we refuse instead.
        snprintf(errBuf, errBufLen,
                 "target owns no BSD TCP/UDP socket (euid=%u) - its traffic is on the "
                 "Network.framework userspace stack and cannot be attributed without "
                 "in-process hooks (P1/P2)",
                 (unsigned)geteuid());
        return -5;
    }
    pthread_mutex_lock(&gPortLock);
    gTargetPorts = ports;
    pthread_mutex_unlock(&gPortLock);

    // 2 — attach BPF to the interfaces the device is really using
    gPortCount = 0;
    NSArray *ifnames = AetherCandidateInterfaces();
    for (NSString *name in ifnames) {
        if (gPortCount >= AETHER_BPF_MAX_IF) break;
        AetherBPFPort port;
        if (AetherBPFAttach([name UTF8String], &port) == 0) {
            gPorts[gPortCount++] = port;
        }
    }
    if (gPortCount == 0) {
        snprintf(errBuf, errBufLen, "cannot open /dev/bpf or attach to any interface");
        return -6;
    }

    // 2b — liveness probe.  Everything above can succeed and still deliver
    //      nothing: on build 403 a device reported "tap started on en0" and then
    //      "seen=0" for the whole session.  One second of polling before we
    //      start the thread tells us whether BPF on THIS device actually hands
    //      out frames, and on which interface.
    {
        size_t perIf[AETHER_BPF_MAX_IF];
        size_t probeFrames = 0;
        int    probeErrno = 0;
        AetherBPFProbe(1000, perIf, &probeFrames, &probeErrno);

        // Bytes arrived but not one record could be decoded: the framing is not
        // what we assumed.  The most likely culprit is the extended header we
        // just asked for, so try once without it before giving up.
        if (probeFrames == 0) {
            size_t total0 = 0;
            for (int i = 0; i < gPortCount; i++) total0 += perIf[i];
            if (total0 > 0) {
                gExtHdrEnabled = false;
                for (int i = 0; i < gPortCount; i++) {
                    uint32_t off = 0;
                    ioctl(gPorts[i].fd, BIOCSEXTHDR, &off);
                }
                AetherLogDaemon(@"[tap] no record decoded from %zu byte(s) — retrying "
                                @"without the extended header", total0);
                AetherBPFProbe(1000, perIf, &probeFrames, &probeErrno);
            }
        }

        NSMutableString *list = [NSMutableString string];
        size_t total = 0;
        for (int i = 0; i < gPortCount; i++) {
            [list appendFormat:@"%s%s=%zuB", i ? " " : "", gPorts[i].name, perIf[i]];
            total += perIf[i];
        }
        AetherLogDaemon(@"[tap] 1s probe: %@ (%zu frame(s) decoded, exthdr=%d, errno=%d)%@",
                        list, probeFrames, gExtHdrEnabled ? 1 : 0, probeErrno,
                        total == 0
                            ? @" — BPF handed out NOTHING on any interface: this device's "
                              @"BPF tap does not see traffic (no ifnet tap), so packet capture "
                              @"is impossible without in-process hooks"
                            : @"");
    }

    // 3 — flow table
    gTapPrimary = primary;
    if (gFlowTable) AetherFlowTableDestroy(gFlowTable);
    gFlowTable = AetherFlowTableCreate(2048);

    // 4 — reader thread
    gTapPID = pid;
    gLastInventoryMs = AetherNowMs();
    gLastStatsMs     = AetherNowMs();
    gFramesSeen = gFramesIP = gFramesMatched = 0;
    gReadCalls = gReadBytes = 0;
    gReadErrors = gReadZero = gReadNoFrames = gReadDumpShown = 0;
    gReadLastErrno = 0;
    gFramesMatchedByPID = 0;
    memset(gPIDHist, 0, sizeof(gPIDHist));
    gPIDZero = 0;
    memset(gTopFlows, 0, sizeof(gTopFlows));
    gExtHdrEnabled = false;
    gMaxBufSize = AETHER_BPF_BUFSIZE;
    for (int i = 0; i < gPortCount; i++) {
        if (gPorts[i].bufsize > gMaxBufSize) gMaxBufSize = gPorts[i].bufsize;
    }
    gTapRunning = true;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&gTapThread, &attr, AetherTapThreadMain, NULL) != 0) {
        gTapRunning = false;
        AetherBPFCloseAll();
        pthread_attr_destroy(&attr);
        snprintf(errBuf, errBufLen, "pthread_create failed: %s", strerror(errno));
        return -7;
    }
    pthread_attr_destroy(&attr);

    // Independent of the reader loop on purpose: if the loop wedges, this
    // thread keeps talking and the log shows loops=… frozen instead of nothing.
    pthread_create(&gTapLivenessThread, NULL, AetherTapLivenessMain, NULL);

    strncpy(st->kernelTapInterface, gPorts[0].name, sizeof(st->kernelTapInterface) - 1);

    NSMutableString *portList = [NSMutableString string];
    for (uint32_t i = 0; i < ports.count && i < 12; i++) {
        [portList appendFormat:(i ? @",%u" : @"%u"), ports.ports[i]];
    }
    NSMutableString *ifList = [NSMutableString string];
    for (int i = 0; i < gPortCount; i++) {
        [ifList appendFormat:@"%s%s(dlt=%u)", i ? "," : "", gPorts[i].name,
                             (unsigned)gPorts[i].dlt];
    }
    AetherLogDaemon(@"[tap] started for pid %d on %@ (%u TCP / %u UDP socket) matching ports [%@]%s",
                    pid, ifList, tcp, udp, portList,
                    ports.count > 12 ? " ..." : "");
    return 0;
}

extern "C" void AetherKernelLaneStop(void) {
    if (!gTapRunning) return;
    gTapRunning = false;
    // Closing the descriptors makes poll()/read() return immediately.
    AetherBPFCloseAll();
    // Give the detached thread a moment to notice.
    usleep(250000);

    if (gFlowTable) {
        AetherFlowTableDestroy(gFlowTable);
        gFlowTable = NULL;
    }
    AetherPortSet ports;
    AetherPortSetClear(&ports);
    pthread_mutex_lock(&gPortLock);
    gTargetPorts = ports;
    pthread_mutex_unlock(&gPortLock);
    gTapPID = 0;
    AetherSharedState *st = AetherGetSharedState();
    uint32_t krecv = 0, kdrop = 0;
    AetherBPFStats(gPorts[0].fd, &krecv, &kdrop);
    AetherLogDaemon(@"[tap] stopped (seen=%u ip=%u matched=%u | shm rx=%llu tx=%llu flows=%u | read=%llu/%lluB err=%u zero=%u noframe=%u krecv=%u kdrop=%u)",
                    gFramesSeen, gFramesIP, gFramesMatched,
                    st ? (unsigned long long)aether_atomic_load(&st->kernelTapPacketsRX) : 0ULL,
                    st ? (unsigned long long)aether_atomic_load(&st->kernelTapPacketsTX) : 0ULL,
                    st ? aether_atomic_load(&st->kernelTapFlows) : 0u,
                    (unsigned long long)gReadCalls, (unsigned long long)gReadBytes,
                    gReadErrors, gReadZero, gReadNoFrames, krecv, kdrop);
}

extern "C" bool AetherKernelLaneIsRunning(void) {
    if (gHelperPID > 0) return AetherKernelLaneRootHelperAlive();
    return gTapRunning;
}

// ===========================================================================
// 5. Root tap helper (`AetherNet -bftap <pid> <primary>`)
// ===========================================================================
#define AETHER_BFTAP_LOCK "/var/mobile/Library/Caches/com.aethernet.bftap.lock"

static volatile sig_atomic_t gHelperStop = 0;

static void AetherBpfTapSignal(int sig) {
    (void)sig;
    gHelperStop = 1;
}

extern "C" bool AetherKernelLaneRootHelperAlive(void) {
    if (gHelperPID <= 0) return false;
    if (kill(gHelperPID, 0) == 0) return true;
    // EPERM: the process exists but is more privileged than us (the helper
    // runs as root) — same rule the HUD liveness probe uses.
    return (errno == EPERM);
}

extern "C" int AetherKernelLaneStartViaRootHelper(pid_t pid, bool primary,
                                                  char *errBuf, size_t errBufLen) {
    if (pid <= 0) {
        snprintf(errBuf, errBufLen, "invalid pid");
        return -1;
    }
    if (AetherKernelLaneRootHelperAlive()) {
        if (gHelperTargetPID == pid) {
            snprintf(errBuf, errBufLen, "root tap helper already running (pid %d)",
                     (int)gHelperPID);
            return 0;
        }
        // Different target: retire the old helper first, otherwise the new one
        // would take the flock, exit immediately, and we would keep reporting
        // the PREVIOUS target's interface as if it were this session's.
        AetherKernelLaneStopRootHelper();
    }

    AetherSharedState *st = AetherGetSharedState();
    if (!st) {
        snprintf(errBuf, errBufLen, "shared state unavailable");
        return -3;
    }
    // The helper publishes the interface it attached to; clear it so we can
    // tell a fresh start apart from a stale value.
    memset(st->kernelTapInterface, 0, sizeof(st->kernelTapInterface));
    aether_atomic_store(&st->tapStopRequest, 0u);   // reset any previous stop

    pid_t child = 0;
    int rc = AetherSpawnRootChild(@[ @"-bftap",
                                     [NSString stringWithFormat:@"%d", (int)pid],
                                     primary ? @"1" : @"0" ],
                                  &child);
    if (rc != 0) {
        snprintf(errBuf, errBufLen, "cannot spawn root tap helper: %s", strerror(rc));
        return -8;
    }

    // Give the helper up to ~2.5 s to attach (it retries the socket inventory
    // for a target that has not opened its sockets yet).
    bool started = false;
    for (int i = 0; i < 50; i++) {
        usleep(50000);
        if (st->kernelTapInterface[0] != '\0') { started = true; break; }
        if (kill(child, 0) != 0 && errno != EPERM) break;   // helper died
    }
    if (!started) {
        kill(child, SIGKILL);
        int status = 0;
        waitpid(child, &status, 0);
        gHelperPID = 0;
        snprintf(errBuf, errBufLen,
                 "root tap helper did not attach (exit=%d) - see daemon log",
                 WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return -9;
    }

    gHelperPID = child;
    gHelperTargetPID = pid;
    gTapPID = pid;
    aether_atomic_store(&st->tapHelperPid, (uint32_t)child);
    AetherLogDaemon(@"[tap] root helper running (helper pid %d, target %d)",
                    (int)child, (int)pid);
    return 0;
}

extern "C" void AetherKernelLaneStopRootHelper(void) {
    if (gHelperPID <= 0) return;
    pid_t child = gHelperPID;
    gHelperPID = 0;
    gHelperTargetPID = 0;

    AetherSharedState *st = AetherGetSharedState();
    bool privileged = (geteuid() == 0);

    // 1 — ask the helper to leave through shared memory.  This is the only
    //     channel that works when we are the uid-501 app: kill() from uid 501
    //     to a uid-0 process fails with EPERM, which is exactly why 4.0.1
    //     helpers survived "Stop" until their parent died.
    if (st) aether_atomic_store(&st->tapStopRequest, 1u);

    bool gone = false;
    for (int i = 0; i < 30; i++) {          // ~1.5 s
        usleep(50000);
        if (kill(child, 0) != 0 && errno != EPERM) { gone = true; break; }
    }

    // 2 — still alive?  Signal it.  Only a root process can; otherwise ask a
    //     short-lived root helper to do it for us.
    if (!gone) {
        if (privileged) {
            kill(child, SIGTERM);
        } else {
            NSString *out = nil;
            AetherRunAsRootVerb(@[ @"kill", [NSString stringWithFormat:@"%d", (int)child] ], &out);
        }
        for (int i = 0; i < 20; i++) {
            usleep(50000);
            if (kill(child, 0) != 0 && errno != EPERM) { gone = true; break; }
        }
    }

    // 3 — last resort (only effective when we are root).
    if (!gone) {
        kill(child, SIGKILL);
        int status = 0;
        waitpid(child, &status, 0);
    }

    if (st) {
        aether_atomic_store(&st->tapHelperPid, 0u);
        aether_atomic_store(&st->tapStopRequest, 0u);
    }
    AetherLogDaemon(@"[tap] root helper stopped (was pid %d, graceful=%d)",
                    (int)child, gone ? 1 : 0);
}

extern "C" int AetherBpfTapMain(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc < 2) return 2;
        pid_t target = (pid_t)atoi(argv[1]);
        bool  primary = (argc > 2) ? (atoi(argv[2]) != 0) : true;
        if (target <= 0) return 2;

        uid_t euid = geteuid();
        AetherLogDaemonSync(@"[bftap] start target=%d primary=%d euid=%u",
                            (int)target, primary ? 1 : 0, (unsigned)euid);
        if (euid != 0) {
            AetherLogDaemonSync(@"[bftap] not root — /dev/bpf and proc_pidfdinfo would both fail");
            return 77;
        }

        // One tap per device: if another helper (app or HUD) already holds the
        // lock, it is already capturing this target, so exit successfully.
        int lockFd = open(AETHER_BFTAP_LOCK, O_RDWR | O_CREAT, 0666);
        if (lockFd >= 0) {
            if (flock(lockFd, LOCK_EX | LOCK_NB) != 0) {
                close(lockFd);
                AetherLogDaemonSync(@"[bftap] another helper is already capturing — exiting");
                return 0;
            }
        }

        signal(SIGTERM, AetherBpfTapSignal);
        signal(SIGINT,  AetherBpfTapSignal);
        signal(SIGHUP,  AetherBpfTapSignal);
        signal(SIGPIPE, SIG_IGN);

        AetherSharedState *st = AetherGetSharedState();
        if (st) {
            aether_atomic_store(&st->daemonBuild, AETHER_BUILD_NUM);
            // The parent cannot signal us (uid 501 -> uid 0 is EPERM), so it
            // clears this flag on start and sets it to ask us to go away.
            aether_atomic_store(&st->tapStopRequest, 0u);
            aether_atomic_store(&st->tapHelperPid, (uint32_t)getpid());
        }

        char errBuf[256] = {0};
        int rc = AetherKernelLaneStart(target, primary, errBuf, sizeof(errBuf));
        if (rc != 0) {
            AetherLogDaemonSync(@"[bftap] tap start failed (%d): %s", rc, errBuf);
            if (lockFd >= 0) { flock(lockFd, LOCK_UN); close(lockFd); }
            return 3;
        }

        AetherLogDaemonSync(@"[bftap] capturing pid %d on %s",
                            (int)target,
                            AetherGetSharedState() ? AetherGetSharedState()->kernelTapInterface : "?");

        // Never outlive the process that asked for the tap: if the app or the
        // HUD daemon goes away, we would keep draining battery in the
        // background with nobody left to read the counters.
        pid_t parent = getppid();

        while (!gHelperStop) {
            usleep(250000);

            if (getppid() != parent) {
                AetherLogDaemonSync(@"[bftap] parent %d went away — stopping",
                                    (int)parent);
                break;
            }
            if (AetherGetSharedState() &&
                aether_atomic_load(&AetherGetSharedState()->tapStopRequest)) {
                AetherLogDaemonSync(@"[bftap] stop requested by the app");
                break;
            }
            // Stop as soon as the target is gone (as root, kill(pid,0) is
            // reliable for every process on the device).
            if (kill(target, 0) != 0 && errno == ESRCH) {
                AetherLogDaemonSync(@"[bftap] target %d exited", (int)target);
                break;
            }
        }

        AetherKernelLaneStop();
        {
            AetherSharedState *s2 = AetherGetSharedState();
            if (s2) {
                aether_atomic_store(&s2->tapHelperPid, 0u);
                aether_atomic_store(&s2->tapStopRequest, 0u);
                aether_atomic_store(&s2->tapFramesSeen, gFramesSeen);
                aether_atomic_store(&s2->tapFramesMatched, gFramesMatched);
            }
        }
        if (lockFd >= 0) { flock(lockFd, LOCK_UN); close(lockFd); }
        AetherLogDaemonSync(@"[bftap] exiting (seen=%u matched=%u)",
                            gFramesSeen, gFramesMatched);
        return 0;
    }
}
