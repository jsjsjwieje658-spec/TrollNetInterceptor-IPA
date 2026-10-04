//
//  AetherPacketCore.h
//  AetherNet — portable L3/L4 packet core (NO ObjC, NO Darwin SPI)
//
//  WHY THIS FILE EXISTS
//  --------------------
//  Everything that has to reason about a TCP/UDP packet — the BPF kernel tap
//  lane, the in-process hook lane, the flow table, the policy engine and the
//  host-side test harness — belongs here, written in portable C11 so that it
//  can be compiled and unit-tested on the build host (Linux) as well as on
//  iOS.  Nothing in this file may reference UIKit, Foundation, libproc,
//  mach, or any Apple private SPI.
//
//  The iOS-only glue (BPF device, proc_pidfdinfo, pfctl, posix_spawn persona)
//  lives in Core/L4Engine/AetherKernelLane.mm and calls into this core.
//

#ifndef AetherPacketCore_h
#define AetherPacketCore_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>   // pid_t

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// 1. Link-layer types we know how to strip (DLT values, <net/bpf.h>)
// ---------------------------------------------------------------------------
#define AETHER_DLT_NULL    0   /* BSD loopback — 4 byte address family */
#define AETHER_DLT_EN10MB  1   /* Ethernet (en0 / awdl0 / ap1) */
#define AETHER_DLT_RAW     12  /* raw IP (pdp_ip0 cellular, utun, ipsec) */
#define AETHER_DLT_LOOP    108 /* OpenBSD loopback */

#define AETHER_IPPROTO_TCP 6
#define AETHER_IPPROTO_UDP 17

// VLAN / protocol Ethertypes
#define AETHER_ETHERTYPE_IPV4 0x0800
#define AETHER_ETHERTYPE_IPV6 0x86DD
#define AETHER_ETHERTYPE_VLAN 0x8100
#define AETHER_ETHERTYPE_QINQ 0x88A8

#define AETHER_TCP_FIN 0x01
#define AETHER_TCP_SYN 0x02
#define AETHER_TCP_RST 0x04
#define AETHER_TCP_PSH 0x08
#define AETHER_TCP_ACK 0x10

// ---------------------------------------------------------------------------
// 2. Parsed L3/L4 view of one packet
// ---------------------------------------------------------------------------
typedef struct {
    uint8_t  version;        // 4 or 6 (0 = unparsed)
    uint8_t  proto;          // AETHER_IPPROTO_TCP / _UDP / other
    uint8_t  srcAddr[16];    // network byte order, v4-mapped for IPv4
    uint8_t  dstAddr[16];
    uint16_t srcPort;        // host byte order (0 if not TCP/UDP)
    uint16_t dstPort;
    uint32_t ipTotalLen;     // IPv4 total length / IPv6 payload length
    uint16_t l4HeaderLen;    // TCP data offset, or 8 for UDP
    uint16_t l4PayloadLen;   // bytes of payload carried after the L4 header
    uint8_t  tcpFlags;       // 0 for UDP
    uint8_t  isFragment;     // non-zero fragment offset
    uint8_t  moreFragments;
} AetherParsedPacket;

/// Strip the link header, then parse IPv4/IPv6 (incl. extension headers,
/// VLAN tags and fragments) and the TCP/UDP header.
/// Returns 0 on success, negative on a malformed / truncated / unsupported
/// frame.  `out` is only written on success.
int  AetherParseLinkFrame(const uint8_t *frame, size_t len, int dlt,
                          AetherParsedPacket *out);

/// Human readable "1.2.3.4:443" from a parsed packet endpoint.
/// `which` = 0 for source, 1 for destination.  Returns `buf`.
const char *AetherFormatEndpoint(const AetherParsedPacket *p, int which,
                                 char *buf, size_t bufLen);

// ---------------------------------------------------------------------------
// 3. Port set — the set of local ports owned by the target PID
//    (built out-of-process from proc_pidfdinfo(PROC_PIDFDSOCKETINFO) on iOS;
//     from /proc on the Linux test host)
// ---------------------------------------------------------------------------
#define AETHER_PORT_SET_CAPACITY 512

typedef struct {
    uint16_t ports[AETHER_PORT_SET_CAPACITY];
    uint32_t count;
    uint32_t overflow;      // ports we could not store (set is full)
} AetherPortSet;

void     AetherPortSetClear(AetherPortSet *set);
bool     AetherPortSetAdd(AetherPortSet *set, uint16_t port);
bool     AetherPortSetContains(const AetherPortSet *set, uint16_t port);

/// Classify a captured packet against the target's local ports.
/// A packet belongs to the target when one of its endpoints is a local port
/// the target owns: source ⇒ TX (upload), destination ⇒ RX (download).
/// Returns true when the packet belongs to the target; *outIsTX is then set.
bool AetherClassifyDirection(const AetherParsedPacket *pkt,
                             const AetherPortSet *localPorts,
                             bool *outIsTX);

// ---------------------------------------------------------------------------
// 4. Flow table (5-tuple → counters), open addressing, fixed capacity
// ---------------------------------------------------------------------------
typedef struct AetherFlowTable AetherFlowTable;

typedef struct {
    uint8_t  proto;
    uint8_t  af;                 // AF_INET / AF_INET6
    uint16_t localPort;
    uint16_t remotePort;
    uint8_t  remoteAddr[16];
    uint64_t rxPackets;
    uint64_t rxBytes;
    uint64_t txPackets;
    uint64_t txBytes;
    uint64_t lastSeenMs;
} AetherFlowEntry;

AetherFlowTable *AetherFlowTableCreate(uint32_t capacity);
void             AetherFlowTableDestroy(AetherFlowTable *table);
void             AetherFlowTableReset(AetherFlowTable *table);
uint32_t         AetherFlowTableCount(const AetherFlowTable *table);

/// Record one packet.  `isTX` comes from AetherClassifyDirection.
/// Returns the (stable) slot index of the flow, or -1 when the table is full.
int32_t AetherFlowTableRecord(AetherFlowTable *table,
                              const AetherParsedPacket *pkt,
                              bool isTX,
                              uint64_t wireBytes,
                              uint64_t nowMs);

/// Snapshot up to `maxEntries` flows (sorted by most recent activity).
uint32_t AetherFlowTableSnapshot(const AetherFlowTable *table,
                                 AetherFlowEntry *outEntries,
                                 uint32_t maxEntries);

// ---------------------------------------------------------------------------
// 4b. BPF buffer walking
//
// read() on a /dev/bpfN device returns a batch:
//
//     [ struct bpf_hdr ][ frame ][ padding ][ struct bpf_hdr ][ frame ]…
//
// where bh_hdrlen is the *padded* header length and the step to the next
// record is BPF_WORDALIGN(hdrlen + caplen).  Getting this arithmetic wrong
// silently corrupts the stream, so it lives here where it can be unit tested
// on the build host instead of on a phone.
// ---------------------------------------------------------------------------
// sizeof(struct bpf_hdr) depends on how wide bh_tstamp is — and Apple makes it
// narrower than the structs suggest:
//
//   #if defined(__LP64__)
//   #define BPF_TIMEVAL timeval32      // { int32 tv_sec; int32 tv_usec; } = 8
//   #else
//   #define BPF_TIMEVAL timeval        // 16 on LP64 hosts
//   #endif
//                                                    (bsd/net/bpf.h, xnu-8792.81.2)
//
// A 4.0.5 device log proved it: the first record read off an iOS 16.5 phone was
//   c2abc16a 23320d00  97000000 97000000  3e00  00 00  00000000 …
//   ^sec     ^usec     ^caplen  ^datalen  ^hdrlen ^fl ^pid
// i.e. caplen sits at 8, not 16.  Hard-coding 28 made the walker read
// bh_hdrlen (62) as a capture length and reject every single record, so the
// framing is now detected from the timestamp at run time.
#define AETHER_BPF_TS_SIZE_32   8u   // timeval32 (LP64 Darwin / iOS)
#define AETHER_BPF_TS_SIZE_64   16u  // struct timeval
#define AETHER_BPF_HDR_SIZE_32TS 18u // SIZEOF_BPF_HDR with an 8 byte timestamp
#define AETHER_BPF_HDR_SIZE_64TS 28u // …with a 16 byte timestamp
#define AETHER_BPF_HDR_SIZE     AETHER_BPF_HDR_SIZE_64TS
#define AETHER_BPF_WORDALIGN(x) (((x) + 3u) & ~((size_t)3u))

// Every field after bh_tstamp sits at a fixed offset from the end of the
// timestamp, so one number describes the whole framing.
typedef struct {
    uint32_t tsSize;    // sizeof(bh_tstamp): 8 or 16
    uint32_t hdrSize;   // sizeof(struct bpf_hdr) for that timestamp
} AetherBPFFraming;

/// Detect the framing of a read() batch from its first record's timestamp.
AetherBPFFraming AetherBPFDetectFraming(const uint8_t *buffer, size_t len);

typedef void (*AetherFrameFn)(void *ctx, const uint8_t *frame, size_t caplen);

/// Walk one read() batch.  Returns the number of frames handed to `fn`.
int AetherBPFIterate(const uint8_t *buffer, size_t len, void *ctx, AetherFrameFn fn);

// ---------------------------------------------------------------------------
// Extended BPF header (XNU BIOCSEXTHDR / struct bpf_hdr_ext).
//
// With it turned on the kernel stamps every record with the PID and process
// name that own the flow, plus the direction — attribution stops being a
// guess based on the port inventory.  Layout from bsd/net/bpf.h
// (xnu-8792.81.2); the extra fields sit after the classic bpf_hdr prefix, and
// bh_hdrlen grows accordingly, so the walker only has to pass the header on.
// ---------------------------------------------------------------------------
// Offsets of the extra fields are relative to the END of bh_tstamp:
//   caplen +0, datalen +4, hdrlen +8, complen +10, flags +11, pid +12,
//   comm +16 (MAXCOMLEN+1 = 17), pktflags +33, trace_tag +34, svc +36,
//   flowid +40, unsent_bytes +44, unsent_snd +48 → sizeof = tsSize + 52.
// Checked against the device: tsSize 8 → pid @20, sizeof 60, and en0 reports
// bh_hdrlen 62 = BPF_WORDALIGN(14 + 60) - 14 (bpf_attach, bsd/net/bpf.c).
#define AETHER_BPF_EXT_PID_OFF(ts)    ((ts) + 12u)
#define AETHER_BPF_EXT_FLAGS_OFF(ts)  ((ts) + 11u)
#define AETHER_BPF_EXT_HDR_MIN(ts)    ((ts) + 52u)
#define AETHER_BPF_EXT_DIR_OUT        0x01u // BPF_HDR_EXT_FLAGS_DIR_OUT

/// What the kernel told us about one record.
typedef struct {
    uint32_t tsSize;    // framing in use
    uint32_t hdrLen;    // bh_hdrlen of this record
    pid_t    pid;       // bh_pid (0 = unknown)
    bool     hasPID;    // pid != 0
    bool     extHdr;    // the record carries the extended fields
    bool     isTX;      // BPF_HDR_EXT_FLAGS_DIR_OUT
} AetherBPFMeta;

typedef void (*AetherFrameMetaFn)(void *ctx,
                                  const AetherBPFMeta *meta,
                                  const uint8_t *frame, size_t caplen);

/// Walk a batch, handing the decoded record metadata to `fn`.
int AetherBPFIterateWithHeader(const uint8_t *buffer, size_t len, void *ctx,
                               AetherFrameMetaFn fn);

/// Decode one record header into `out` (framing is detected from the header).
void AetherBPFDecodeHeader(const uint8_t *hdr, size_t hdrLen,
                           AetherBPFFraming framing, AetherBPFMeta *out);

// ---------------------------------------------------------------------------
// 5. Policy engine — the single decision function shared by every lane
// ---------------------------------------------------------------------------
typedef enum {
    AetherVerdictPass  = 0,  // deliver now
    AetherVerdictDelay = 1,  // deliver after latency + jitter + bandwidth delay
    AetherVerdictHold  = 2,  // queue in user space, deliver on flush
    AetherVerdictDrop  = 3   // discard
} AetherVerdict;

typedef struct {
    bool     active;
    uint8_t  direction;        // AetherTrafficDirection
    uint8_t  protocolFilter;   // AetherProtocolFilter
    uint8_t  mode;             // AetherInterceptMode
    uint32_t captureRatioPct;  // 0..100 master
    uint32_t rxRatioPct;       // 0..100 download
    uint32_t txRatioPct;       // 0..100 upload
    uint32_t latencyMs;
    uint32_t jitterMs;
    uint32_t bandwidthKbps;    // 0 = unlimited
    uint32_t duplicatePct;     // 0..100 UDP duplication
} AetherPolicy;

/// Fill `policy` from the live shared state (NULL state ⇒ inactive policy).
void AetherPolicyLoad(AetherPolicy *policy, const void *sharedState);

/// Pure decision function.
///   `isTX`    true = upload (send side), false = download (recv side)
///   `isTCP` / `isUDP` come from the socket (hook lane) or the packet (tap)
///   `roll`    caller supplied random value in [0,100) — injected so the
///             decision stays deterministic under test
///   `outRatio`  optional, receives the effective capture ratio in [0,100]
///   `outTamper` optional, set when the payload should be bit-flipped
AetherVerdict AetherPolicyDecide(const AetherPolicy *policy,
                                 bool isTX, bool isTCP, bool isUDP,
                                 uint32_t roll,
                                 uint32_t *outRatio,
                                 bool *outTamper);

/// Effective probability (0..100) that a packet is selected for hold/drop.
uint32_t AetherPolicyEffectiveRatio(const AetherPolicy *policy, bool isTX);

/// Serialisation delay + latency + jitter, in microseconds.
/// `bytes` = payload size, `jitterRoll` = caller random in [0, jitterMs*1000).
/// Clamped to AETHER_MAX_DELAY_US so a bad config can never wedge a thread.
#define AETHER_MAX_DELAY_US 3000000u
uint32_t AetherPolicyDelayUs(const AetherPolicy *policy,
                             size_t bytes,
                             uint32_t jitterRoll);

// ---------------------------------------------------------------------------
// 6. Small helpers
// ---------------------------------------------------------------------------
uint16_t AetherReadU16BE(const uint8_t *p);
uint32_t AetherIPv4MappedPrefix(const uint8_t addr[16]); // 1 when ::ffff:x.y.z.w

#ifdef __cplusplus
}
#endif

#endif /* AetherPacketCore_h */
