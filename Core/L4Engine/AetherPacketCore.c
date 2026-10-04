//
//  AetherPacketCore.c
//  AetherNet — portable L3/L4 packet core (see AetherPacketCore.h)
//
//  Compiled on:
//    • iOS  — clang arm64, -x c -std=gnu11 (linked into AetherNet + payload)
//    • host — gcc/clang, tests/host harness (unit tests + traffic simulation)
//

#include "AetherPacketCore.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../headers/AetherNetShared.h"

// ===========================================================================
// 1. Tiny readers
// ===========================================================================
uint16_t AetherReadU16BE(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

uint32_t AetherIPv4MappedPrefix(const uint8_t addr[16]) {
    static const uint8_t mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
    return (memcmp(addr, mapped, 12) == 0) ? 1u : 0u;
}

static void AetherStoreIPv4Mapped(const uint8_t v4[4], uint8_t out[16]) {
    memset(out, 0, 12);
    out[10] = 0xFF;
    out[11] = 0xFF;
    memcpy(out + 12, v4, 4);
}

// ===========================================================================
// 2. Link layer + IP + TCP/UDP parsing
// ===========================================================================
static int AetherParseIPv4(const uint8_t *ip, size_t len, AetherParsedPacket *out) {
    if (len < 20) return -1;
    if ((ip[0] >> 4) != 4) return -2;

    size_t headerLen = (size_t)(ip[0] & 0x0F) * 4u;
    if (headerLen < 20 || headerLen > len) return -3;

    uint32_t totalLen = AetherReadU16BE(ip + 2);
    if (totalLen < headerLen) return -4;                 // bogus length
    uint32_t payloadLen = totalLen - (uint32_t)headerLen;
    if ((size_t)payloadLen > len - headerLen) {
        payloadLen = (uint32_t)(len - headerLen);        // snaplen truncated us
    }

    uint16_t frag = AetherReadU16BE(ip + 6);
    out->isFragment    = (uint8_t)((frag & 0x1FFF) != 0);
    out->moreFragments = (uint8_t)((frag & 0x2000) != 0);
    out->version    = 4;
    out->proto      = ip[9];
    out->ipTotalLen = totalLen;
    AetherStoreIPv4Mapped(ip + 12, out->srcAddr);
    AetherStoreIPv4Mapped(ip + 16, out->dstAddr);
    out->tcpFlags     = 0;
    out->srcPort      = 0;
    out->dstPort      = 0;
    out->l4HeaderLen  = 0;
    out->l4PayloadLen = 0;

    const uint8_t *l4 = ip + headerLen;

    if (out->proto == AETHER_IPPROTO_TCP) {
        if (payloadLen < 20) return -5;
        size_t dataOffset = (size_t)(l4[12] >> 4) * 4u;
        if (dataOffset < 20 || dataOffset > payloadLen) return -6;
        out->srcPort      = AetherReadU16BE(l4 + 0);
        out->dstPort      = AetherReadU16BE(l4 + 2);
        out->tcpFlags     = l4[13];
        out->l4HeaderLen  = (uint16_t)dataOffset;
        out->l4PayloadLen = (uint16_t)(payloadLen - dataOffset);
        return 0;
    }
    if (out->proto == AETHER_IPPROTO_UDP) {
        if (payloadLen < 8) return -7;
        uint16_t ulen = AetherReadU16BE(l4 + 4);
        size_t   body = (ulen >= 8 && ulen <= payloadLen)
                        ? (size_t)(ulen - 8u)
                        : (size_t)(payloadLen - 8u);
        out->srcPort      = AetherReadU16BE(l4 + 0);
        out->dstPort      = AetherReadU16BE(l4 + 2);
        out->l4HeaderLen  = 8;
        out->l4PayloadLen = (uint16_t)body;
        return 0;
    }
    return 0; // other protocol (ICMP, ESP, …) — counted, not parsed further
}

#define AETHER_IPV6_HOPOPTS 0
#define AETHER_IPV6_ROUTING 43
#define AETHER_IPV6_FRAG    44
#define AETHER_IPV6_ESP     50
#define AETHER_IPV6_AH      51
#define AETHER_IPV6_NONE    59
#define AETHER_IPV6_DSTOPTS 60
#define AETHER_IPV6_MOBILITY 135

static int AetherParseIPv6(const uint8_t *ip, size_t len, AetherParsedPacket *out) {
    if (len < 40) return -1;
    if ((ip[0] >> 4) != 6) return -2;

    uint32_t payloadLen = AetherReadU16BE(ip + 4);
    size_t   available  = len - 40;
    if (payloadLen == 0 || payloadLen > available) {
        payloadLen = (uint32_t)available;   // jumbogram / snaplen truncation
    }

    uint8_t  next = ip[6];
    size_t   off  = 40;
    size_t   remaining = payloadLen;

    out->version    = 6;
    out->proto      = 0;
    out->ipTotalLen = payloadLen;
    memcpy(out->srcAddr, ip + 8, 16);
    memcpy(out->dstAddr, ip + 24, 16);
    out->tcpFlags     = 0;
    out->srcPort      = 0;
    out->dstPort      = 0;
    out->l4HeaderLen  = 0;
    out->l4PayloadLen = 0;
    out->isFragment   = 0;
    out->moreFragments = 0;

    // Walk extension headers (bounded so a hostile packet cannot spin)
    for (int hops = 0; hops < 8; hops++) {
        switch (next) {
            case AETHER_IPV6_HOPOPTS:
            case AETHER_IPV6_ROUTING:
            case AETHER_IPV6_DSTOPTS:
            case AETHER_IPV6_MOBILITY: {
                if (remaining < 8) return -3;
                size_t extLen = ((size_t)ip[off + 1] + 1u) * 8u;
                if (extLen > remaining) return -4;
                next = ip[off];
                off += extLen;
                remaining -= extLen;
                break;
            }
            case AETHER_IPV6_FRAG: {
                if (remaining < 8) return -5;
                uint16_t fo = (uint16_t)((AetherReadU16BE(ip + off + 2) & 0xFFF8) >> 3);
                out->isFragment    = (uint8_t)(fo != 0);
                out->moreFragments = (uint8_t)((ip[off + 3] & 0x01) != 0);
                size_t extLen = 8;
                next = ip[off];
                off += extLen;
                remaining -= extLen;
                break;
            }
            case AETHER_IPV6_AH: {
                if (remaining < 8) return -6;
                size_t extLen = ((size_t)ip[off + 1] + 2u) * 4u;
                if (extLen > remaining) return -7;
                next = ip[off];
                off += extLen;
                remaining -= extLen;
                break;
            }
            case AETHER_IPV6_ESP:
            case AETHER_IPV6_NONE:
                return 0;                 // encrypted / no upper layer
            default:
                goto l4_done;
        }
    }
    return -8; // too many extension headers

l4_done:
    out->proto = next;
    const uint8_t *l4 = ip + off;

    if (next == AETHER_IPPROTO_TCP) {
        if (remaining < 20) return -9;
        size_t dataOffset = (size_t)(l4[12] >> 4) * 4u;
        if (dataOffset < 20 || dataOffset > remaining) return -10;
        out->srcPort      = AetherReadU16BE(l4 + 0);
        out->dstPort      = AetherReadU16BE(l4 + 2);
        out->tcpFlags     = l4[13];
        out->l4HeaderLen  = (uint16_t)dataOffset;
        out->l4PayloadLen = (uint16_t)(remaining - dataOffset);
        return 0;
    }
    if (next == AETHER_IPPROTO_UDP) {
        if (remaining < 8) return -11;
        uint16_t ulen = AetherReadU16BE(l4 + 4);
        size_t   body = (ulen >= 8 && ulen <= remaining) ? (size_t)(ulen - 8u)
                                                         : (remaining - 8u);
        out->srcPort      = AetherReadU16BE(l4 + 0);
        out->dstPort      = AetherReadU16BE(l4 + 2);
        out->l4HeaderLen  = 8;
        out->l4PayloadLen = (uint16_t)body;
        return 0;
    }
    return 0;
}

int AetherParseLinkFrame(const uint8_t *frame, size_t len, int dlt,
                         AetherParsedPacket *out) {
    if (!frame || !out || len == 0) return -100;

    const uint8_t *p = frame;
    size_t remaining = len;

    switch (dlt) {
        case AETHER_DLT_EN10MB: {
            if (remaining < 14) return -101;
            uint16_t ethertype = AetherReadU16BE(p + 12);
            p += 14;
            remaining -= 14;
            // VLAN / QinQ unwrapping (802.1ad + 802.1q)
            for (int i = 0; i < 2; i++) {
                if (ethertype == AETHER_ETHERTYPE_VLAN ||
                    ethertype == AETHER_ETHERTYPE_QINQ) {
                    if (remaining < 4) return -102;
                    ethertype = AetherReadU16BE(p + 2);
                    p += 4;
                    remaining -= 4;
                } else {
                    break;
                }
            }
            if (ethertype == AETHER_ETHERTYPE_IPV4) {
                return AetherParseIPv4(p, remaining, out);
            }
            if (ethertype == AETHER_ETHERTYPE_IPV6) {
                return AetherParseIPv6(p, remaining, out);
            }
            return -103; // ARP / unsupported ethertype
        }
        case AETHER_DLT_NULL:
        case AETHER_DLT_LOOP: {
            if (remaining < 4) return -104;
            p += 4;
            remaining -= 4;
            break;
        }
        case AETHER_DLT_RAW:
        default:
            break; // assume raw IP; fall through to version sniffing
    }

    if (remaining == 0) return -105;
    switch (p[0] >> 4) {
        case 4:  return AetherParseIPv4(p, remaining, out);
        case 6:  return AetherParseIPv6(p, remaining, out);
        default: return -106;
    }
}

const char *AetherFormatEndpoint(const AetherParsedPacket *p, int which,
                                 char *buf, size_t bufLen) {
    if (!p || !buf || bufLen < 8) return "";
    const uint8_t *addr = (which == 0) ? p->srcAddr : p->dstAddr;
    uint16_t       port = (which == 0) ? p->srcPort : p->dstPort;

    char host[INET6_ADDRSTRLEN];
    host[0] = '\0';
    if (p->version == 4 || AetherIPv4MappedPrefix(addr)) {
        struct in_addr a;
        memcpy(&a, addr + 12, 4);
        inet_ntop(AF_INET, &a, host, sizeof(host));
    } else {
        inet_ntop(AF_INET6, addr, host, sizeof(host));
    }
    snprintf(buf, bufLen, "%s:%u", host, port);
    return buf;
}

// ===========================================================================
// 3. Port set
// ===========================================================================
void AetherPortSetClear(AetherPortSet *set) {
    if (!set) return;
    set->count = 0;
    set->overflow = 0;
}

bool AetherPortSetAdd(AetherPortSet *set, uint16_t port) {
    if (!set || port == 0) return false;
    if (AetherPortSetContains(set, port)) return true;
    if (set->count >= AETHER_PORT_SET_CAPACITY) {
        set->overflow++;
        return false;
    }
    set->ports[set->count++] = port;
    return true;
}

bool AetherPortSetContains(const AetherPortSet *set, uint16_t port) {
    if (!set || port == 0) return false;
    for (uint32_t i = 0; i < set->count; i++) {
        if (set->ports[i] == port) return true;
    }
    return false;
}

bool AetherClassifyDirection(const AetherParsedPacket *pkt,
                             const AetherPortSet *localPorts,
                             bool *outIsTX) {
    if (!pkt || !localPorts || !outIsTX) return false;

    bool srcIsOurs = AetherPortSetContains(localPorts, pkt->srcPort);
    bool dstIsOurs = AetherPortSetContains(localPorts, pkt->dstPort);

    // Loopback / self-talk: both ends are ours → call it TX (upload).
    if (srcIsOurs && dstIsOurs) { *outIsTX = true;  return true; }
    if (srcIsOurs)              { *outIsTX = true;  return true; }
    if (dstIsOurs)              { *outIsTX = false; return true; }
    return false;
}

// ===========================================================================
// 4. Flow table
// ===========================================================================
struct AetherFlowTable {
    AetherFlowEntry *entries;
    uint8_t         *used;
    uint32_t         capacity;
    uint32_t         count;
};

AetherFlowTable *AetherFlowTableCreate(uint32_t capacity) {
    if (capacity == 0) capacity = 512;
    AetherFlowTable *t = (AetherFlowTable *)calloc(1, sizeof(AetherFlowTable));
    if (!t) return NULL;
    t->capacity = capacity;
    t->entries  = (AetherFlowEntry *)calloc(capacity, sizeof(AetherFlowEntry));
    t->used     = (uint8_t *)calloc(capacity, 1);
    if (!t->entries || !t->used) {
        free(t->entries); free(t->used); free(t);
        return NULL;
    }
    return t;
}

void AetherFlowTableDestroy(AetherFlowTable *table) {
    if (!table) return;
    free(table->entries);
    free(table->used);
    free(table);
}

void AetherFlowTableReset(AetherFlowTable *table) {
    if (!table) return;
    memset(table->entries, 0, sizeof(AetherFlowEntry) * table->capacity);
    memset(table->used, 0, table->capacity);
    table->count = 0;
}

uint32_t AetherFlowTableCount(const AetherFlowTable *table) {
    return table ? table->count : 0;
}

static uint32_t AetherFlowHash(uint8_t proto, uint8_t af,
                               uint16_t localPort, uint16_t remotePort,
                               const uint8_t remoteAddr[16]) {
    uint32_t h = 2166136261u;
#define AETHER_HASH_BYTE(b) do { h ^= (uint32_t)(b); h *= 16777619u; } while (0)
    AETHER_HASH_BYTE(proto);
    AETHER_HASH_BYTE(af);
    AETHER_HASH_BYTE(localPort & 0xFF);
    AETHER_HASH_BYTE(localPort >> 8);
    AETHER_HASH_BYTE(remotePort & 0xFF);
    AETHER_HASH_BYTE(remotePort >> 8);
    for (int i = 0; i < 16; i++) AETHER_HASH_BYTE(remoteAddr[i]);
#undef AETHER_HASH_BYTE
    return h;
}

static bool AetherFlowMatches(const AetherFlowEntry *e, uint8_t proto, uint8_t af,
                              uint16_t localPort, uint16_t remotePort,
                              const uint8_t remoteAddr[16]) {
    return e->proto == proto && e->af == af &&
           e->localPort == localPort && e->remotePort == remotePort &&
           memcmp(e->remoteAddr, remoteAddr, 16) == 0;
}

int32_t AetherFlowTableRecord(AetherFlowTable *table,
                              const AetherParsedPacket *pkt,
                              bool isTX,
                              uint64_t wireBytes,
                              uint64_t nowMs) {
    if (!table || !pkt) return -1;
    if (pkt->proto != AETHER_IPPROTO_TCP && pkt->proto != AETHER_IPPROTO_UDP) {
        return -1; // we only track L4 flows
    }

    uint8_t af = (pkt->version == 4) ? AF_INET : AF_INET6;
    uint16_t localPort  = isTX ? pkt->srcPort : pkt->dstPort;
    uint16_t remotePort = isTX ? pkt->dstPort : pkt->srcPort;
    const uint8_t *remoteAddr = isTX ? pkt->dstAddr : pkt->srcAddr;

    uint32_t mask = table->capacity - 1;
    uint32_t idx  = AetherFlowHash(pkt->proto, af, localPort, remotePort, remoteAddr) & mask;

    for (uint32_t probe = 0; probe < table->capacity; probe++) {
        uint32_t slot = (idx + probe) & mask;
        if (!table->used[slot]) {
            AetherFlowEntry *e = &table->entries[slot];
            e->proto      = pkt->proto;
            e->af         = af;
            e->localPort  = localPort;
            e->remotePort = remotePort;
            memcpy(e->remoteAddr, remoteAddr, 16);
            e->rxPackets = e->rxBytes = e->txPackets = e->txBytes = 0;
            table->used[slot] = 1;
            table->count++;
            e->lastSeenMs = nowMs;
            if (isTX) { e->txPackets++; e->txBytes += wireBytes; }
            else      { e->rxPackets++; e->rxBytes += wireBytes; }
            return (int32_t)slot;
        }
        if (AetherFlowMatches(&table->entries[slot], pkt->proto, af,
                              localPort, remotePort, remoteAddr)) {
            AetherFlowEntry *e = &table->entries[slot];
            e->lastSeenMs = nowMs;
            if (isTX) { e->txPackets++; e->txBytes += wireBytes; }
            else      { e->rxPackets++; e->rxBytes += wireBytes; }
            return (int32_t)slot;
        }
    }
    return -1; // full
}

static int AetherFlowCompareByRecency(const void *a, const void *b) {
    const AetherFlowEntry *ea = (const AetherFlowEntry *)a;
    const AetherFlowEntry *eb = (const AetherFlowEntry *)b;
    if (ea->lastSeenMs == eb->lastSeenMs) return 0;
    return (ea->lastSeenMs > eb->lastSeenMs) ? -1 : 1;
}

uint32_t AetherFlowTableSnapshot(const AetherFlowTable *table,
                                 AetherFlowEntry *outEntries,
                                 uint32_t maxEntries) {
    if (!table || !outEntries || maxEntries == 0) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < table->capacity && n < maxEntries; i++) {
        if (table->used[i]) outEntries[n++] = table->entries[i];
    }
    if (n > 1) {
        qsort(outEntries, n, sizeof(AetherFlowEntry), AetherFlowCompareByRecency);
    }
    return n;
}

// ===========================================================================
// 4b. BPF buffer walking
// ===========================================================================
static uint32_t AetherReadU32LE(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint64_t AetherReadU64LE(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

// A plausible Unix seconds value: 2001-09-09 … 2128.  Used only to tell a
// 64 bit timeval apart from a 32 bit one, so the window can be generous.
static bool AetherPlausibleSeconds(uint64_t sec) {
    return sec >= 1000000000ULL && sec <= 5000000000ULL;
}

static bool AetherFramingLooksSane(const uint8_t *buffer, size_t len, uint32_t tsSize) {
    // Minimum record: timestamp + caplen + datalen + hdrlen.
    size_t minHdr = (size_t)tsSize + 10u;
    if (!buffer || len < minHdr) return false;
    uint32_t caplen = AetherReadU32LE(buffer + tsSize);
    uint32_t datalen = AetherReadU32LE(buffer + tsSize + 4u);
    uint32_t hdrlen = (uint32_t)(buffer[tsSize + 8] | (buffer[tsSize + 9] << 8));
    if (caplen == 0 || caplen > 262144u) return false;
    if (datalen < caplen) return false;
    if (hdrlen < (size_t)tsSize + 10u || hdrlen > 4096u) return false;
    if ((size_t)hdrlen + (size_t)caplen > len) return false;
    return true;
}

AetherBPFFraming AetherBPFDetectFraming(const uint8_t *buffer, size_t len) {
    AetherBPFFraming f;
    // Conservative default: the layout every BSD textbook shows.
    f.tsSize  = AETHER_BPF_TS_SIZE_64;
    f.hdrSize = AETHER_BPF_HDR_SIZE_64TS;
    if (!buffer || len < 20u) return f;

    // 16 byte timeval: a 64 bit seconds field sits at offset 0.
    if (AetherPlausibleSeconds(AetherReadU64LE(buffer)) &&
        AetherFramingLooksSane(buffer, len, AETHER_BPF_TS_SIZE_64)) {
        return f;
    }
    // 8 byte timeval32 (what LP64 Darwin actually writes): seconds at 0,
    // microseconds at 4.
    if (AetherPlausibleSeconds((uint64_t)AetherReadU32LE(buffer)) &&
        AetherFramingLooksSane(buffer, len, AETHER_BPF_TS_SIZE_32)) {
        f.tsSize  = AETHER_BPF_TS_SIZE_32;
        f.hdrSize = AETHER_BPF_HDR_SIZE_32TS;
    }
    return f;
}

void AetherBPFDecodeHeader(const uint8_t *hdr, size_t hdrLen,
                           AetherBPFFraming framing, AetherBPFMeta *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->tsSize = framing.tsSize;
    out->hdrLen = (uint32_t)hdrLen;

    size_t extMin = (size_t)AETHER_BPF_EXT_HDR_MIN(framing.tsSize);
    out->extHdr = (hdrLen >= extMin);
    if (!out->extHdr) return;

    out->isTX = (hdr[AETHER_BPF_EXT_FLAGS_OFF(framing.tsSize)] &
                 AETHER_BPF_EXT_DIR_OUT) != 0;
    pid_t pid = 0;
    memcpy(&pid, hdr + AETHER_BPF_EXT_PID_OFF(framing.tsSize), sizeof(pid));
    out->pid    = pid;
    out->hasPID = (pid > 0);
}

int AetherBPFIterateWithHeader(const uint8_t *buffer, size_t len, void *ctx,
                               AetherFrameMetaFn fn) {
    if (!buffer || !fn) return 0;

    AetherBPFFraming framing = AetherBPFDetectFraming(buffer, len);
    uint32_t ts = framing.tsSize;
    size_t  offset = 0;
    int     frames = 0;

    /* 4.1.2 — the record walk must NEVER let `offset` run past `len`.
       The kernel pads every record up to a 4-byte boundary, so for the LAST
       record of a batch WORDALIGN(hdrlen + caplen) can be up to 3 bytes more
       than the bytes actually present. The old loop added that padding and
       then evaluated `len - offset` as size_t: once offset > len the
       subtraction wraps to ~2^64, both the loop condition and the bounds
       guard pass, and `buffer + offset` becomes a wild pointer (SIGSEGV at
       the next caplen load). Every step below is expressed in terms of
       `remaining`, which is only ever computed while offset <= len. */
    while (offset < len) {
        size_t remaining = len - offset;
        if (remaining < (size_t)ts + 10u) break;

        const uint8_t *hdr = buffer + offset;

        uint32_t caplen  = AetherReadU32LE(hdr + ts);
        uint32_t datalen = AetherReadU32LE(hdr + ts + 4u);
        uint16_t hdrlen  = (uint16_t)(((uint16_t)hdr[ts + 8]) | ((uint16_t)hdr[ts + 9] << 8));

        (void)datalen;
        if (hdrlen < (uint32_t)ts + 10u) hdrlen = (uint16_t)((uint32_t)ts + 10u);
        if (caplen == 0 ||
            (size_t)hdrlen > remaining ||
            (size_t)caplen > remaining - (size_t)hdrlen) break;

        AetherBPFMeta meta;
        AetherBPFDecodeHeader(hdr, (size_t)hdrlen, framing, &meta);
        fn(ctx, &meta, hdr + hdrlen, (size_t)caplen);
        frames++;

        size_t used = (size_t)hdrlen + (size_t)caplen;
        size_t step = AETHER_BPF_WORDALIGN(used);
        if (step <= used) step = used;              /* paranoia: never go backwards */
        if (step >= remaining) break;               /* last record (incl. tail padding) */
        offset += step;
    }
    return frames;
}

// The header-less walk is the one the unit tests drive: keep it as a thin
// adapter so both share exactly one implementation of the stepping arithmetic.
typedef struct {
    void         *ctx;
    AetherFrameFn fn;
} AetherFrameAdapter;

static void AetherFrameAdapterFn(void *ctx, const AetherBPFMeta *meta,
                                 const uint8_t *frame, size_t caplen) {
    (void)meta;
    AetherFrameAdapter *a = (AetherFrameAdapter *)ctx;
    a->fn(a->ctx, frame, caplen);
}

int AetherBPFIterate(const uint8_t *buffer, size_t len, void *ctx, AetherFrameFn fn) {
    if (!fn) return 0;
    AetherFrameAdapter adapter;
    adapter.ctx = ctx;
    adapter.fn  = fn;
    return AetherBPFIterateWithHeader(buffer, len, &adapter, AetherFrameAdapterFn);
}

// ===========================================================================
// 5. Policy engine
// ===========================================================================
void AetherPolicyLoad(AetherPolicy *policy, const void *sharedState) {
    if (!policy) return;
    memset(policy, 0, sizeof(*policy));
    if (!sharedState) return;

    const AetherSharedState *st = (const AetherSharedState *)sharedState;
    policy->active         = aether_atomic_load(&st->interceptionActive);
    policy->direction      = aether_atomic_load(&st->direction);
    policy->protocolFilter = aether_atomic_load(&st->protocolFilter);
    policy->mode           = aether_atomic_load(&st->interceptMode);
    policy->captureRatioPct = aether_atomic_load(&st->captureRatioPercent);
    policy->rxRatioPct      = aether_atomic_load(&st->downloadHoldPercent);
    policy->txRatioPct      = aether_atomic_load(&st->uploadHoldPercent);
    policy->latencyMs       = aether_atomic_load(&st->simulatedLatencyMs);
    policy->jitterMs        = aether_atomic_load(&st->simulatedJitterMs);
    policy->bandwidthKbps   = aether_atomic_load(&st->bandwidthLimitKbps);
    policy->duplicatePct    = aether_atomic_load(&st->duplicatePacketPercent);
}

uint32_t AetherPolicyEffectiveRatio(const AetherPolicy *policy, bool isTX) {
    if (!policy) return 0;
    uint32_t master = policy->captureRatioPct > 100 ? 100 : policy->captureRatioPct;
    uint32_t dir    = isTX ? policy->txRatioPct : policy->rxRatioPct;
    if (dir > 100) dir = 100;
    uint32_t eff = (master * dir) / 100u;
    return eff > 100 ? 100 : eff;
}

AetherVerdict AetherPolicyDecide(const AetherPolicy *policy,
                                 bool isTX, bool isTCP, bool isUDP,
                                 uint32_t roll,
                                 uint32_t *outRatio,
                                 bool *outTamper) {
    if (outTamper) *outTamper = false;
    if (!policy || !policy->active) {
        if (outRatio) *outRatio = 0;
        return AetherVerdictPass;
    }

    // --- Direction filter -------------------------------------------------
    if (policy->direction == AetherDirectionDownload && isTX)  {
        if (outRatio) *outRatio = 0;
        return AetherVerdictPass;
    }
    if (policy->direction == AetherDirectionUpload && !isTX) {
        if (outRatio) *outRatio = 0;
        return AetherVerdictPass;
    }

    // --- Protocol filter --------------------------------------------------
    if (policy->protocolFilter == AetherProtoUDPOnly && !isUDP) {
        if (outRatio) *outRatio = 0;
        return AetherVerdictPass;
    }
    if (policy->protocolFilter == AetherProtoTCPOnly && !isTCP) {
        if (outRatio) *outRatio = 0;
        return AetherVerdictPass;
    }

    uint32_t eff = AetherPolicyEffectiveRatio(policy, isTX);
    if (outRatio) *outRatio = eff;

    switch (policy->mode) {
        case AetherModeObserve:
            // Observe-only: everything passes untouched, telemetry still counts.
            return AetherVerdictPass;

        case AetherModeDelayJitter:
            // Network conditioning applies to every matching packet,
            // independent of the capture ratio.
            return AetherVerdictDelay;

        case AetherModeCorruptTamper: {
            bool hit = (roll % 100u) < eff;
            if (outTamper) *outTamper = hit;
            return AetherVerdictPass;
        }

        case AetherModeHoldQueue:
        case AetherModeDropPacket: {
            bool hit = (roll % 100u) < eff;
            if (!hit) return AetherVerdictPass;
            return (policy->mode == AetherModeHoldQueue) ? AetherVerdictHold
                                                         : AetherVerdictDrop;
        }
        default:
            return AetherVerdictPass;
    }
}

uint32_t AetherPolicyDelayUs(const AetherPolicy *policy,
                             size_t bytes,
                             uint32_t jitterRoll) {
    if (!policy) return 0;

    uint64_t us = (uint64_t)policy->latencyMs * 1000ULL;
    if (policy->jitterMs > 0) {
        us += (uint64_t)(jitterRoll % ((uint32_t)policy->jitterMs * 1000u));
    }
    if (policy->bandwidthKbps > 0 && bytes > 0) {
        // Serialisation delay = bits / kbps → microseconds
        us += ((uint64_t)bytes * 8000ULL) / (uint64_t)policy->bandwidthKbps;
    }
    if (us > AETHER_MAX_DELAY_US) us = AETHER_MAX_DELAY_US;
    return (uint32_t)us;
}
