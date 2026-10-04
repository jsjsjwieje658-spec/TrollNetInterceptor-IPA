//
//  AetherProcInfoLayout.h
//  AetherNet — XNU bsd/sys/proc_info.h layout, transcribed for the public SDK
//
//  Why this file exists
//  --------------------
//  Public iPhoneOS SDKs ship neither <sys/proc_info.h> nor <libproc.h>, so the
//  per-PID socket structures used by proc_pidfdinfo() have to be declared by
//  hand.  Getting one field wrong is fatal in a very quiet way: proc_pidfdinfo
//  returns sizeof(struct socket_fdinfo), the caller compares it against its own
//  sizeof, and on mismatch every socket is silently skipped — the tap then
//  reports "target has no INET TCP/UDP socket" for a process that is obviously
//  online (this is exactly what 4.0.0 did: struct socket_info begins with
//  soi_stat, which the hand-written version had dropped).
//
//  Everything below is transcribed verbatim from XNU bsd/sys/proc_info.h
//  (xnu-8792.81.2 — the iOS 16.x era) for the LP64 ABI.  It is plain C on
//  purpose, with no Foundation/UIKit includes, so tests/host can compile it on
//  Linux and assert the offsets with _Static_assert (see test_layout.c).
//

#ifndef AetherProcInfoLayout_h
#define AetherProcInfoLayout_h

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/un.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SOCK_MAXADDRLEN
#define SOCK_MAXADDRLEN 255              /* sys/socket.h */
#endif
#ifndef MAX_KCTL_NAME
#define MAX_KCTL_NAME   96               /* sys/kern_control.h */
#endif
#ifndef IF_NAMESIZE
#define IF_NAMESIZE     16
#endif

/* ---------------------------------------------------------------- fd list */
struct aether_proc_fdinfo {
    int32_t  proc_fd;
    uint32_t proc_fdtype;
};

/* ------------------------------------------------------- vinfo_stat (136B) */
struct aether_vinfo_stat {
    uint32_t vst_dev;
    uint16_t vst_mode;
    uint16_t vst_nlink;
    uint64_t vst_ino;
    uid_t    vst_uid;
    gid_t    vst_gid;
    int64_t  vst_atime;
    int64_t  vst_atimensec;
    int64_t  vst_mtime;
    int64_t  vst_mtimensec;
    int64_t  vst_ctime;
    int64_t  vst_ctimensec;
    int64_t  vst_birthtime;
    int64_t  vst_birthtimensec;
    off_t    vst_size;
    int64_t  vst_blocks;
    int32_t  vst_blksize;
    uint32_t vst_flags;
    uint32_t vst_gen;
    uint32_t vst_rdev;
    int64_t  vst_qspare[2];
};

/* --------------------------------------------------------- in_sockinfo (80B) */
struct aether_in4in6_addr {
    union {
        struct in_addr  ina_46;
        struct in6_addr ina_6;
    };
};

struct aether_in_sockinfo {
    int                      insi_fport;
    int                      insi_lport;
    uint64_t                 insi_gencnt;
    uint32_t                 insi_flags;
    uint32_t                 insi_flow;
    uint8_t                  insi_vflag;   /* INI_IPV4 = 0x1, INI_IPV6 = 0x2 */
    uint8_t                  insi_ip_ttl;
    uint32_t                 rfu_1;
    struct aether_in4in6_addr insi_faddr;
    struct aether_in4in6_addr insi_laddr;
    struct { u_char in4_tos; } insi_v4;
    struct {
        uint8_t  in6_hlim;
        int      in6_cksum;
        u_short  in6_ifindex;
        short    in6_hops;
    } insi_v6;
};

struct aether_tcp_sockinfo {
    struct aether_in_sockinfo tcpsi_ini;
    int                       tcpsi_state;
    int                       tcpsi_timer[4];   /* TSI_T_NTIMERS */
    int                       tcpsi_mss;
    uint32_t                  tcpsi_flags;
    uint32_t                  rfu_1;
    uint64_t                  tcpsi_tp;
};

/* The remaining union members are never read, but they decide the SIZE of
   soi_proto (un_sockinfo is by far the largest), and therefore the size the
   kernel returns.  They must be transcribed too. */
struct aether_un_sockinfo {
    uint64_t unsi_conn_so;
    uint64_t unsi_conn_pcb;
    union {
        struct sockaddr_un ua_sun;
        char               ua_dummy[SOCK_MAXADDRLEN];
    } unsi_addr;
    union {
        struct sockaddr_un ua_sun;
        char               ua_dummy[SOCK_MAXADDRLEN];
    } unsi_caddr;
};

struct aether_ndrv_info {
    uint32_t ndrvsi_if_family;
    uint32_t ndrvsi_if_unit;
    char     ndrvsi_if_name[IF_NAMESIZE];
};

struct aether_kern_event_info {
    uint32_t kesi_vendor_code_filter;
    uint32_t kesi_class_filter;
    uint32_t kesi_subclass_filter;
};

struct aether_kern_ctl_info {
    uint32_t kcsi_id;
    uint32_t kcsi_reg_unit;
    uint32_t kcsi_flags;
    uint32_t kcsi_recvbufsize;
    uint32_t kcsi_sendbufsize;
    uint32_t kcsi_unit;
    char     kcsi_name[MAX_KCTL_NAME];
};

struct aether_vsock_sockinfo {
    uint32_t local_cid;
    uint32_t local_port;
    uint32_t remote_cid;
    uint32_t remote_port;
};

/* ---------------------------------------------------------- sockbuf_info (20B) */
struct aether_sockbuf_info {
    uint32_t sbi_cc;
    uint32_t sbi_hiwat;
    uint32_t sbi_mbcnt;
    uint32_t sbi_mbmax;
    uint32_t sbi_lowat;
    short    sbi_flags;
    short    sbi_timeo;
};

/* ----------------------------------------------------------- socket_info (760B) */
struct aether_socket_info {
    struct aether_vinfo_stat soi_stat;           /* ← the field 4.0.0 forgot */
    uint64_t                 soi_so;
    uint64_t                 soi_pcb;
    int                      soi_type;           /* SOCK_STREAM / SOCK_DGRAM */
    int                      soi_protocol;       /* IPPROTO_TCP / IPPROTO_UDP */
    int                      soi_family;         /* AF_INET / AF_INET6 */
    short                    soi_options;
    short                    soi_linger;
    short                    soi_state;
    short                    soi_qlen;
    short                    soi_incqlen;
    short                    soi_qlimit;
    short                    soi_timeo;
    u_short                  soi_error;
    uint32_t                 soi_oobmark;
    struct aether_sockbuf_info soi_rcv;
    struct aether_sockbuf_info soi_snd;
    int                      soi_kind;           /* SOCKINFO_IN / SOCKINFO_TCP … */
    uint32_t                 rfu_1;
    union {
        struct aether_in_sockinfo     pri_in;
        struct aether_tcp_sockinfo    pri_tcp;
        struct aether_un_sockinfo     pri_un;
        struct aether_ndrv_info       pri_ndrv;
        struct aether_kern_event_info pri_kern_event;
        struct aether_kern_ctl_info   pri_kern_ctl;
        struct aether_vsock_sockinfo  pri_vsock;
    } soi_proto;
};

/* -------------------------------------------------------- proc_fileinfo (24B) */
struct aether_proc_fileinfo {
    uint32_t fi_openflags;
    uint32_t fi_status;
    off_t    fi_offset;
    int32_t  fi_type;
    uint32_t fi_guardflags;
};

/* ------------------------------------------------------ socket_fdinfo (784B) */
struct aether_socket_fdinfo {
    struct aether_proc_fileinfo pfi;
    struct aether_socket_info   psi;
};

#ifdef __cplusplus
}
#endif

#endif /* AetherProcInfoLayout_h */
