//
//  test_layout.c
//  AetherNet — XNU proc_info layout regression test (host)
//
//  Public iPhoneOS SDKs do not ship <sys/proc_info.h>, so AetherNet declares
//  the per-PID socket structures itself in headers/AetherProcInfoLayout.h.
//  If one field drifts, proc_pidfdinfo() returns a size the caller does not
//  recognise, every socket is skipped, and the kernel tap reports
//  "target has no INET TCP/UDP socket" for a process that is plainly online —
//  the bug 4.0.0 shipped.  These assertions pin the layout to the LP64 ABI of
//  XNU bsd/sys/proc_info.h (xnu-8792.81.2, iOS 16.x), which is also the ABI of
//  this host (x86_64 LP64), so a drift fails the build instead of the device.
//

#include <stddef.h>
#include <stdio.h>

#include "../../headers/AetherProcInfoLayout.h"

/* Compile-time: a wrong layout cannot even be built. */
_Static_assert(sizeof(struct aether_proc_fdinfo)   == 8,   "proc_fdinfo");
_Static_assert(sizeof(struct aether_vinfo_stat)    == 136, "vinfo_stat");
_Static_assert(sizeof(struct aether_in_sockinfo)   == 80,  "in_sockinfo");
_Static_assert(sizeof(struct aether_tcp_sockinfo)  == 120, "tcp_sockinfo");
_Static_assert(sizeof(struct aether_sockbuf_info)  == 24,  "sockbuf_info");
_Static_assert(sizeof(struct aether_socket_info)   == 768, "socket_info");
_Static_assert(sizeof(struct aether_socket_fdinfo) == 792, "socket_fdinfo");

_Static_assert(offsetof(struct aether_socket_fdinfo, psi) == 24, "fdinfo.psi");
_Static_assert(offsetof(struct aether_socket_info, soi_stat)     == 0,   "soi_stat");
_Static_assert(offsetof(struct aether_socket_info, soi_type)     == 152, "soi_type");
_Static_assert(offsetof(struct aether_socket_info, soi_protocol) == 156, "soi_protocol");
_Static_assert(offsetof(struct aether_socket_info, soi_family)   == 160, "soi_family");
_Static_assert(offsetof(struct aether_socket_info, soi_rcv)      == 184, "soi_rcv");
_Static_assert(offsetof(struct aether_socket_info, soi_kind)     == 232, "soi_kind");
_Static_assert(offsetof(struct aether_socket_info, soi_proto)    == 240, "soi_proto");

_Static_assert(offsetof(struct aether_in_sockinfo, insi_fport) == 0,  "insi_fport");
_Static_assert(offsetof(struct aether_in_sockinfo, insi_lport) == 4,  "insi_lport");
_Static_assert(offsetof(struct aether_in_sockinfo, insi_faddr) == 32, "insi_faddr");
_Static_assert(offsetof(struct aether_tcp_sockinfo, tcpsi_ini)   == 0,  "tcpsi_ini");
_Static_assert(offsetof(struct aether_tcp_sockinfo, tcpsi_state) == 80, "tcpsi_state");

int main(void) {
    printf("── XNU proc_info layout (LP64, transcribed from xnu-8792.81.2)\\n");
    printf("   struct proc_fdinfo      %4zu B\\n", sizeof(struct aether_proc_fdinfo));
    printf("   struct vinfo_stat       %4zu B\\n", sizeof(struct aether_vinfo_stat));
    printf("   struct in_sockinfo      %4zu B\\n", sizeof(struct aether_in_sockinfo));
    printf("   struct tcp_sockinfo     %4zu B\\n", sizeof(struct aether_tcp_sockinfo));
    printf("   struct socket_info      %4zu B\\n", sizeof(struct aether_socket_info));
    printf("   struct socket_fdinfo    %4zu B   <-- what proc_pidfdinfo() returns\\n",
           sizeof(struct aether_socket_fdinfo));
    printf("     .psi                  @%zu\\n", offsetof(struct aether_socket_fdinfo, psi));
    printf("     .psi.soi_type         @%zu\\n", offsetof(struct aether_socket_info, soi_type));
    printf("     .psi.soi_family       @%zu\\n", offsetof(struct aether_socket_info, soi_family));
    printf("     .psi.soi_kind         @%zu\\n", offsetof(struct aether_socket_info, soi_kind));
    printf("     .psi.soi_proto        @%zu\\n", offsetof(struct aether_socket_info, soi_proto));
    printf("     .psi…insi_lport       @%zu\\n", offsetof(struct aether_in_sockinfo, insi_lport));
    printf("   all layout assertions hold\\n");
    printf("── 0 failure\\n");
    return 0;
}
