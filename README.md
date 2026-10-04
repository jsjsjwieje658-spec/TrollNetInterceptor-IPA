# AetherNet — TrollStore L4 TCP/UDP Packet Interceptor & Global Floating HUD

> **Thể loại:** System-level network instrumentation tool (kiểu Intercepter-NG / NetHunter cho iOS)
> **Cơ chế cài:** TrollStore (iOS 14.0 – 16.6.1 / 17.0) — permasign với **arbitrary entitlements**
> **Ngôn ngữ:** Objective-C++ (UIKit + Mach + XNU libproc + BPF + fishhook) + portable C11 core
> **Phiên bản:** 4.1.5 (build 415)

---

## 1. Tổng quan kiến trúc — 4 lane bắt gói tin (v4.0)

Bản 3.x chỉ biết một cách bắt gói tin: hook `send()/recv()` trong tiến trình đích. Đó là
**một trong bốn** con đường mà một gói tin có thể đi từ app xuống OS (§2), và không phải con
đường mặc định của app iOS hiện đại. Bản 4.0 viết lại engine bắt gói tin thành **4 lane song
song**, mỗi lane bám một vị trí khác nhau trên đường đi đó:

```
                        ┌───────────────────────────────────────────┐
   app code             │  NSURLSession / Network.framework         │  BSD sockets
                        │  (nw_connection_*, libusrtcp)             │  (send/recv/…)
                        └───────────────┬───────────────────────────┴────────┬──────────┘
                                        │                                    │
                     P2  libnetwork ────┤                            P1  BSD ┤  ← in-process
                        (fishhook)      │                          (fishhook)│    (cần inject)
                                        └──────────┬─────────────────────────┘
                                                   ▼
                                   ┌───────────────────────────────────┐
                                   │  kernel: socket / skywalk / netif │
                                   └───────┬───────────────────┬───────┘
                                           │                   │
                        P3  /dev/bpf ◄─────┘                   └─────►  P4  PF + dummynet
                        (kernel tap: thấy CẢ P1 lẫn P2)                 (pfctl/dnctl + SIGSTOP)
                        ▲                                                   ▲
                        └──── hai lane này chỉ cần root + no-sandbox ────────┘
                             (TrollStore cấp được ⇒ luôn hoạt động)
```

| Lane | Vị trí | Cần gì | Thấy gì | Điều khiển được gì |
|---|---|---|---|---|
| **P1** `AetherLaneBSDSocket` | `__la_symbol_ptr` của `send/sendto/sendmsg/write`… trong tiến trình đích | inject dylib thành công | payload của game/engine native dùng BSD socket | đầy đủ: hold / drop / delay / tamper / duplicate |
| **P2** `AetherLaneLibnetwork` | `libnetwork.dylib` / `libusrtcp.dylib` (`nw_connection_*`) | inject dylib thành công | NSURLSession / Network.framework — **đường mặc định của app iOS ≥ 12** | như P1 |
| **P3** `AetherLaneKernelTap` | `/dev/bpf` trên interface thật | **root + no-sandbox** | **mọi** gói của PID đích, từ cả P1 lẫn P2 | quan sát + flow table (không giữ/ghi đè payload) |
| **P4** `AetherLaneShaper` | `pfctl` anchor + `dnctl` pipe + `SIGSTOP` | **root + no-sandbox** | (không copy packet) | delay / bandwidth / loss / freeze toàn bộ PID |

Điểm mấu chốt: **P3 và P4 không cần inject code**, nên chúng chạy được trên mọi thiết bị có
TrollStore kể cả khi PPL/SPTM chặn `task_for_pid()`. Đó là "baseline đảm bảo" của bản 4.0;
P1/P2 là phần cộng thêm khi inject thành công.

---

## 2. Research: đường đi gói tin UDP/TCP từ app xuống OS trên iOS

### 2.1 Bốn đường đi có thật

**P1 — BSD socket syscalls.**
App gọi `sendto()` → `libsystem_kernel.dylib` → syscall → `bsd/net` → `socket()` layer.
Payload còn nằm trong buffer của tiến trình, nên `fishhook` (rebind bảng `__la_symbol_ptr`
trong `__DATA`) có thể chặn ngay tại ranh giới user/kernel. Đây là đường của mọi engine
native (Unity/Unreal, thư viện C/C++, `curl`, …) — nhưng **không phải** đường mặc định của
app iOS hiện đại.

**P2 — Network.framework / NSURLSession (userspace stack).**
Từ iOS 12, Apple chuyển TCP sang userspace: `libnetwork.dylib` (`nw_connection_*`) ghép với
`libusrtcp.dylib` (user_socket.c) nói chuyện trực tiếp với skywalk channel, không đi qua
`send()/recv()`. Minh chứng:
* Một crash log công khai trên Apple Developer Forums cho thấy stack
  `libusrtcp.dylib` ← `libnetwork.dylib -[NWConcrete_nw_endpoint_flow updatePathWithHandler:]`
  (tức là TCP thực sự nằm trong userspace).
* Quinn “The Eskimo!” (Swift Forums): *user-space networking has been the default since
  Network framework (iOS 12)* — kết quả thực tế là luồng NSURLSession/Network.framework
  **chỉ** hiện ra trong `skywalkctl`, không hiện trong `lsof`, và một hook thuần BSD socket
  sẽ **bỏ sót hoàn toàn** luồng đó.

⇒ Hook P2 phải nhắm vào symbol của `libnetwork`/`libusrtcp`, và vì đây là đường mà hầu hết
app dùng, **bắt buộc phải có P3 để kiểm chứng chéo**.

**P3 — Kernel tap.**
Bất kể app dùng P1 hay P2, gói tin cuối cùng đều rời interface (skywalk/netif) và đi vào
`/dev/bpf` nếu ta mở và attach device đó. Vì vậy BPF **nhìn thấy cả hai** luồng trên — đây là
lane duy nhất không phụ thuộc vào việc app chọn stack nào.
Điều kiện: `/dev/bpf` cần root (macOS có group `access_bpf`, **iOS không có**), nên không thể
dùng từ một App Store app. Dưới TrollStore: app chạy unsandboxed và có thể
`posix_spawnattr_set_persona_np(..., uid 0, gid 0)` để chạy helper với UID 0 ⇒ mở được BPF.

**P4 — PF/dummynet + SIGSTOP (enforcement).**
iOS/macOS không có ALTQ; cách tạo hình lưu lượng thực tế là **PF + dummynet**:
`dnctl pipe N config bw … delay … plr …` rồi `dummynet in|out … pipe N`, nạp qua một anchor
 (`dummynet-anchor "x"` + `anchor "x"` + `pfctl -a x -f -`) và bật bằng `pfctl -E`. iOS có sẵn
cả `pfctl` lẫn `dnctl`. Thêm `SIGSTOP/SIGCONT` lên PID đích để có lệnh "freeze" thật sự.
Lane này không copy packet (không có visibility), bù lại **không cần inject** và là cách duy
nhất ép delay/bandwidth lên cả luồng P2 khi không hook được userspace stack.

### 2.2 Những đường **không** tồn tại (và đã bị xoá khỏi bản 4.0)

| Thiết kế cũ | Vì sao chết |
|---|---|
| **"Tier 0 NECP capture"** | NECP là **policy engine**, không phải tap. `bsd/net/necp.h` chỉ có `necp_match_policy` (#460, trả về aggregate result) và `necp_client_action` (#461) với action `ADD/REMOVE`; các tham số `NECP_PARAMETER_PID/UID` đều ghi *"Requires entitlement"*. Không có action nào để đăng ký/divert packet — API mà bản cũ gọi đến đơn giản là không tồn tại. |
| **NetworkExtension** (`NEFilterDataProvider` / `NEPacketTunnelProvider`) | Theo WWDC25 "Filter and tunnel network traffic with NetworkExtension", filter/packet provider hệ thống yêu cầu thiết bị **supervised / MDM** (thực tế trả `NEFilterErrorDomain` code 5). Không bao giờ khả dụng với TrollStore. |
| **utun** (`PF_SYSTEM`/`SYSPROTO_CONTROL`, `net.utun_control`) | Tạo được interface read/write thật, nhưng cần root + quyền control — không viable từ trong payload của tiến trình đích. |
| **`/dev/bpf` từ app sandbox** | Cần root và iOS không có group `access_bpf`; chỉ chạy được nhờ persona-UID-0 của TrollStore (xem P3). |
| **Dopamine "Tier 0"** (README 3.x) | Không hề có file nào trong repo (`Core/DopamineBridge.*` chưa từng tồn tại). Đã xoá khỏi tài liệu thay vì để lại tuyên bố sai. |

### 2.3 Kết luận thiết kế

> Capture engine v4 = **P1 + P2** (in-process, khi inject được) **+ P3** (`/dev/bpf`, luôn chạy
> được dưới TrollStore) **+ P4** (enforcement). P3/P4 là baseline; P1/P2 là phần nâng cao.
> Không còn tier nào dựa trên API không tồn tại.

**BIOCSEXTHDR — kernel tự nói gói tin của ai (4.0.5).** `BIOCSEXTHDR` (`_IOW('B',124,u_int)`)
bật `struct bpf_hdr_ext`: mỗi record BPF được kernel đóng thêm `bh_pid`, `bh_comm`, và
`bh_flags & BPF_HDR_EXT_FLAGS_DIR_OUT` (hướng TX/RX). Nghĩa là **không còn phải đoán** chủ gói tin
bằng danh sách port lấy từ `proc_pidfdinfo` (danh sách này luôn lỗi thời và hoàn toàn mù trước
Network.framework). 4.0.5 bật nó khi attach (log báo nếu kernel từ chối) và ưu tiên khớp theo
`bh_pid == targetPID`, chỉ rớt về khớp port khi `bh_pid == 0`. Dòng thống kê có `matchedByPID=%u`
để bạn thấy cơ chế nào đang chạy. Bộ giải mã được unit-test trên host (`TestBPFExtHeader`).

**Layout thật của record BPF trên iOS (đã đối chiếu bằng bytes từ máy thật).** Đây là nguyên nhân
`noframe` tăng liên tục ở 4.0.5. Trong `bsd/net/bpf.h` của Apple:

```c
#if defined(__LP64__)
#define BPF_TIMEVAL timeval32      /* { int32 tv_sec; int32 tv_usec; } = 8 bytes */
#else
#define BPF_TIMEVAL timeval
#endif
struct bpf_hdr { struct BPF_TIMEVAL bh_tstamp; u_int32 bh_caplen; u_int32 bh_datalen; u_short bh_hdrlen; };
```

Tức là trên arm64 **`bh_tstamp` chỉ dài 8 byte**, không phải 16: `caplen` nằm ở **offset 8**,
`hdrlen` ở **16**, còn `bpf_hdr_ext` thì có `bh_flags` ở `ts+11` và `bh_pid` ở **`ts+12`**
(= 20 với iOS). Ta đang đọc theo layout 28 byte của sách giáo khoa ⇒ đọc nhầm `bh_hdrlen` (62) thành
chiều dài gói tin và loại bỏ **mọi** record. Minh chứng, đúng bytes máy bạn log ra:

```
c2abc16a 23320d00 | 97000000 97000000 | 3e00 | 00 00 | 00000000 …
^tv_sec  ^tv_usec | ^caplen=151 ^datalen | ^hdrlen=62 | ^fl ^pid=0
```

62 = `BPF_WORDALIGN(14 + sizeof(bpf_hdr_ext=60)) - 14` (đúng công thức trong `bpf_attach`).
4.0.6 **không còn đoán**: `AetherBPFDetectFraming()` nhận diện độ rộng timestamp ngay từ record đầu
tiên (kiểm tra giá trị giây có nằm trong miền epoch hợp lý không), rồi mọi offset tính theo nó.
Cả hai layout đều được unit-test trên host, trong đó có đúng chuỗi bytes ở trên (`TestBPFDeviceBytes`).

**Lane P5 (đếm theo socket) không tồn tại — đã kiểm tra.** `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`
trả `struct socket_fdinfo`, và tưởng có thể đếm byte/packet từ đó mà không cần BPF lẫn inject.
Thực tế theo `bsd/sys/proc_info.h` của xnu-8792.81.2 (iOS 16.5): `struct tcp_sockinfo` chỉ gồm
`tcpsi_ini`, `tcpsi_state`, `tcpsi_timer[]`, `tcpsi_mss`, `tcpsi_flags`, `rfu_1`, `tcpsi_tp`
(con trỏ PCB dạng opaque) — **không có bộ đếm TX/RX nào**; `soi_stat` là `vinfo_stat` (metadata
kiểu file), còn UDP (`in_sockinfo`) hoàn toàn không có counter. Nói cách khác: ngoài inject (P1/P2)
và BPF (P3), **không có đường nào khác** để thấy traffic của process khác trên iOS không jailbreak.

---

## 2b. Entitlements — tại sao app cần từng quyền

Tham khảo từ **TrollStore** (opa334) và **TrollSpeed** (Lessica/82flex):

| Entitlement | Lý do bắt buộc |
|---|---|
| `platform-application` | Biến app thành platform binary → AMFI chấp nhận private entitlements |
| `com.apple.private.security.no-sandbox` (+ `no-container`) | Thoát sandbox: đọc socket info bằng `proc_pidfdinfo`, ghi dylib ra `/var/mobile/Library/Caches`, mmap shared memory liên tiến trình |
| `com.apple.private.persona-mgmt` | `posix_spawnattr_set_persona_np` spawn helper **UID 0/GID 0** → mở `/dev/bpf`, chạy `pfctl`/`dnctl`, `SIGSTOP` PID đích |
| `task_for_pid-allow`, `get-task-allow`, `com.apple.system-task-ports*` | `task_for_pid()` → `mach_vm_*` + `thread_create_running(dlopen)` để inject payload (lane P1/P2) |
| `com.apple.springboard.accessibility-window-hosting`, `com.apple.backboard.client`, `QuartzCore.displayable-context/secure-mode` | Đăng ký `UIWindow` (windowLevel 10000010) sống **ngoài** app qua `SBSAccessibilityWindowHostingController` |
| `com.apple.private.hid.client.*`, `hid.manager.client` | Nhận/giả lập touch cho nút nổi qua BackBoard HID (`BKSHIDEventRegisterEventCallback`) |
| `com.apple.private.kernel.jetsam`, `memorystatus` | HUD daemon root không bị jetsam kill |
| `file-read-data`, `user-preference-read/write` | Đọc path process, lưu cấu hình |

**Đã xoá trong 4.0:** `com.apple.private.necp.match`, `necp.policies`,
`com.apple.networkd.modify_settings`, `com.apple.private.networkextension.configuration`,
`com.apple.private.network.socket-delegate` — tất cả thuộc về các thiết kế đã chết ở §2.2.
Engine v4 không cần entitlement mạng nào: mọi thứ nó dùng (`/dev/bpf`, `pfctl`, `dnctl`,
`proc_pidfdinfo`) chỉ cần **root**, và root đạt được bằng persona spawn.

> **PPL/SPTM:** A12+ / iOS 15+ chặn vĩnh viễn các entitlement chạy code unsigned
> (`dynamic-codesigning`, `csdebugger` dạng JIT) ⇒ lane P1/P2 (inject) có thể thất bại. Khi đó
> app tự hạ cấp xuống P3+P4 và vẫn bắt/điều khiển được lưu lượng — đây chính là lý do kiến
> trúc 4 lane tồn tại.

---

## 3. Chức năng chi tiết

### Tab Home
- Chọn PID (search tên / PID / bundle id, lọc "User Apps" / "All Processes", hiện icon + số
  socket TCP/UDP đang mở nhờ `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`).
- Sau khi chọn: tên app, PID, bundle id, **pill trạng thái lane** (`INJECTED · DYLIB HOOKS`,
  `KERNEL TAP (BPF)`, `SHAPER/PF` …) do `probeAvailableLanes` trả về.
- **Card L4 Network Status:** 2 lane TCP (teal) & UDP (blue) — socket active, packet RX/TX,
  B/s live, packet đang **Held** / đã **Dropped**, và bộ đếm riêng của kernel tap.

### Floating Button (toàn hệ thống)
- Hình tròn viền titanium + ring logo orbital (quay chậm khi active) + badge số packet giữ.
- **Tắt:** tam giác ▶ (standby) · **Bật:** 2 gạch ⏸ (đang bắt giữ).
- Kéo tự do, edge snap, lưu vị trí, haptic; kích thước/độ mờ chỉnh ở Tab Settings.
- Chạm được nhờ chuỗi BKSHID → (raw IOHID digitizer parse, có fallback AXEventRepresentation)
  → `TSEventFetcher` → synthetic `UITouch` → gesture recognizer.

### Tab Settings
| Nhóm | Tuỳ chỉnh |
|---|---|
| **Interception Rules** | Hướng `Both / Download / Upload` · Protocol `TCP+UDP / UDP / TCP` · Mode `Hold / Drop / Delay+Jitter / Tamper / **Observe**` · **Master ratio 0–100 %** · riêng **RX ratio** và **TX ratio** |

> **Mode `Observe` là mặc định kể từ 4.0.4.** Nó chỉ **đếm + log** mọi gói tin TCP/UDP của
> target, không giữ, không drop, không delay, và đặc biệt **không SIGSTOP target**. Chọn mode
> khác (Hold/Drop/…) khi bạn thực sự muốn can thiệp — khi ấy, vì thiết bị không có `pfctl`,
> primitive duy nhất là **đóng băng tiến trình** (xem §6).
| **Network Simulation** | Preset `Normal / Ghost-Freeze / Lag Spike / Degraded 3G / TCP-RST` · Latency 0–1500 ms · Jitter 0–500 ms · Bandwidth cap 64 kbps–20 Mbps (log) · Duplicate UDP % · Auto-flush `Off/5s/12s/30s` |
| **Floating Button** | Diameter 40–88 pt · Opacity 35–100 % · Edge snap · Lock position · Haptics · vị trí X/Y bằng slider |

---

## 4. Cấu trúc source

```
TrollNetInterceptor-IPA/
├── main.mm                       # Dispatcher: -hud / -exit / -check / -rootctl / -bftap
├── supports/
│   ├── entitlements.plist        # Entitlements (§2b, đã bỏ các key thuộc thiết kế chết)
│   ├── Info.plist
│   └── AppIconSource.png
├── headers/
│   ├── AetherNetShared.h         # Shared memory struct + enum 4 lane (app ⇄ HUD ⇄ payload)
│   ├── AetherProcInfoLayout.h    # XNU sys/proc_info.h layout, plain C (static-asserted)
│   ├── PrivateSystemSPI.h        # libproc / BPF / BackBoard / SBS private SPI
│   └── AetherTouchPrivate.h      # UITouch / UIEvent private SPI (KIF)
├── Core/
│   ├── AetherSharedMemory.mm     # mmap IPC lock-free (atomic C11)
│   ├── AetherLog.h/.mm           # Log app + merge log daemon
│   ├── ProcessManager.h/.mm      # sysctl proc list, proc_pidfdinfo, spawn HUD/helper, chọn lane
│   ├── MachInjector.mm           # task_for_pid → remote dlopen + handoff shared state
│   ├── compiler_rt_shim.c        # __isPlatformVersionAtLeast + __chkstk_darwin (cross-build)
│   └── L4Engine/                  # ★ engine bắt gói tin v4
│       ├── AetherPacketCore.h/.c  #   portable C11: parse L2/L3/L4, flow table, policy, BPF iterate
│       ├── AetherKernelLane.h/.mm #   P3: /dev/bpf + socket inventory (iOS glue)
│       └── AetherShaper.h/.mm     #   P4: PF/dummynet + SIGSTOP + AetherRootCtlMain
├── Payload/
│   ├── fishhook.h/.c             # Facebook fishhook (BSD) — Mach-O symbol rebinding
│   ├── AetherHookCore.h/.c       # ★ portable C11: hold queue + toàn bộ chính sách send/recv
│   └── NetHookPayload.mm         # P1 + P2 binding: trampoline → AetherHookCore
├── HUD/
│   ├── HUDMain.mm                # Plugin-mode UIApplication + raw HID digitizer bridge
│   ├── HUDRootApplication.mm     # SBSAccessibilityWindowHostingController @ level 1e7
│   ├── HUDMainWindow.h/.mm       # Passthrough hit-test (chỉ chạm đúng nút mới ăn)
│   ├── FloatingToggleButton.*    # Nút tròn logo + ▶/⏸ morph + drag/snap/badge
│   └── TSEventFetcher.*, IOHIDEventKIF.*, UITouchKIFAdditions.*   # touch synthesis (KIF/TrollSpeed)
├── UI/
│   ├── AppTheme.h/.mm            # Obsidian × Champagne gold design system
│   ├── AetherGoldButton.h/.mm    # UIControl thay UIButton (tránh crash legacy visual provider)
│   ├── MainApp.mm                # UIApplicationMain (no-UIScene) + TabBar + rate ticker
│   ├── HomeViewController.*      # Tab 1
│   ├── SettingsViewController.*  # Tab 2
│   └── LogViewController.*       # Tab 3 — log viewer
├── tests/host/                   # ★ Môi trường mô phỏng (§5a)
│   ├── Makefile
│   ├── run_tests.sh              # 12 kịch bản traffic thật
│   ├── host_support.h/.cpp       # stand-in cho shared memory / log daemon
│   ├── preload_shim.c            # LD_PRELOAD interposer (= fishhook của Linux)
│   ├── fake_target.c             # "app bị test": UDP + TCP echo client/server
│   ├── test_core.c               # unit test: parser, policy, BPF framing, hold queue
│   ├── test_layout.c             # static asserts on the XNU proc_info layout
│   └── test_tap.c                # pipeline P3: parse → match → flow table → counters
├── .github/workflows/build.yml   # CI: host-sim (bắt buộc) → cross-build → verify → release
└── scripts/
    ├── crossbuild-linux.sh       # clang/ld64.lld + iPhoneOS16.5.sdk + ldid → AetherNet.tipa
    ├── build.sh                  # macOS/XcodeGen path (tuỳ chọn)
    └── gen_icons*.py, gen_info_plist.py
```

**Quy tắc kiến trúc:** mọi quyết định chính sách (hold/drop/delay/tamper, tỉ lệ, hướng,
protocol, hàng đợi giữ, auto-flush) nằm trong **`Payload/AetherHookCore.c`** (C11, không phụ
thuộc Darwin). Binding iOS (`NetHookPayload.mm`) chỉ cung cấp con trỏ syscall thật. Nhờ vậy
`tests/host` biên dịch và chạy **đúng mã quyết định sẽ lên máy**, chứ không phải một bản mô
phỏng song song.

---

## 5. Build & kiểm thử

### 5a. Mô phỏng trên Linux (bắt buộc phải xanh trước khi phát hành)

```bash
cd tests/host
make all          # test_core, test_tap, fake_target, libaetherhooks.so
./run_tests.sh    # 2 unit suite + 12 kịch bản traffic thật qua loopback
```

Cách mô phỏng hoạt động: `libaetherhooks.so` được `LD_PRELOAD` vào `fake_target` — nó là bản
thế của `libNetHookPayload.dylib` trên Linux (cùng kỹ thuật "interpose symbol" như fishhook),
và gọi thẳng vào `AetherHookCore.c` đang được ship. Traffic là **UDP + TCP thật** qua
loopback, server echo không bị can thiệp, mọi khẳng định đều dựa trên gói tin thực sự tới đích.

```
0a. XNU proc_info layout (what proc_pidfdinfo() must return)           ✔
 0. Unit tests (packet core, policy engine, BPF framing, hold queue)   ✔
 1. Kernel tap pipeline (P3: parse → match → flow table → counters)    ✔
 2. Baseline — interception OFF (telemetry must not disturb traffic)   ✔ 6 assertions
 3. Drop 100% (UDP + TCP)                                              ✔ 3
 4. Hold → flush (⏸ → ▶ releases everything, nothing is lost)          ✔ 5
 5. Delay + jitter (all packets still arrive, just later)              ✔ 3
 6. Capture ratio 50% (statistical, deterministic RNG)                 ✔ 3
 7. Direction filter — upload only                                     ✔ 3
 8. Direction filter — download only (peer still receives)             ✔ 4
 9. Protocol filter — UDP only                                         ✔ 2
10. Protocol filter — TCP only                                         ✔ 2
11. Tamper (payload bit-flips detected by the peer)                    ✔ 1
12. Safety auto-flush (held traffic is released on its own)            ✔ 1
13. UDP duplication (server sees two copies)                           ✔ 1
════════════════════════════════════════════════════════════════════
 12 scenario(s) · 37 assertion(s) passed · 0 failed
════════════════════════════════════════════════════════════════════
```

Job `host-sim` chạy đúng hai lệnh trên trong CI, và job build IPA có `needs: host-sim` ⇒ một
lỗi logic trong mã quyết định sẽ **chặn** pipeline trước khi có IPA.

### 5b. Cross-build IPA trên Linux

```bash
sudo apt-get install -y clang lld
curl -Lo ~/.cache/ldid https://github.com/ProcursusTeam/ldid/releases/latest/download/ldid_linux_x86_64 && chmod +x ~/.cache/ldid
git clone --depth=1 --filter=blob:none --sparse https://github.com/theos/sdks.git ~/.cache/sdk-repo
cd ~/.cache/sdk-repo && git sparse-checkout set iPhoneOS16.5.sdk && cd -
./scripts/crossbuild-linux.sh          # → AetherNet.tipa
```

Toolchain: `clang` (`-target arm64-apple-ios14.0`) + `ld64.lld`
(`-Wl,-undefined,dynamic_lookup`) + iPhoneOS16.5.sdk + `ldid` fakesign entitlements.
Sản phẩm: `Payload/AetherNet.app/{AetherNet, libNetHookPayload.dylib, Info.plist, icon}`.

### 5c. Build trên macOS (tuỳ chọn)

```bash
brew install xcodegen ldid
./scripts/build.sh all
```

### Cài lên iPhone
1. Copy `AetherNet.tipa` (AirDrop / Files / URL install).
2. Mở bằng **TrollStore** → Install.
3. Mở AetherNet → Tab Home → chọn PID → **Create Floating Button**.
4. Bấm nút nổi để bật/tắt bắt gói tin; đổi rule trong Tab Settings (áp dụng ngay, không cần
   inject lại).

---

## 6. Troubleshooting

**Crash `symbol not found in flat namespace '___isPlatformVersionAtLeast'`:** `@available()`
sinh tham chiếu tới helper của Apple compiler-rt mà toolchain Linux không có.
`Core/compiler_rt_shim.c` tự triển khai helper (đọc `kern.osproductversion` bằng sysctl) và
được nhúng vào cả executable lẫn dylib.

**`matched=0` dù tap đang chạy — kiểm tra 2 thứ này trước tiên:**
1. **Target có đang bị đóng băng không?** Tất cả các log `matched=0` nhận được tới nay đều đi kèm
   `[shaper] pid … SIGSTOP` + `lanes=12 method=4`: mode lúc đó **không phải Observe**, và vì thiết bị
   này **không có hook** (`task_for_pid … 0x5`) nên cách duy nhất để "giữ" gói tin là **SIGSTOP** —
   mà một app bị stop thì **không còn gì để bắt**. 4.1.0 log cảnh báo rất to khi điều này xảy ra.
   Để **bắt gói tin**, hãy để mode = **Observe** (log sẽ hiện `lanes=4 method=2`).
2. **Bộ lọc kernel chỉ lọc IPv4/IPv6, không lọc port.** 12 frame/s mà tap đọc được là traffic của
   **toàn máy**, không phải của target — `matching ports [...]` chỉ dùng để phân loại ở user space.
   Nếu mọi frame đều `DIR_IN` + `pid=0`, đó là **broadcast/multicast nền** (mDNS/NDP), không phải
   target. 4.1.0 thêm `[tap] kernel frame ownership: pid=0 xN | <pid> (<số>)` để phân biệt dứt khoát
   "target im lặng" với "kernel không gán frame cho ai".

**HUD daemon chết với `FATAL signal 11 (SIGSEGV)` vài giây sau khi tap chạy (≤ 4.1.0):** đã sửa
trong 4.1.1. Nguyên nhân **không nằm ở BPF** mà ở **logging**: `AetherLogCurrentTimestamp()` dùng chung
một `NSDateFormatter` cho mọi luồng (`NSDateFormatter` **không thread-safe**), và timestamp được tính
trên **luồng gọi** — main thread, tap thread và liveness thread log cùng lúc ⇒ crash đúng lúc tap bắt
đầu chạy. Nếu bản mới vẫn crash, dòng
`[pid …] FATAL signal 11 (SIGSEGV) pc=0x… lr=0x… base=0x… phase=N thread=tap|main|other` cho biết
chính xác luồng và vị trí (`phase`: 1=tạo poll set, 2=poll, 3=read, 4=đi record BPF, 5=việc định kỳ,
6=refresh inventory).

**HUD daemon chết ngay sau khi tap khởi động (mọi dòng log của daemon dừng lại, lần bấm Remove sau
đó báo `running=1` nhưng daemon không hề log `HUD daemon exiting (remove command)`):** daemon **đã
chết trước đó**, và `running=1` là do **zombie** (4.0.9 sửa phần phát hiện). 4.1.0 thêm
`[tap] liveness: loops=… (+…) frames=… lastData=…ms` mỗi 2 s từ một luồng **độc lập** với reader
loop, nên log sẽ nói rõ: `loops=` đứng im ⇒ loop bị kẹt trong `read()` (đã chặn bằng O_NONBLOCK);
không có dòng nào ⇒ tiến trình đã chết (4.0.9 log `died from signal …` / `[pid …] FATAL signal …`).

**Nút floating tự biến mất, log không ghi gì cả:** đây mới là trường hợp thường gặp nhất. HUD daemon
là một **root plugin process** spawned ra, nên nó có thể bị **jetsam**, bị **SpringBoard relaunch**
giết, hoặc bị iOS thu hồi — tất cả đều **không để lại một dòng log nào**, và lần bấm kế tiếp chỉ báo
`HUD toggle pressed (running=0)`. Trước 4.0.8 **không có ai trông nó cả**. Giờ có supervisor:
mỗi 2 s app kiểm tra (heartbeat **hoặc** pid còn sống), và nếu daemon biến mất thì
`HUD daemon vanished without an exit log (attempt N) — respawning`. Đường tự huỷ do SpringBoard
relaunch cũng đã được log lại (`HUD daemon exiting (SpringBoard relaunched)`) thay vì chết câm.
Nếu nó cứ chết liên tục, app log `keeps dying … backing off` rồi thử lại mỗi phút để không giật máy.

Kèm theo: lane capture có thể chạy ở **app** hoặc ở **daemon** (tuỳ chỗ bạn bấm), nên 4.0.8 ghi
`laneOwnerPID`. Daemon mới chỉ **tự nối lại phiên capture** khi chủ cũ đã chết
(`capture already owned by pid … — not starting a second tap`), và `stopCaptureLanes` từ chối gỡ
lane của tiến trình khác — tránh đếm gói tin hai lần.

**Nút floating tự biến mất một lúc sau khi bật capture:** HUD daemon chỉ **quan sát** raw HID (nó
không thể nuốt sự kiện), nên một cú chạm vật lý được xử lý **cả** bởi nút floating **lẫn** bởi app
đang hiển thị bên dưới — trong đó có nút "−  Remove Floating Button" của Tab Home nếu nó nằm ngay
dưới overlay. Kết quả: vừa bật capture xong là HUD bị gỡ. 4.0.7 thêm **trọng tài chạm**: daemon ghi
lại thời điểm + toạ độ mỗi cú chạm nó xử lý (`hudTapConsumedMs/X/Y`), và app bỏ qua lần bấm nút HUD
nếu nó đến từ **cùng một cú chạm** (< 700 ms, cùng vùng với nút floating). Ngoài ra, nếu daemon bị
khởi động lại (cập nhật, respring, gỡ nhầm) trong lúc đang capture, daemon mới **tự nối lại phiên
capture** (`resuming live capture session for pid …`) thay vì để trạng thái "đang bắt" nhưng thực tế
đã chết.

**Nút floating bấm không ăn:** HUD daemon chạy UID 0 còn app chạy uid 501 —
`kill(pid, 0)` trả `EPERM` (process *có tồn tại*) ⇒ `EPERM` được tính là "đang chạy".
Touch được xử lý bằng **raw IOHID digitizer parse** (thử một họ các affine transform và khoá
transform đầu tiên chạm trúng nút) với fallback `AXEventRepresentation` trên iOS cũ.

**App đích bị "treo" khi đang Hold (download):** đây là lỗi thật của bản 3.x — vòng lặp
giữ gói tin RX chặn đến **30 giây** mà không tôn trọng `SO_RCVTIMEO` của socket. Bản 4.0 đọc
`SO_RCVTIMEO` bằng `getsockopt` và giới hạn thời gian chờ theo đúng timeout của ứng dụng
(tối đa 30 s nếu socket không đặt timeout) ⇒ Hold giờ trông như "mạng chậm" chứ không phải treo.

**`kernel tap unavailable: target has no INET TCP/UDP socket` (4.0.0):** `struct socket_info`
bắt đầu bằng `soi_stat`, nhưng bản khai báo tay của 4.0.0 đã bỏ sót trường này → mọi offset lệch,
`proc_pidfdinfo()` trả về kích thước không khớp (`792` ≠ `224`) → **mọi** socket bị bỏ qua.
4.0.1 chuyển toàn bộ layout sang `headers/AetherProcInfoLayout.h` (chép nguyên văn từ
`xnu-8792.81.2`), cho phép parse khi kernel trả kích thước lớn hơn, log `[inventory] …` đầy đủ
(euid / số fd / số socket / size kernel-ours) và retry 3 s trước khi bỏ cuộc. `tests/host/
test_layout.c` khoá layout bằng `_Static_assert` để lỗi này không thể lặp lại.

**`[rootctl] unknown verb: -rootctl`, `capabilities pfctl=0 dnctl=0 freeze=0` (4.0.0):** helper
root được spawn với argv `[AetherNet, -rootctl, <verb>, …]` nhưng `AetherRootCtlMain` lại đọc
verb ở `argv[1]` — tức là đọc chính cờ `-rootctl`. Mọi lệnh helper vì thế chết với `exit=2`, nên
toàn bộ lane P4 (pfctl/dnctl/freeze) bị coi là không tồn tại. 4.0.1 truyền `argv+1` và còn chấp
nhiệm cả hai quy ước gọi.

**`task_for_pid(...) failed: 0x5 ((os/kern) failure)`:** không phải lỗi — PPL/SPTM trên A12+/iOS 15+
chặn `task_for_pid` với tiến trình không được debug, nên lane P1/P2 (inject) sẽ không chạy.
App tự hạ cấp xuống P3 (BPF) + P4 (PF/freeze); log báo
`Injection failed — kernel tap / shaper lanes will carry the session`.

**`capabilities pfctl=0 dnctl=0 freeze=1`:** iOS không ship `pfctl`/`dnctl`, nên lane P4 chỉ còn
**freeze (SIGSTOP)** — và nó chỉ được dùng cho mode **Hold/Drop** (dừng tiến trình = không gì ra/vào
được). Với **Delay/Tamper** app sẽ báo `shaper failed: mode … needs PF/dummynet or in-process hooks`
thay vì giả vờ thành công. Muốn đầy đủ Delay/Tamper/Duplicate thì cần inject được (P1/P2), tức là
cần bypass PPL (thiết bị đã jailbreak) — TrollStore một mình không làm được.

**`[bftap] parent … went away` / helper sống sót sau khi bấm Stop (4.0.1):** app chạy
**uid 501**, helper chạy **uid 0** → `kill()` từ app tới helper trả `EPERM`, nên helper chỉ thoát
khi parent chết. 4.0.2 đưa lệnh dừng qua shared memory (`tapStopRequest`); nếu vẫn chưa thoát, app
nhờ một helper root khác gửi tín hiệu (`-rootctl kill <pid>`).

**Không có dòng `[tap] seen=…` nào dù đã capture vài chục giây (4.0.2):** thống kê và việc làm
mới danh sách port đã bị đặt **bên trong nhánh `poll()==0`** của vòng lặp đọc, trong khi `poll` có
timeout 200 ms. Trên một interface thật (en0 luôn có chatter nền) `poll()` hầu như không bao giờ
trả 0 ⇒ phần việc định kỳ **không bao giờ chạy**: tap trở thành hộp đen, và inventory không bao giờ
được làm mới. 4.0.3 tách hẳn: đọc frame khi `poll() > 0`, còn thống kê (5 s, có thêm `poll=%d`) và
refresh inventory (500 ms) chạy **theo thời gian**, độc lập với kết quả `poll`.

**`read() failed (x1): Invalid argument` + `BIOCSBLEN(...,262144) failed: Invalid argument`
(nguyên nhân gốc của `seen=0` trên build 404):** đã tìm thấy trong mã nguồn XNU
(`bsd/net/bpf.c`, xnu-8792.81.2) — **`bpfread()` bắt buộc `uio_resid == d->bd_bufsize`**:

```c
/* Restrict application to use a buffer the same size as kernel buffers. */
if (uio_resid(uio) != d->bd_bufsize) { … return EINVAL; }
```

Ta đọc bằng buffer 256 KB trong khi kernel chỉ cấp **4096 byte** ⇒ **mọi** `read()` trả `EINVAL`.
Và buffer đó không nâng được vì `BIOCSBLEN` bị từ chối **sau khi đã `BIOCSETIF`**
("Interface already attached, unable to change buffers"). 4.0.5 sửa cả hai: `BIOCSBLEN` gọi
**trước** khi gắn interface (thử 256 KB → 32 KB), và mỗi lần `read()` dùng **đúng** `BIOCG*BLEN*`
của từng port. Nếu bạn vẫn thấy `read() failed`, hãy gửi kèm dòng `[tap] <if> buffer is … bytes`.

**`<N> byte(s) read but no BPF record decoded (dlt=1, …): <hex>`:** có dữ liệu nhưng walker không
tách được record nào — 99% là sai layout header (xem mục "Layout thật của record BPF" ở §2.3).
4.0.6 tự nhận diện framing, nên nếu dòng này còn xuất hiện, hãy gửi kèm 32 byte hex đầu: nó cho biết
ngay `caplen` / `hdrlen` / `pid` đang nằm ở offset nào trên máy bạn.

**`[tap] seen=0 … poll=1` (BPF báo sẵn sàng mà không đọc được gì):** dòng thống kê 4.0.4 in thêm
`read=<số lần đọc>/<byte> err=<số lỗi>(<errno>) zero=<số lần read()=0> noframe=<số lần đọc được
byte nhưng không decode được record> krecv/kdrop=<bộ đếm của kernel>` và mỗi interface khi start
đều có probe 1 s (`[tap] 1s probe: en0=0B utun1=0B …`). Đọc theo thứ tự:
`krecv>0` mà `read=0B` ⇒ `read()` lỗi (xem `err`/errno) hoặc filter BPF loại hết; `krecv=0` ⇒
interface không có traffic (đang dùng interface khác — danh sách interface + DLT được in ở dòng
`[tap] started …`); `read` có byte mà `noframe>0` ⇒ header `bpf_hdr` khác với layout ta đang dùng
(4.0.4 dump sẵn 32 byte đầu để đối chiếu). Nếu probe 1 s ra `0B` trên **mọi** interface thì BPF của
máy đó không thấy traffic gì — khi ấy capture chỉ còn có thể làm bằng inject (P1/P2), tức cần bypass PPL.

**`[tap] seen=%u ip=%u matched=%u` đọc thế nào:** `seen` = số record BPF đọc được, `ip` = số frame
thực sự là IPv4 (phần còn lại là ARP/IPv6/multicast nền — bình thường), `matched` = số frame mang
đúng port của target. 5 frame đầu tiên được log chi tiết (`[tap] match#1 UDP 10.0.0.5:54862 ->
… TX 62B`) và khi Stop luôn có một dòng tổng kết `[tap] stopped (seen=… ip=… matched=…)`, nên
phiên capture ngắn cũng có chứng cứ. Nếu `seen > 0` mà `matched = 0`: gói tin không mang port nào
trong `matching ports […]` — target có thể mở socket bằng Network.framework (`libusrtcp`, không
thấy qua BSD socket inventory) hoặc đã mở socket mới (inventory được làm mới mỗi 500 ms).

**Target bị đứng im / đơ khung hình trong suốt phiên capture (log có `signal 17` lúc Start,
`signal 19` lúc Stop):** đó là **SIGSTOP/SIGCONT**. Nguyên nhân là mode cũ mặc định **Hold**, mà
thiết bị không có `pfctl` ⇒ cách duy nhất để "giữ" gói tin của nguyên tiến trình là **dừng tiến
trình đó**. Với mục tiêu "chỉ muốn xem gói tin" thì cái này phản tác dụng: tiến trình bị dừng thì
không sinh ra traffic để mà xem.

4.0.4 thêm **mode `Observe`** (bắt gói tin thuần túy: đếm + log, không can thiệp, **không SIGSTOP**)
và đặt nó làm **mặc định**. Nếu bạn *muốn* can thiệp (Hold/Drop/Delay/Tamper) thì chọn mode đó trong
Tab Settings — lúc ấy việc đóng băng target là có chủ ý.

**Log trống:** Tab 3 merge log của daemon vào log app mỗi giây (`AetherLogMergeDaemonLog`);
kéo để refresh nếu cần.

---

## 7. Cảnh báo pháp lý & đạo đức

Công cụ này can thiệp vào **tiến trình và network stack của thiết bị bạn sở hữu** — dùng để
phân tích giao thức, nghiên cứu game networking, test resilience ứng dụng trên **máy của bạn**.
Không dùng để can thiệp thiết bị/thông tin của người khác. Mọi rủi ro (crash process đích,
vi phạm ToS của game/app) do người dùng tự chịu.

## 6b. Lịch sử phiên bản (ngắn)

| Phiên bản | Điểm chính |
|---|---|
| **4.0.0** | Viết lại engine bắt gói tin theo research §2: 4 lane (BSD / libnetwork / BPF / PF+freeze). |
| **4.0.1** | Sửa layout `proc_pidfdinfo` (inventory trống), sửa argv của `-rootctl` (P4 bị câm), thêm retry inventory 3 s. |
| **4.0.2** | Làm tap có thể quan sát và dừng được từ uid 501 (`tapStopRequest`, `-rootctl kill`, `[tap] seen=…`); P4 không còn nhận lệnh thi hành khi `pfctl`/`dnctl` vắng mặt. |
| **4.0.3** | Sửa tap thành "hộp đen": thống kê + refresh inventory bị kẹt trong nhánh `poll()==0` nên không bao giờ chạy trên interface thật. Thêm log 5 frame khớp đầu tiên và tổng kết khi Stop. |
| **4.0.4** | Thêm **mode Observe** (bắt gói tin thuần túy, không can thiệp) và đặt làm mặc định: trước đây bật intercepting ở mode Hold mà không có `pfctl` ⇒ target bị **SIGSTOP** (đơ khung hình). Thêm probe 1 s mỗi interface lúc start + đếm sức khoẻ đường đọc (`read/err/zero/noframe/krecv`) để chẩn đoán `seen=0`. |
| **4.1.5** | **Giả lập ping (lag switch) + UI trung thực.** Lý do ping game không đổi: để tăng độ trễ phải **giữ gói tin lại**, mà máy này có `pfctl=0 dnctl=0` (iOS không ship) và `task_for_pid → 0x5` (không inject được) ⇒ **không có hàng đợi nào** ở kernel hay trong tiến trình; BPF chỉ nhận **bản sao** frame nên đo được nhưng **không thể giữ/trễ/sửa** gói gốc. Do đó Hold/Drop/Delay/Tamper **không bao giờ có tác dụng** trên máy này, chỉ Observe chạy thật. Thêm **Ping spike**: `lagSpikeMs` (0 = TẮT, mặc định) + `lagCycleMs` (mặc định 1000 ms) — worker chạy vòng lặp **SIGSTOP / SIGCONT**, đúng cơ chế lag switch phần cứng; app sẽ khựng theo, đó chính là tác dụng. Dùng `kill()` trực tiếp (daemon và target cùng uid 501), chỉ fallback qua root helper; **luôn SIGCONT** khi thoát/khi tắt interception để không bao giờ bỏ lại app bị stop. Slider đổi giá trị có hiệu lực **ngay**, không cần bật lại. Settings giờ **khoá** (setEnabled:NO) các segment Hold/Drop/Delay/Tamper không chạy được, hiện chú thích đỏ, tự đưa về Observe, và `ProcessManager` log `mode %u cannot be enforced on this device … falling back to Observe` thay vì `shaper failed` mỗi phiên. |
| **4.1.4** | **Sửa mojibake trong log + hiện đủ danh sách port.** Log 4.1.3 xác nhận hết freeze (`lanes=4 method=2`, không còn `SIGSTOP`) và capture tốt (`matched=264`, `read=363/193512B`, `err=0`), nhưng lộ hai lỗi hiển thị: (1) `injection unavailable) ‚Äî freeze is OFF` — vì `NSString` giải mã buffer `char[]` truyền qua `%s` bằng **`NSCStringEncoding` = MacRoman**, nên mọi ký tự ngoài ASCII trong **C string literal** bị vỡ (em-dash U+2014 → `‚Äî`, `…` → `‚Ä¶`); literal `@"..."` (UTF-16) thì không sao — đúng như log: phần `@"…"` hiện đúng, phần từ `errBuf` thì vỡ. Đổi **10** literal C sang ASCII thuần. (2) Dòng stats ghi `ports=5` nhưng chỉ liệt kê 4 port → đổi sang danh sách dựng động, hiện tối đa 8 rồi `+N more`. Không đổi logic bắt gói tin. |
| **4.1.3** | **Không còn freeze (SIGSTOP) app mặc định nữa.** Log 4.1.2 cho thấy capture đã chạy (`matched=13..51`, không còn `FATAL signal`) nhưng game bị **đứng hình**: `[shaper] pid … signal 17` → `SIGSTOP` → `lanes=12 method=4 — BPF tap + PF/freeze`. Nguyên nhân: mode đang là **Hold (0)**, và trên máy **không có pfctl/dnctl** lại **không inject được** (`task_for_pid → 0x5`), nên primitive duy nhất còn lại để "giữ" gói tin là **SIGSTOP** — tức đóng băng cả app. Nó bị kích hoạt **ngầm**, chỉ qua một dòng log. Sửa: thêm cờ `allowFreeze` trong shared state, **mặc định 0**, và `AetherShaperApply()` **chỉ** SIGSTOP khi user bật explicit; khi tắt: trả `-7`, log rõ ràng, **tiếp tục capture bình thường** (app vẫn chạy, vẫn có FPS). Thêm **switch "Freeze target (SIGSTOP)"** trong Settings (OFF mặc định, kèm chú thích). Migration `version < 413U` đưa mode về **Observe** và `allowFreeze = 0` → tự gỡ trạng thái kẹt trên máy bạn ngay khi cập nhật, không cần xoá app. `ProcessManager` phân biệt `-7` (không phải lỗi) và hiển thị `BPF tap on en0 (capture only — this mode needs freeze, which is OFF (Settings))`. |
| **4.1.2** | **Sửa SIGSEGV thật sự — tràn số nguyên trong bộ đi record BPF.** Symbolicate 8/8 crash trong log 4.1.1 đều cho **cùng một địa chỉ tĩnh**: `pc = base - 0x150C4`, `lr = pc - 0x28`, nằm trong `_AetherBPFIterateWithHeader` (`Core/L4Engine/AetherPacketCore.c:532`); 7 lần `phase=4 thread=tap`, 1 lần `phase=0 thread=other` (= probe 1 s, gọi **chung** hàm này). Giải mã lệnh tại `pc`: `ldr w3, [x9]` với `x9 = buffer + offset` → `offset` đã **vượt quá `len`**. Nguyên nhân: kernel đệm mỗi record lên bội của 4 byte, nên với record **cuối cùng** của một lần `read()`, `WORDALIGN(hdrlen + caplen)` có thể lớn hơn số byte thực có tới 3 byte; vòng lặp cộng phần đệm đó rồi tính `len - offset` kiểu `size_t` ⇒ **underflow** thành ~2⁶⁴ ⇒ cả điều kiện lặp lẫn chặn biên đều **vượt qua** ⇒ `buffer + offset` thành con trỏ rác ⇒ SIGSEGV. Đúng lý do crash chỉ xảy ra khi có frame (`match#5` xong là chết) và sao probe trên HUD thread cũng chết. Sửa: mọi bước nhảy đều tính theo `remaining = len - offset` (chỉ tính khi `offset <= len`), `break` khi `step >= remaining`. Thêm regression test **có guard page** (`PROT_NONE` ngay sau buffer): bản cũ chạy test này **`Segmentation fault` (exit 139)**, bản mới pass 41/41. |
| **4.1.1** | **Sửa SIGSEGV giết HUD daemon** (4/4 lần trong log 4.1.0: `[pid …] FATAL signal 11` vài giây sau khi tap chạy). Thủ phạm **không phải BPF** mà là **logging**: `AetherLogCurrentTimestamp()` dùng chung một **`NSDateFormatter`** — vốn **không thread-safe** — và timestamp được tính trên **luồng của người gọi**, nên main thread + tap thread + liveness thread log đồng thời ⇒ crash đúng lúc tap bắt đầu chạy. Đổi sang `gettimeofday` + `localtime_r` + `snprintf` (không trạng thái chia sẻ); `ensureLogQueue()` chuyển sang `dispatch_once`. Thêm: crash handler dùng `sigaction(SA_SIGINFO)` và in **`pc`, `lr`, `base`, `phase`, `thread`** → định vị được hàm crash bằng `nm`. Thêm `-resumeCaptureForPID:` huỷ nếu user đã tắt interception trong lúc daemon khởi động (log 4.1.0: STOP 11:27:18.828 mà resume vẫn dựng tap mới lúc 11:27:20.785 đè lên tap vừa gỡ). |
| **4.1.0** | **Chẩn đoán & phòng ngừa "tap câm":** thêm **luồng liveness độc lập** (log `[tap] liveness: loops=… frames=… lastData=…ms` mỗi 2 s) — nếu reader loop bị kẹt trong `read()` thì `loops=` đứng im, còn nếu tiến trình chết thì không có dòng nào: hai trường hợp trước đây **trông y hệt nhau** (im lặng). BPF descriptor chuyển sang **O_NONBLOCK** (+ `EAGAIN` không còn tính là lỗi) để `read()` không bao giờ block vô hạn; buffer BPF giảm 256 KB → **64 KB** (4 thiết bị × 256 KB = 1 MB **wired memory** là lý do jetsam khá hợp lý cho một plugin process nhỏ). Sửa **respawn giả**: app spawn daemon xong 64 ms đã bị watchdog respawn thêm một bản thứ hai (con cần ~300 ms để ghi pid file) — giờ có grace period. Thêm cảnh báo **rõ ràng** khi shaper đóng băng target bằng SIGSTOP (mọi báo cáo `matched=0` đến nay đều từ phiên bị freeze). |
| **4.0.9** | Sửa **nút biến mất vài giây sau khi bật interception**: (1) lane start chạy trên background queue thay vì main thread của daemon (chặn run loop ⇒ iOS `0x8badf00d` kill, câm hoàn toàn); (2) phát hiện **zombie** — daemon do `posix_spawn` sinh ra không bao giờ được `waitpid`, nên `kill(pid,0)` vẫn trả "sống", khiến UI hiện "Remove" cho một nút đã biến mất và làm mọi daemon mới spawn thoát ngay lập tức; watchdog giờ thu hồi zombie và log nguyên nhân chết (signal / exit code); (3) signal handler + uncaught-exception handler ghi bằng `AetherLogRawSync()` (async-signal-safe). Thêm phát hiện daemon **còn sống nhưng câm** (heartbeat > 8 s) → kill + respawn, và log `[tap] kernel frame ownership: pid=0 xN …` để phân biệt "target im lặng" với "kernel không gán được frame nào cho ai". |
| **4.0.8** | **Supervisor cho HUD daemon:** nó vốn có thể chết câm (jetsam / SpringBoard relaunch / bị thu hồi) và không ai khởi động lại; giờ app kiểm tra mỗi 2 s và respawn có log. Thêm `laneOwnerPID` để daemon chỉ tự nối lại capture khi chủ cũ đã chết (tránh đếm gói 2 lần) và không gỡ lane của tiến trình khác. |
| **4.0.7** | Sửa **nút floating tự biến mất** (trọng tài chạm: daemon ghi lại cú chạm đã xử lý, app bỏ qua cú chạm trùng) + daemon **tự nối lại phiên capture** sau khi bị restart. Sửa probe 1 s báo sai ("BPF handed out NOTHING") do đọc thiếu byte so với `bd_bufsize`; thêm log các flow đông nhất **chưa** gán được cho target để chẩn đoán `matched=0`. |
| **4.0.6** | **Sai layout record BPF:** `BPF_TIMEVAL` là `timeval32` (8 byte) trên LP64 ⇒ `caplen` ở offset **8** chứ không phải 16; ta đọc theo layout 28 byte nên vứt bỏ mọi record (`noframe` tăng đều). Giờ framing được **tự nhận diện** từ timestamp, mọi offset tính theo nó, và có test dùng chính bytes máy thật. |
| **4.0.5** | **Tìm ra và sửa nguyên nhân `seen=0`:** `bpfread()` của XNU đòi `read()` dài **đúng bằng** `bd_bufsize` (4096) trong khi ta đọc 256 KB ⇒ mọi `read()` trả `EINVAL`; `BIOCSBLEN` cũng phải gọi **trước** `BIOCSETIF`. Thêm **BIOCSEXTHDR** để kernel gắn thẳng PID + hướng vào từng gói tin (khớp chính xác thay vì đoán theo port). Shared memory được migrate khi nâng cấp, để mode cũ (Hold ⇒ SIGSTOP) không sống sót qua bản cập nhật. |

## Credits
- [opa334/TrollStore](https://github.com/opa334/TrollStore) — CoreTrust bypass & arbitrary entitlements
- [Lessica/TrollSpeed](https://github.com/Lessica/TrollSpeed) — HUD plugin-mode UIApplication & window hosting
- [facebook/fishhook](https://github.com/facebook/fishhook) — Mach-O symbol rebinding
- KIF (Square, MIT) qua TrollSpeed — touch synthesis
- newosxbook.com — tài liệu syscall/BSD & hệ thống control `PF_SYSTEM`
- Quinn “The Eskimo!” (Apple Developer Forums / Swift Forums) — xác nhận userspace networking
- Intercepter-NG / NetHunter — cảm hứng concept
