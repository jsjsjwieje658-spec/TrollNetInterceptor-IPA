# AetherNet — TrollStore L4 TCP/UDP Packet Interceptor & Global Floating HUD

> **Thể loại:** System-level network instrumentation tool (kiểu Intercepter-NG / NetHunter cho iOS)
> **Cơ chế cài:** TrollStore (iOS 14.0 – 16.6.1 / 17.0) — permasign với **arbitrary entitlements**
> **Ngôn ngữ:** Objective-C++ (UIKit + Mach + XNU libproc + fishhook)

---

## 1. Tổng quan kiến trúc

```
┌──────────────────────────────────────────────────────────────────────┐
│                     AetherNet.app (single binary)                    │
│                                                                      │
│  ┌───────────────────────┐      spawn (persona UID 0)                │
│  │  Main App UI (2 tab)  │ ────────────────────────────►  ┌────────┐ │
│  │  • Tab Home           │                                │  HUD   │ │
│  │  • Tab Settings       │ ◄── shared memory + Darwin ──  │ daemon │ │
│  └──────────┬────────────┘         notifications           └───┬────┘ │
│             │ task_for_pid()                                  │      │
│             ▼                                                 │      │
│  ┌────────────────────────┐                                   │      │
│  │ libNetHookPayload.dylib│  inject vào PID đích              │      │
│  │  fishhook rebind:      │  (remote thread → dlopen)         │      │
│  │  send / sendto /       │                                   │      │
│  │  sendmsg / recv /      │                                   │      │
│  │  recvfrom / recvmsg    │                                   │      │
│  └────────────────────────┘                                   │      │
└──────────────────────────────────────────────────────────────────────┘
```

**3 thành phần chạy song song, đồng bộ qua `mmap` shared memory (lock-free atomics):**

1. **Main App** — UI 2 tab (Home / Settings), liệt kê process qua `sysctl(KERN_PROC_ALL)`, đếm
   socket TCP/UDP của từng PID qua XNU SPI `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`.
2. **HUD daemon (`-hud`)** — cùng binary chạy lại ở chế độ *plugin-mode UIApplication* với
   **UID 0** (posix_spawn persona), host 1 `UIWindow` hệ thống **windowLevel 10000010.0** đăng ký
   qua `SBSAccessibilityWindowHostingController` → nút tròn nổi lên **tất cả** tiến trình.
3. **Payload dylib** — được inject vào PID đích, rebind symbol `send/sendto/sendmsg/recv/recvfrom/
   recvmsg` bằng **fishhook** (__DATA `__la_symbol_ptr`/`__nl_symbol_ptr`) → chặn toàn bộ packet
   tầng L4 (TCP stream + UDP datagram) theo cấu hình trong shared memory.

---

## 2. Research & nghiên cứu quyền (entitlements) — tại sao app cần từng quyền

Tham khảo trực tiếp từ mã nguồn **TrollSpeed** (`supports/entitlements.plist` của Lessica/82flex),
tài liệu **TrollStore** của opa334 và cơ chế `assistivetouchd` của Apple:

| Entitlement | Lý do bắt buộc | Nguồn tham khảo |
|---|---|---|
| `platform-application` | Biến app thành platform binary → AMFI chấp nhận private entitlements | TrollStore README |
| `com.apple.private.security.no-sandbox` | Thoát sandbox: đọc `/proc`-style socket info, ghi dylib ra `/var/mobile/Library/Caches`, map shared memory liên tiến trình | TrollStore README |
| `com.apple.private.persona-mgmt` | `posix_spawnattr_set_persona_np` **spawn con với UID 0/GID 0** → HUD daemon sống sót qua lock/unlock (nếu không sẽ bị SpringBoard giết) | TrollSpeed `HUDHelper.mm` |
| `task_for_pid-allow` + `get-task-allow` + `com.apple.system-task-ports.*` | **`task_for_pid()` lấy Mach task port của PID đích** → `mach_vm_allocate/write` + `thread_create_running` gọi `dlopen` từ xa (inject dylib) | Debugging entitlements (debugserver) |
| `com.apple.springboard.accessibility-window-hosting` + `com.apple.backboard.client` | Đăng ký window **tồn tại ngoài app** (`SBSAccessibilityWindowHostingController.registerWindowWithContextID:atLevel:`) → nút nổi trên mọi process | TrollSpeed |
| `com.apple.QuartzCore.displayable-context` / `secure-mode` | Cho phép context render ngoài UIProcess của app (secure = không bị che trong screenshot nếu muốn) | TrollSpeed |
| `com.apple.private.hid.client.*` (event-dispatch / event-filter / event-monitor / manager) | Nhận & tổng hợp touch event cho nút nổi qua **BackBoard HID pipeline** (`BKSHIDEventRegisterEventCallback`) | TrollSpeed `TSEventFetcher` |
| `com.apple.private.kernel.jetsam` + `com.apple.private.memorystatus` | HUD daemon root không bị jetsam kill khi device hết RAM | TrollSpeed `JetsamHelper` |
| `com.apple.springboard.CFUserNotification` / `appbackgroundstyle` | Tương thích hiển thị hệ thống khi HUD active | TrollSpeed |
| `file-read-data` + `user-preference-read/write` | Đọc path process, cấu hình persists | TrollStore |
| `com.apple.private.network.socket-delegate` + `com.apple.private.necp.*` | Gắn policy L4 vào NECP (Network Extension Control Policy) — dùng cho root fallback engine khi PPL chặn `task_for_pid` | NEHelper/NEKit |

> **Lưu ý quan trọng (A12+ / iOS 15+):** 3 entitlement chạy code unsigned
> (`dynamic-codesigning`, `csdebugger`, `get-task-allow` dạng JIT) bị **PPL chặn vĩnh viễn**.
> Vì vậy injector có **3 tầng hoạt động** (chi tiết tầng 0 ở mục 2b):
> - **Tier 0 — Dopamine 3.x PPL-Bypass Bridge:** nếu thiết bị cài Dopamine (rootless), app gọi
>   thẳng jbserver của Dopamine trong launchd qua XPC → trust dylib vào kernel trust cache +
>   `cs_allow_invalid()` target PID → **Mach inject hoạt động dù PPL/SPTM** (15.0–17.3.1 arm64e).
> - **Tier 1 — Mach inject:** `task_for_pid → mach_vm_allocate → thread_create_running(dlopen)`
>   (hoạt động tốt trên iOS 14.0–16.6.1 A8–A11, và 17.0 KFD).
> - **Tier 2 — Root socket/PF engine:** nếu Tier 0+1 fail (PPL, không có Dopamine), dùng
>   persona-UID-0 + `pfctl` anchor theo PID/port + conditioning trong shared-state để giữ/drop/
>   delay packet — **không cần inject code** nhưng vẫn kiểm soát được TCP/UDP theo cấu hình.

---

## 2b. Research Dopamine 3.x — phương pháp "fix PPL chặn" & cách AetherNet tận dụng

Nghiên cứu trực tiếp mã nguồn **opa334/Dopamine nhánh `3.x` (v3.0.10, 09/2026)** — clone về và
đọc: `BaseBin/libjailbreak/src/`, `BaseBin/launchdhook/src/jbserver/`, `BaseBin/boomerang/`.

### Cơ chế PPL bypass của Dopamine hoạt động thế nào?

```
┌─────────────┐  exploit kernel    ┌──────────────────────────────────────────┐
│ Dopamine.app│ ─────────────────► │ physrw / physrw_pte / kcall (kernel R/W) │
└─────────────┘                    └───────────────┬──────────────────────────┘
                                                   │ boomerang: stash primitives
                                                   ▼ (spawn /basebin/boomerang,
       ┌────────────────────────────────────────────┐  registered ports → launchd recover)
       │ launchd (launchdhook + jbserver bên trong) │
       │  → có toàn quyền ghi kernel, gồm vùng      │
       │    PPL/SPTM/TXM bảo vệ (Titan PPL/SPTM     │
       │    bypass của AlfieCG cho 16.5.1–17.3.1)   │
       └───────────────┬────────────────────────────┘
                       │ XPC domains (jbserver_domains.h)
        ┌──────────────┼───────────────────────────┐
        ▼              ▼                           ▼
  SYSTEMWIDE       PLATFORM                   ROOT
  (mọi process)    (CS_PLATFORMIZED /         (process root)
   get_jbroot       platform-application ← ★   physrw, sign_thread,
   trust_file ★     = app TrollStore của ta!)  trustcache_add_cdhash
```

**Điểm mấu chốt — `cs_allow_invalid(proc, fullyDebugged)` trong `kernel.c`:** đây chính là
"phương pháp fix PPL chặn" mà ta cần. Khi được gọi qua action
`JBS_PLATFORM_SET_PROCESS_DEBUGGED`, Dopamine dùng kernel R/W để:

```c
proc_csflags_clear(proc, CS_KILL | CS_HARD);   // không cho kernel kill target
proc_csflags_set(proc, CS_DEBUGGED);           // target như đang bị debugger gắn
vm_map.flags.cs_debugged = true;               // tắt cs_enforcement của vm_map
pmap_cs_allow_invalid(pmap);                   // arm64e/SPTM: ghi allowsInvalidCode=true
                                               // vào TXMAddressSpace (iOS 17+) hoặc
                                               // wx_allowed=true trong pmap (pmap_cs)
```

→ Sau đó target PID **chấp nhận code unsigned/thiếu trust cache** — chính là điều PPL
chặn — nên `dlopen` từ xa (remote-thread injection) của ta chạy được.

**Vì sao app TrollStore của ta gọi được API này?** File
`launchdhook/src/jbserver/jbdomain_platform.c` xác thực client:

```c
static bool platform_domain_allowed(audit_token_t clientToken) {
    ...
    return (csflags & CS_PLATFORM_BINARY);   // ← chỉ cần platform binary!
}
```

App ta ký bằng entitlement **`platform-application`** → AMFI gắn cờ `CS_PLATFORM_BINARY`
lúc launch → qua cửa PLATFORM ngay. Wire protocol cũng đơn giản (mình tái implement trong
`Core/DopamineBridge.mm`, không cần libjailbreak): XPC dict qua **launchd bootstrap port**
(`task_get_bootstrap_port` → `xpc_pipe_create_from_port` → `xpc_pipe_routine_with_flags`),
keys `jb-domain`/`action` + args:

| Bước | Domain/Action | Args | Hiệu quả |
|---|---|---|---|
| Probe | `1 / 1` GET_JBROOT | — | reply `root-path` → biết Dopamine đang chạy |
| Trust dylib | `1 / 3` TRUST_FILE | `fd` (server resolve path qua audit token + `proc_pidfdinfo`) | `libNetHookPayload.dylib` vào kernel trust cache |
| Set debugged | `2 / 1` SET_PROCESS_DEBUGGED | `pid`, `fully-debugged` | `cs_allow_invalid()` target → **PPL hết chặn** |

###Luồng inject mới của AetherNet

```
Chọn PID → [Tier 0] DopamineAvailable()? → trust_file + set_process_debugged
         → [Tier 1] Mach inject (task_for_pid → remote dlopen)   ← giờ luôn thành công khi có Dopamine
         → [Tier 2] Fallback: Root PF/socket engine (không cần inject)
```

Pill trạng thái trên Tab Home hiển thị `INJECTED · DYLIB HOOKS + PPL BYPASS (DOPAMINE)`
khi Tier 0 được dùng. Không cài Dopamine → app vẫn chạy như cũ (Tier 1 trên thiết bị cũ,
Tier 2 trên thiết bị PPL).

**Phạm vi hỗ trợ của Tier 0:** Dopamine 3.x = iOS 15.0–17.3.1 (arm64e), 15.0–18.7.1,
26.0–26.0.1 (A12/A13 — Titan PPL/SPTM bypass của AlfieCG + exploit kernel darksword).
*Tier 0 chỉ có tác động khi thiết bị đã jailbreak bằng Dopamine; bản thân TrollStore
không (và không thể) tự bypass PPL.*

---

## 3. Chức năng chi tiết

### Tab Home
- **Box chữ nhật lớn** → bấm mở **sheet chọn PID** (search theo tên / PID / bundle id,
  lọc "User Apps" hoặc "All Processes", hiện icon app + số socket TCP/UDP đang mở của từng tiến trình).
- Sau khi chọn: hiển thị **tên app, PID, bundle id, trạng thái INJECTED** (pill xanh) và tier
  inject đang dùng (Mach dylib hooks / Root engine).
- **Card L4 Network Status:** 2 lane TCP (teal) & UDP (blue) — số socket active, packet
  count RX/TX, tốc độ B/s live, số packet đang **Held** và đã **Dropped**.
- **Card Global Floating HUD:** mini preview nút tròn + nút vàng **"Create Floating Button"**
  → spawn HUD daemon root (nút nổi trên mọi process). Bấm lần nữa → Remove.

### Floating Button (toàn hệ thống)
- **Hình tròn** viền titanium + ring logo orbital (quay chậm khi active) + badge số packet giữ.
- **Tắt:** icon **tam giác ▶** giữa hình tròn (standby).
- **Bật:** icon **2 gạch song song ⏸** (kiểu pause video) — đang bắt giữ packet TCP/UDP.
- Kéo tự do, **edge snap** magnet, lưu vị trí, haptic feedback.
- Kích thước/độ mờ chỉnh ở Tab Settings (40–88 pt / 35–100%).

### Tab Settings
| Nhóm | Tuỳ chỉnh |
|---|---|
| **Interception Rules** | Hướng bắt: `Both / Download only / Upload only` · Protocol: `TCP+UDP / UDP only / TCP only` · Mode: `Hold / Drop / Delay+Jitter / Tamper` · **Master capture ratio 0–100 %** · riêng **Download (RX) ratio** và **Upload (TX) ratio** |
| **Network Simulation** | Preset `Normal / Ghost-Freeze / Lag Spike / Degraded 3G / TCP-RST` · Latency RTT 0–1500 ms · Jitter 0–500 ms · **Bandwidth cap** 64 kbps–20 Mbps (log) · Duplicate UDP % · Auto-flush `Off/5s/12s/30s` (chống treo app) |
| **Floating Button** | **Diameter slider 40–88 pt** · Opacity 35–100 % · Edge snap · Lock position · Haptics |

---

## 4. Cấu trúc source

```
TrollNetInterceptor/
├── main.mm                       # Dispatcher: -hud / -exit / -check / normal app
├── supports/
│   ├── entitlements.plist        # ★ Toàn bộ entitlements đã research (mục 2)
│   └── Info.plist
├── headers/
│   ├── AetherNetShared.h         # Shared memory struct (app ⇄ HUD ⇄ payload)
│   └── PrivateSystemSPI.h        # Kernel/libproc/BackBoard/SBS private SPI
├── Core/
│   ├── DopamineBridge.h/.mm      # ★ Tier 0: Dopamine 3.x XPC bridge (PPL bypass)
│   ├── AetherSharedMemory.mm     # mmap IPC lock-free (atomic C11)
│   ├── ProcessManager.h/.mm      # sysctl proc list + proc_pidfdinfo socket telemetry
│   │                             # + posix_spawn persona-0 HUD daemon
│   └── MachInjector.mm           # task_for_pid remote-thread dlopen + pfctl fallback
├── Payload/
│   ├── fishhook.h/.c             # Facebook fishhook (MIT/BSD) — symbol rebinding
│   └── NetHookPayload.mm         # send/sendto/sendmsg/recv/recvfrom/recvmsg hooks
├── HUD/
│   ├── HUDMain.mm                # Plugin-mode UIApplication bootstrap (TrollSpeed-style)
│   ├── HUDRootApplication.mm     # SBSAccessibilityWindowHostingController @ level 1e7
│   ├── HUDMainWindow.h/.mm       # Passthrough hit-test (chỉ chạm đúng nút mới ăn)
│   └── FloatingToggleButton.h/.mm# Nút tròn logo + ▶/⏸ morph + drag/snap/badge
├── UI/
│   ├── AppTheme.h/.mm            # Obsidian × Champagne gold design system
│   ├── MainApp.mm                # UIApplicationMain (no-UIScene) + TabBar + rate ticker
│   ├── HomeViewController.*      # Tab 1
│   └── SettingsViewController.*  # Tab 2
├── project.yml                   # XcodeGen project spec
└── scripts/build.sh              # xcodegen → xcodebuild → ldid -S entitlements → .tipa
```

---

## 5. Build & cài đặt

### 5a. Build trên Linux (đã build sẵn — `AetherNet.tipa` / `AetherNet.ipa` trong repo)

Toolchain dùng: `clang 19` (target `arm64-apple-ios14.0`) + `ld64.lld` + **iPhoneOS16.5 SDK**
(theos/sdks, sparse-checkout) + `ldid` (Procursus) — ký entitlements bằng fake root cert,
TrollStore sẽ giữ nguyên entitlements khi permasign.

```bash
sudo apt-get install -y clang lld
curl -Lo ~/.cache/ldid https://github.com/ProcursusTeam/ldid/releases/latest/download/ldid_linux_x86_64 && chmod +x ~/.cache/ldid
git clone --depth=1 --filter=blob:none --sparse https://github.com/theos/sdks.git ~/.cache/sdk-repo
cd ~/.cache/sdk-repo && git sparse-checkout set iPhoneOS16.5.sdk && cd -
./scripts/crossbuild-linux.sh          # → AetherNet.tipa
```

Build sản phẩm: `Payload/AetherNet.app` chứa binary `AetherNet` (arm64 PIE, 38 entitlement keys
đã nhúng), `libNetHookPayload.dylib` (hook payload), icon 120/180px, Info.plist
(`com.aethernet.interceptor`, MinimumOSVersion 14.0).

### 5b. Build trên macOS (Xcode — tuỳ chọn)

```bash
brew install xcodegen ldid
./scripts/build.sh all                 # xcodegen → xcodebuild arm64 → ldid → .tipa
```

### Cài lên iPhone

1. Copy `AetherNet.tipa` vào máy (AirDrop / Files / URL install)
2. Mở bằng **TrollStore** → Install
3. Mở AetherNet → Tab Home → bấm box chọn PID → **Create Floating Button**

**Yêu cầu thiết bị:** iOS 14.0 – 16.6.1 hoặc 17.0 với TrollStore 2 (A8–A17). Trên A12+/iOS 15+,
tier Mach-inject có thể bị PPL chặn → app tự chuyển Root Engine (tier 2) tự động.

### Troubleshooting

**Crash khi mở app — `symbol not found in flat namespace '___isPlatformVersionAtLeast'` (SIGABRT, DYLD):**
Đã fix từ bản **2.4.1 (build 241)**. Nguyên nhân: `@available(...)` trong code sinh tham chiếu tới
helper `__isPlatformVersionAtLeast` của Apple compiler-rt, vốn không tồn tại khi cross-build từ
Linux. `Core/compiler_rt_shim.c` giờ tự triển khai helper này (đọc `kern.osproductversion` qua
sysctl) và nhúng thẳng vào cả executable lẫn dylib — dyld không còn tra symbol ngoài nữa.

**Nút floating bấm không ăn / không kéo được / không tắt được:**
Đã fix trọn bộ ở bản **2.5.0 (build 250)**:
- *Không tắt được*: HUD daemon chạy ROOT còn app chạy uid 501 — `kill(pid, 0)` trả `EPERM`
  (process có tồn tại nhưng không có quyền signal) → app tưởng HUD chưa chạy, không bao giờ
  gọi đường Remove. Giờ `EPERM` được coi là "đang chạy".
- *Bấm/kéo không ăn*: port đúng cơ chế TrollSpeed — `BKSHIDEventRegisterEventCallback` →
  `AXEventRepresentation` → `TSEventFetcher` (KIF touch synthesis) → gesture recognizers hoạt
  động trong plugin-mode process. Kèm fix C-linkage cho `IOHIDEvent*` (tránh mangled symbol).
- *Kích thước/vị trí lạ*: bump shm magic → state rác của bản cũ bị reset; clamp 40–88pt +
  clamp vị trí trong màn hình khi đọc từ shared memory.

---

## 6. Cảnh báo pháp lý & đạo đức

Công cụ này can thiệp vào **tiến trình và network stack của thiết bị bạn sở hữu** — dùng để
phân tích giao thức, nghiên cứu game networking, test resilience ứng dụng trên **máy của bạn**.
Không dùng để can thiệp thiết bị/thông tin của người khác. Mọi rủi ro (bootloop app, crash
process đích, vi phạm ToS của game/app) do người dùng tự chịu.

## Credits
- [opa334/TrollStore](https://github.com/opa334/TrollStore) — CoreTrust bypass & arbitrary entitlements
- [opa334/Dopamine](https://github.com/opa334/Dopamine) 3.x — PPL/SPTM bypass, jbserver XPC protocol & cs_allow_invalid (Tier 0)
- [Lessica/TrollSpeed](https://github.com/Lessica/TrollSpeed) — HUD plugin-mode UIApplication & window hosting kiến trúc
- [facebook/fishhook](https://github.com/facebook/fishhook) — Mach-O symbol rebinding
- Intercepter-NG / NetHunter — cảm hứng concept
