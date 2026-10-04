//
//  MachInjector.mm
//  AetherNet — remote dylib injection + shared-state handoff
//
//  Injection is a two-step job:
//
//   1. dlopen() the payload inside the target through a remote Mach thread.
//   2. Hand the target a *mapping* of our shared state.  The payload can
//      usually not open /var/mobile/Library/Caches/… itself (App Store apps are
//      sandboxed), so we map the very pages we are already using into the
//      target with mach_make_memory_entry_64 + mach_vm_map, then call
//      AetherSharedStateAdopt() there with a second remote thread.
//
//  Step 2 is best-effort: when it fails (older kernels, hardened targets) the
//  payload falls back to opening the file itself, and when that fails too the
//  payload stays dormant instead of misbehaving.
//

#import <Foundation/Foundation.h>

#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../Core/AetherLog.h"
#include "../headers/AetherNetShared.h"
#include "../headers/PrivateSystemSPI.h"

extern "C" char **environ;

// ===========================================================================
// 0. Remote-thread helper
// ===========================================================================
static int AetherRemoteCall(mach_port_t task,
                            uint64_t functionAddress,
                            uint64_t arg0,
                            char *errBuf, size_t errBufLen) {
    mach_vm_address_t remoteStack = 0;
    mach_vm_size_t    stackSize   = 0x8000;
    kern_return_t kr = mach_vm_allocate(task, &remoteStack, stackSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        snprintf(errBuf, errBufLen, "mach_vm_allocate(stack) failed: 0x%x", kr);
        return -1;
    }

#if defined(__arm64__) || defined(__aarch64__)
    arm_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    state.__x[0] = arg0;
    state.__sp   = (uint64_t)(remoteStack + (stackSize / 2));
    state.__pc   = functionAddress;

    thread_act_t thread = MACH_PORT_NULL;
    kr = thread_create_running(task, ARM_THREAD_STATE64,
                               (thread_state_t)&state, ARM_THREAD_STATE64_COUNT, &thread);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(thread)) {
        snprintf(errBuf, errBufLen, "thread_create_running failed: 0x%x", kr);
        mach_vm_deallocate(task, remoteStack, stackSize);
        return -2;
    }
    mach_port_deallocate(mach_task_self(), thread);
    mach_vm_deallocate(task, remoteStack, stackSize);
    return 0;
#else
    (void)functionAddress; (void)arg0; (void)task;
    snprintf(errBuf, errBufLen, "remote call unsupported on this architecture");
    mach_vm_deallocate(task, remoteStack, stackSize);
    return -3;
#endif
}

// ===========================================================================
// 1. Locating a symbol inside the copy of the dylib we just dlopen'd remotely
// ===========================================================================

// Minimal mirror of <mach-o/dyld_images.h> — we only read the first fields.
#ifndef _MACH_O_DYLD_IMAGES_
struct aether_dyld_all_image_infos {
    uint32_t version;
    uint32_t infoArrayCount;
    uint64_t infoArray;          // struct dyld_image_info *
    uint64_t notification;
    uint64_t processDetachedFromSharedRegion;
    uint64_t libSystemInitialized;
    uint64_t dyldImageLoadAddress;
};
#endif

/// Find the load address of `pathSuffix` inside `task`.
static uint64_t AetherRemoteImageAddress(mach_port_t task, const char *pathSuffix) {
    struct task_dyld_info info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS || info.all_image_info_addr == 0) return 0;

    struct aether_dyld_all_image_infos all;
    memset(&all, 0, sizeof(all));
    mach_vm_size_t outSize = 0;
    kr = mach_vm_read_overwrite(task, (mach_vm_address_t)info.all_image_info_addr,
                                sizeof(all), (mach_vm_address_t)&all, &outSize);
    if (kr != KERN_SUCCESS || all.infoArray == 0) return 0;

    uint32_t maxImages = all.infoArrayCount > 512 ? 512 : all.infoArrayCount;
    for (uint32_t i = 0; i < maxImages; i++) {
        uint64_t entryAddr = all.infoArray + (uint64_t)i * 24ull;
        uint64_t entry[3] = { 0, 0, 0 };
        outSize = 0;
        kr = mach_vm_read_overwrite(task, (mach_vm_address_t)entryAddr,
                                    sizeof(entry), (mach_vm_address_t)entry, &outSize);
        if (kr != KERN_SUCCESS) continue;
        if (entry[1] == 0) continue;

        char path[PATH_MAX];
        memset(path, 0, sizeof(path));
        outSize = 0;
        kr = mach_vm_read_overwrite(task, (mach_vm_address_t)entry[1],
                                    sizeof(path) - 1, (mach_vm_address_t)path, &outSize);
        if (kr != KERN_SUCCESS) continue;
        if (strstr(path, pathSuffix) != NULL) {
            return entry[0];
        }
    }
    return 0;
}

/// Read the offset of `symbol` (without leading underscore) inside a Mach-O
/// file, relative to its __TEXT segment.  Returns 0 when not found.
static uint64_t AetherSymbolOffsetInFile(const char *filePath, const char *symbol) {
    FILE *f = fopen(filePath, "rb");
    if (!f) return 0;

    struct mach_header_64 mh;
    if (fread(&mh, 1, sizeof(mh), f) != sizeof(mh)) { fclose(f); return 0; }
    if (mh.magic != MH_MAGIC_64 && mh.magic != MH_CIGAM_64) { fclose(f); return 0; }

    uint64_t textVmaddr = 0;
    uint32_t symOff = 0, nSyms = 0, strOff = 0, strSize = 0;

    fseek(f, sizeof(mh), SEEK_SET);
    for (uint32_t i = 0; i < mh.ncmds; i++) {
        struct load_command lc;
        long pos = ftell(f);
        if (fread(&lc, 1, sizeof(lc), f) != sizeof(lc)) break;
        fseek(f, pos, SEEK_SET);

        if (lc.cmd == LC_SEGMENT_64) {
            struct segment_command_64 seg;
            if (fread(&seg, 1, sizeof(seg), f) == sizeof(seg)) {
                if (strncmp(seg.segname, "__TEXT", 6) == 0) textVmaddr = seg.vmaddr;
            }
        } else if (lc.cmd == LC_SYMTAB) {
            struct symtab_command st;
            if (fread(&st, 1, sizeof(st), f) == sizeof(st)) {
                symOff = st.symoff; nSyms = st.nsyms;
                strOff = st.stroff; strSize = st.strsize;
            }
        }
        fseek(f, pos + (long)lc.cmdsize, SEEK_SET);
    }

    if (!symOff || !nSyms || !strSize) { fclose(f); return 0; }

    // String table
    char *strtab = (char *)malloc(strSize + 1);
    if (!strtab) { fclose(f); return 0; }
    fseek(f, (long)strOff, SEEK_SET);
    if (fread(strtab, 1, strSize, f) != strSize) { free(strtab); fclose(f); return 0; }
    strtab[strSize] = '\0';

    uint64_t result = 0;
    fseek(f, (long)symOff, SEEK_SET);
    for (uint32_t i = 0; i < nSyms; i++) {
        struct nlist_64 nl;
        if (fread(&nl, 1, sizeof(nl), f) != sizeof(nl)) break;
        uint32_t idx = nl.n_un.n_strx;
        if (idx == 0 || idx >= strSize) continue;
        const char *name = strtab + idx;
        if (name[0] == '_') name++;                    // Mach-O C symbol prefix
        if (strncmp(name, symbol, strlen(symbol) + 1) == 0) {
            result = nl.n_value ? (nl.n_value - textVmaddr) : 0;
            break;
        }
    }

    free(strtab);
    fclose(f);
    return result;
}

// ===========================================================================
// 2. Public: dlopen the payload inside the target
// ===========================================================================
extern "C" int AetherInjectDylibIntoPID(pid_t pid, const char *dylibPath,
                                        char *errBuf, size_t errBufLen) {
    if (pid <= 0 || !dylibPath) {
        snprintf(errBuf, errBufLen, "invalid arguments");
        return -1;
    }

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
        snprintf(errBuf, errBufLen, "task_for_pid(%d) failed: 0x%x (%s)",
                 pid, kr, mach_error_string(kr));
        return -2;
    }

    mach_vm_size_t    stackSize     = 0x8000;
    mach_vm_size_t    pathAllocSize = 0x1000;
    mach_vm_address_t remoteStack   = 0;
    mach_vm_address_t remotePath    = 0;

    kr = mach_vm_allocate(task, &remoteStack, stackSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "mach_vm_allocate(stack) failed: 0x%x", kr);
        return -3;
    }
    kr = mach_vm_allocate(task, &remotePath, pathAllocSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(task, remoteStack, stackSize);
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "mach_vm_allocate(path) failed: 0x%x", kr);
        return -4;
    }

    size_t pathLen = strlen(dylibPath) + 1;
    kr = mach_vm_write(task, remotePath, (vm_offset_t)dylibPath,
                       (mach_msg_type_number_t)pathLen);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(task, remotePath, pathAllocSize);
        mach_vm_deallocate(task, remoteStack, stackSize);
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "mach_vm_write(dylibPath) failed: 0x%x", kr);
        return -5;
    }
    mach_vm_protect(task, remoteStack, stackSize, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    mach_vm_protect(task, remotePath, pathAllocSize, FALSE, VM_PROT_READ);

    void *dlopenAddr = dlsym(RTLD_DEFAULT, "dlopen");
    if (!dlopenAddr) {
        mach_vm_deallocate(task, remotePath, pathAllocSize);
        mach_vm_deallocate(task, remoteStack, stackSize);
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "cannot resolve dlopen locally");
        return -6;
    }

    int rc = AetherRemoteCall(task, (uint64_t)(uintptr_t)dlopenAddr,
                              (uint64_t)remotePath, errBuf, errBufLen);
    mach_vm_deallocate(task, remotePath, pathAllocSize);
    mach_vm_deallocate(task, remoteStack, stackSize);
    mach_port_deallocate(mach_task_self(), task);
    if (rc != 0) return -7;

    AetherLogDaemon(@"[inject] dlopen(%s) dispatched into pid %d", dylibPath, pid);
    return 0;
}

// ===========================================================================
// 3. Public: map our shared state into the target and adopt it there
// ===========================================================================
extern "C" int AetherAdoptSharedStateIntoPID(pid_t pid, const char *dylibPath,
                                             char *errBuf, size_t errBufLen) {
    if (pid <= 0 || !dylibPath) {
        snprintf(errBuf, errBufLen, "invalid arguments");
        return -1;
    }

    AetherSharedState *local = AetherGetSharedState();
    if (!local) {
        snprintf(errBuf, errBufLen, "local shared state unavailable");
        return -2;
    }

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
        snprintf(errBuf, errBufLen, "task_for_pid(%d) failed: 0x%x", pid, kr);
        return -3;
    }

    // Give the payload time to finish its constructor.
    usleep(150000);

    // 3.1 — where did our dylib land in the target?
    const char *leaf = strrchr(dylibPath, '/');
    leaf = leaf ? leaf + 1 : dylibPath;
    uint64_t imageAddr = AetherRemoteImageAddress(task, leaf);
    if (imageAddr == 0) {
        // Second chance: the payload may not be in the dyld image list yet.
        usleep(400000);
        imageAddr = AetherRemoteImageAddress(task, leaf);
    }
    if (imageAddr == 0) {
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "dylib image not found in pid %d (dlopen failed?)", pid);
        return -4;
    }

    uint64_t adoptOffset = AetherSymbolOffsetInFile(dylibPath, "AetherSharedStateAdopt");
    if (adoptOffset == 0) {
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "symbol AetherSharedStateAdopt not found in payload");
        return -5;
    }

    // 3.2 — map the pages we are using into the target
    uint64_t regionAddr = (uint64_t)(uintptr_t)local;
    uint64_t pageSize   = (uint64_t)getpagesize();
    uint64_t pageMask   = pageSize - 1ull;
    mach_vm_address_t pageAligned = (mach_vm_address_t)(regionAddr & ~pageMask);
    uint64_t span = ((sizeof(AetherSharedState) +
                     (size_t)(regionAddr - (uint64_t)pageAligned)) + pageMask) & ~pageMask;

    uint64_t entrySize = span;
    mach_port_t memEntry = MACH_PORT_NULL;
    mach_port_t parentEntry = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(mach_task_self(), &entrySize,
                                   (memory_object_offset_t)pageAligned,
                                   VM_PROT_READ | VM_PROT_WRITE,
                                   &memEntry, parentEntry);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(memEntry)) {
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "mach_make_memory_entry_64 failed: 0x%x", kr);
        return -6;
    }

    mach_vm_address_t remoteRegion = 0;
    kr = mach_vm_map(task, &remoteRegion, (mach_vm_size_t)span, 0, VM_FLAGS_ANYWHERE,
                     memEntry, 0, FALSE,
                     VM_PROT_READ | VM_PROT_WRITE,
                     VM_PROT_READ | VM_PROT_WRITE,
                     VM_INHERIT_NONE);
    mach_port_deallocate(mach_task_self(), memEntry);
    if (parentEntry != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), parentEntry);

    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), task);
        snprintf(errBuf, errBufLen, "mach_vm_map into pid %d failed: 0x%x", pid, kr);
        return -7;
    }

    // 3.3 — tell the payload about it
    uint64_t remoteStateAddr = (uint64_t)remoteRegion +
                               ((uint64_t)(uintptr_t)local - (uint64_t)pageAligned);
    int rc = AetherRemoteCall(task, imageAddr + adoptOffset, remoteStateAddr,
                              errBuf, errBufLen);
    mach_port_deallocate(mach_task_self(), task);
    if (rc != 0) {
        mach_vm_deallocate(task, remoteRegion, (mach_vm_size_t)span);
        return -8;
    }

    AetherLogDaemon(@"[inject] shared state handed to pid %d (remote=0x%llx, %llu bytes)",
                    pid, (unsigned long long)remoteStateAddr, (unsigned long long)span);
    return 0;
}

/// Convenience: inject, then hand over the shared state.  Injection success is
/// reported even when the handoff fails — the payload may still reach the file.
extern "C" int AetherInjectAndArm(pid_t pid, const char *dylibPath,
                                  char *errBuf, size_t errBufLen) {
    int rc = AetherInjectDylibIntoPID(pid, dylibPath, errBuf, errBufLen);
    if (rc != 0) return rc;

    char adoptErr[256] = {0};
    int arc = AetherAdoptSharedStateIntoPID(pid, dylibPath, adoptErr, sizeof(adoptErr));
    if (arc != 0) {
        AetherLogDaemon(@"[inject] handoff skipped: %s", adoptErr);
    }
    return 0;
}
