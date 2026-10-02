//
//  AetherXpcPrivate.h
//  AetherNet — Private xpc SPI declarations
//
//  xpc_pipe_create_from_port and xpc_pipe_routine_with_flags are NOT
//  in the public <xpc/xpc.h> — they live in <xpc/private.h> which is
//  not available in the iOS SDK. We resolve them via dlsym at runtime
//  from the default-loaded libxpc.dylib.
//
//  Under ARC, xpc_release maps to the Objective-C -release selector
//  which ARC forbids. We use C function pointers to avoid that.

#ifndef AetherXpcPrivate_h
#define AetherXpcPrivate_h

#include <xpc/xpc.h>
#include <mach/mach.h>
#include <stdint.h>
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

// ARC-safe wrapper for xpc_release (avoids Objective-C ARC selector conflict)
static inline void AetherXpcRelease(xpc_object_t obj) {
    if (obj) {
        // Call the C function directly — xpc_release is a C function in libxpc
        // ARC only blocks [obj release] (ObjC message send). The C function
        // call xpc_release(obj) is fine but may be ambiguous; use this wrapper.
        typedef void (*xpc_release_func)(xpc_object_t);
        static xpc_release_func _xpc_release = NULL;
        if (!_xpc_release) {
            _xpc_release = (xpc_release_func)dlsym(RTLD_DEFAULT, "xpc_release");
        }
        if (_xpc_release) _xpc_release(obj);
    }
}

static inline void AetherXpcRetain(xpc_object_t obj) {
    if (obj) {
        typedef void (*xpc_retain_func)(xpc_object_t);
        static xpc_retain_func _xpc_retain = NULL;
        if (!_xpc_retain) {
            _xpc_retain = (xpc_retain_func)dlsym(RTLD_DEFAULT, "xpc_retain");
        }
        if (_xpc_retain) _xpc_retain(obj);
    }
}

// Resolve private xpc pipe functions via dlsym (libxpc.dylib is always loaded)
static inline xpc_object_t AetherXpcPipeCreateFromPort(mach_port_t port, uint64_t flags) {
    typedef xpc_object_t (*create_from_port_func)(mach_port_t, uint64_t);
    static create_from_port_func _create = NULL;
    if (!_create) {
        _create = (create_from_port_func)dlsym(RTLD_DEFAULT, "xpc_pipe_create_from_port");
    }
    if (!_create) return NULL;
    return _create(port, flags);
}

static inline int AetherXpcPipeRoutineWithFlags(xpc_object_t pipe,
                                                xpc_object_t message,
                                                xpc_object_t *reply,
                                                uint32_t flags) {
    typedef int (*routine_func)(xpc_object_t, xpc_object_t, xpc_object_t *, uint32_t);
    static routine_func _routine = NULL;
    if (!_routine) {
        _routine = (routine_func)dlsym(RTLD_DEFAULT, "xpc_pipe_routine_with_flags");
    }
    if (!_routine) return -1;
    return _routine(pipe, message, reply, flags);
}

#ifdef __cplusplus
}
#endif

#endif /* AetherXpcPrivate_h */
