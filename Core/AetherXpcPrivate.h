//
//  AetherXpcPrivate.h
//  AetherNet — Private xpc SPI declarations
//
//  xpc types and functions — xpc is part of libsystem on iOS. When building
//  against sparse SDKs (e.g. theos/iPhoneOS16.5) <xpc/xpc.h> may be absent.
//  We forward-declare the opaque type and resolve all xpc functions via
//  dlsym at runtime from the always-loaded libsystem/xpc.
//
//  Under ARC, xpc_release maps to the Objective-C -release selector which
//  ARC forbids. We use C function pointers via dlsym to invoke them.

#ifndef AetherXpcPrivate_h
#define AetherXpcPrivate_h

#include <stdint.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque xpc type — resolves to objc_object* on modern iOS (xpc_object_t)
typedef struct _xpc_object *xpc_object_t;
typedef xpc_object_t xpc_t;

// Private SPI — resolved from libxpc.dylib at runtime via dlsym.
// These are NOT in public <xpc/xpc.h> headers.
static inline xpc_object_t xpc_dictionary_create_empty(void) {
    typedef xpc_object_t (*func_t)(void);
    static func_t _fn = NULL;
    if (!_fn) _fn = (func_t)dlsym(RTLD_DEFAULT, "xpc_dictionary_create_empty");
    if (!_fn) return NULL;
    return _fn();
}

static inline void xpc_dictionary_set_uint64(xpc_object_t xdict, const char *key, uint64_t value) {
    typedef void (*func_t)(xpc_object_t, const char *, uint64_t);
    static func_t _fn = NULL;
    if (!_fn) _fn = (func_t)dlsym(RTLD_DEFAULT, "xpc_dictionary_set_uint64");
    if (_fn) _fn(xdict, key, value);
}

static inline void xpc_dictionary_set_bool(xpc_object_t xdict, const char *key, bool value) {
    typedef void (*func_t)(xpc_object_t, const char *, bool);
    static func_t _fn = NULL;
    if (!_fn) _fn = (func_t)dlsym(RTLD_DEFAULT, "xpc_dictionary_set_bool");
    if (_fn) _fn(xdict, key, value);
}

static inline int64_t xpc_dictionary_get_int64(xpc_object_t xdict, const char *key) {
    typedef int64_t (*func_t)(xpc_object_t, const char *);
    static func_t _fn = NULL;
    if (!_fn) _fn = (func_t)dlsym(RTLD_DEFAULT, "xpc_dictionary_get_int64");
    if (!_fn) return 0;
    return _fn(xdict, key);
}

static inline const char *xpc_dictionary_get_string(xpc_object_t xdict, const char *key) {
    typedef const char *(*func_t)(xpc_object_t, const char *);
    static func_t _fn = NULL;
    if (!_fn) _fn = (func_t)dlsym(RTLD_DEFAULT, "xpc_dictionary_get_string");
    if (!_fn) return NULL;
    return _fn(xdict, key);
}

static inline xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint64_t flags) {
    typedef xpc_object_t (*func_t)(mach_port_t, uint64_t);
    static func_t _fn = NULL;
    if (!_fn) _fn = (func_t)dlsym(RTLD_DEFAULT, "xpc_pipe_create_from_port");
    if (!_fn) return NULL;
    return _fn(port, flags);
}

static inline int xpc_pipe_routine_with_flags(xpc_object_t pipe,
                                               xpc_object_t message,
                                               xpc_object_t *reply,
                                               uint32_t flags) {
    typedef int (*func_t)(xpc_object_t, xpc_object_t, xpc_object_t *, uint32_t);
    static func_t _fn = NULL;
    if (!_fn) _fn = (func_t)dlsym(RTLD_DEFAULT, "xpc_pipe_routine_with_flags");
    if (!_fn) return -1;
    return _fn(pipe, message, reply, flags);
}

// ARC-safe wrappers for xpc retain/release
static inline void AetherXpcRetain(xpc_object_t obj) {
    if (!obj) return;
    typedef void (*func_t)(xpc_object_t);
    static func_t _fn = NULL;
    if (!_fn) _fn = (func_t)dlsym(RTLD_DEFAULT, "xpc_retain");
    if (_fn) _fn(obj);
}

static inline void AetherXpcRelease(xpc_object_t obj) {
    if (!obj) return;
    typedef void (*func_t)(xpc_object_t);
    static func_t _fn = NULL;
    if (!_fn) _fn = (func_t)dlsym(RTLD_DEFAULT, "xpc_release");
    if (_fn) _fn(obj);
}

#ifdef __cplusplus
}
#endif

#endif /* AetherXpcPrivate_h */
