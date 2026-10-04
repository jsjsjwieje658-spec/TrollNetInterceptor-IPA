# =============================================================================
#  AetherNet — host simulation harness (Linux / build host)
#
#   make            build every test binary
#   make test       build + run the full suite
#   make clean
#
#  The harness compiles the *device* sources for the portable core:
#     Core/L4Engine/AetherPacketCore.c    (parsers, flow table, policy engine)
#     Payload/AetherHookCore.c            (hold queue, send/recv policy)
#     headers/AetherNetShared.h           (shared-memory contract)
#  and drives them with real UDP/TCP traffic over loopback.
# =============================================================================

CC      ?= gcc
CFLAGS  ?= -O1 -g -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
LDFLAGS ?= -lpthread

ROOT     := $(abspath ../..)
BUILD    := build

CORE_SRC := $(ROOT)/Core/L4Engine/AetherPacketCore.c
HOOK_SRC := $(ROOT)/Payload/AetherHookCore.c
HOST_SRC := host_support.cpp

CORE_OBJ := $(BUILD)/AetherPacketCore.o
HOOK_OBJ := $(BUILD)/AetherHookCore.o
HOST_OBJ := $(BUILD)/host_support.o

.PHONY: all test clean

all: $(BUILD)/test_core $(BUILD)/test_tap $(BUILD)/test_layout $(BUILD)/fake_target $(BUILD)/libaetherhooks.so

$(BUILD):
	mkdir -p $(BUILD)

# The shared header is C11 when compiled by a C compiler (<stdatomic.h>) and
# C++17 when compiled by a C++ one (std::atomic).  host_support.cpp therefore
# uses the C++ flavour.
$(BUILD)/host_support.o: $(HOST_SRC) host_support.h | $(BUILD)
	$(CC) -x c++ -std=gnu++17 $(CFLAGS) -c $< -o $@

$(CORE_OBJ): $(CORE_SRC) | $(BUILD)
	$(CC) -x c -std=gnu11 $(CFLAGS) -c $< -o $@

$(HOOK_OBJ): $(HOOK_SRC) | $(BUILD)
	$(CC) -x c -std=gnu11 $(CFLAGS) -c $< -o $@

# NB: the link rules must NOT force -x c — the object files on the command
# line would then be re-read as C source.
$(BUILD)/test_core: test_core.c $(CORE_OBJ) $(HOOK_OBJ) $(HOST_OBJ) | $(BUILD)
	$(CC) -std=gnu11 $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Header-only: pins the XNU proc_info layout (no linking needed).
$(BUILD)/test_layout: test_layout.c ../../headers/AetherProcInfoLayout.h | $(BUILD)
	$(CC) -std=gnu11 $(CFLAGS) test_layout.c -o $@

$(BUILD)/test_tap: test_tap.c $(CORE_OBJ) $(HOST_OBJ) | $(BUILD)
	$(CC) -std=gnu11 $(CFLAGS) $^ -o $@ $(LDFLAGS)

# -rdynamic exports fake_target's symbols (AetherGetSharedState,
# AetherHostLogLine, …) so the LD_PRELOAD shim can resolve them exactly as the
# injected payload resolves AetherGetSharedState() in a real target process.
$(BUILD)/fake_target: fake_target.c $(HOST_OBJ) | $(BUILD)
	$(CC) -std=gnu11 $(CFLAGS) -rdynamic $^ -o $@ $(LDFLAGS)

# LD_PRELOAD interposer — the Linux stand-in for the injected payload
$(BUILD)/libaetherhooks.so: preload_shim.c $(CORE_OBJ) $(HOOK_OBJ) | $(BUILD)
	$(CC) -std=gnu11 $(CFLAGS) -fPIC -shared \
		preload_shim.c $(CORE_OBJ) $(HOOK_OBJ) -o $@ $(LDFLAGS) -ldl

test: all
	./run_tests.sh

clean:
	rm -rf $(BUILD)
