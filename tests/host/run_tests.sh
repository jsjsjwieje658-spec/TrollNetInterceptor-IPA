#!/usr/bin/env bash
# =============================================================================
#  AetherNet — host simulation suite (integration: real UDP + TCP traffic)
#
#   ./run_tests.sh
#
#  For every scenario the harness
#    1. starts the echo server (the "peer" — never intercepted),
#    2. runs fake_target under LD_PRELOAD of the hook shim — the shim is the
#       Linux stand-in for libNetHookPayload.dylib and calls the *same*
#       AetherHookCore code that ships to the device,
#    3. asserts on what actually arrived at the peer and on the shared-memory
#       counters.
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")"

BUILD=build
TMP="${TMPDIR:-/tmp}/aether-tests.$$"
mkdir -p "$TMP"
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$TMP"' EXIT

COUNT=8
SERVER_PID=0
PASS=0
FAIL=0
SCENARIOS=0

green() { printf "  \033[32m✔\033[0m %s\n" "$1"; }
red()   { printf "  \033[31m✘\033[0m %s\n" "$1"; FAIL=$((FAIL+1)); }
head1() { printf "\n\033[1m%s\033[0m\n" "$1"; }

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
start_server() {
    rm -f "$TMP/server.out"
    ( "./$BUILD/fake_target" --server --udp-port 0 --tcp-port 0 ) > "$TMP/server.out" 2>&1 &
    SERVER_PID=$!
    UDP_PORT=""; TCP_PORT=""
    for _ in $(seq 1 60); do
        if [ -s "$TMP/server.out" ]; then
            UDP_PORT=$(sed -n 's/.*udp_port=\([0-9]*\).*/\1/p' "$TMP/server.out" | head -1)
            TCP_PORT=$(sed -n 's/.*tcp_port=\([0-9]*\).*/\1/p' "$TMP/server.out" | head -1)
        fi
        [ -n "$UDP_PORT" ] && [ -n "$TCP_PORT" ] && break
        sleep 0.05
    done
    if [ -z "$UDP_PORT" ] || [ -z "$TCP_PORT" ]; then
        red "server did not report its ports"; exit 1
    fi
}

stop_server() {
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=0
}

# ---------------------------------------------------------------------------
# Client wrapper: run_scenario <name> -- <fake_target args…>
# ---------------------------------------------------------------------------
run_client() {
    local name="$1"; shift
    SCENARIOS=$((SCENARIOS+1))
    start_server

    rm -f "$TMP/state.shm" "$TMP/hook.log"
    AETHER_TEST_SHM="$TMP/state.shm" \
    AETHER_TEST_LOG="$TMP/hook.log" \
    AETHER_TEST_DETERMINISTIC=1 \
    LD_PRELOAD="./$BUILD/libaetherhooks.so" \
        "./$BUILD/fake_target" --client \
            --udp-port "$UDP_PORT" --tcp-port "$TCP_PORT" \
            --count "$COUNT" "$@" > "$TMP/client.out" 2>"$TMP/client.err"

    RESULT=$(grep '^RESULT ' "$TMP/client.out" | head -1)
    STATE=$(grep '^STATE '  "$TMP/client.out" | head -1)
    MID=$(grep '^MID '      "$TMP/client.out" | head -1)

    if [ -z "$RESULT" ]; then
        red "$name: client produced no RESULT ($(head -2 "$TMP/client.err" 2>/dev/null))"
        stop_server
        return 1
    fi
    stop_server
    return 0
}

val() { # val <line> <key>
    echo "$1" | sed -n "s/.*$2=\([0-9-]*\).*/\1/p" | head -1
}

expect_eq() { # name key expected actual
    if [ "$3" = "$4" ]; then PASS=$((PASS+1)); green "$1: $2 = $4"
    else red "$1: $2 expected $3, got $4"; fi
}
expect_ge() {
    if [ "$4" -ge "$3" ] 2>/dev/null; then PASS=$((PASS+1)); green "$1: $2 = $4 (≥ $3)"
    else red "$1: $2 expected ≥ $3, got $4"; fi
}
expect_le() {
    if [ "$4" -le "$3" ] 2>/dev/null; then PASS=$((PASS+1)); green "$1: $2 = $4 (≤ $3)"
    else red "$1: $2 expected ≤ $3, got $4"; fi
}
expect_ne() {
    if [ "$3" != "$4" ]; then PASS=$((PASS+1)); green "$1: $2 = $4 (≠ $3)"
    else red "$1: $2 expected ≠ $3, got $4"; fi
}
# Direction assertions: the hook log records one line per intercepted packet
# and tags it TX (upload) or RX (download), so a direction filter can be
# checked for what it must NOT touch — something the counters alone cannot
# tell apart.
tx_events() { grep -c "\[P1 TX" "$TMP/hook.log" 2>/dev/null || true; }
rx_events() { grep -c "\[P1 RX" "$TMP/hook.log" 2>/dev/null || true; }

echo "══════════════════════════════════════════════════════════════════"
echo " AetherNet — host simulation suite (real UDP + TCP over loopback)"
echo "══════════════════════════════════════════════════════════════════"

# ---------------------------------------------------------------------------
head1 "0. Unit tests (packet core, policy engine, BPF framing, hold queue)"
if "./$BUILD/test_core" | tail -1 | grep -q "0 failure"; then
    PASS=$((PASS+1)); green "test_core: all unit checks passed"
else
    red "test_core: unit failures"
fi

head1 "1a. XNU proc_info layout (what proc_pidfdinfo() must return)"
if "./$BUILD/test_layout" | tail -1 | grep -q "0 failure"; then
    PASS=$((PASS+1)); green "test_layout: socket_fdinfo layout verified"
else
    red "test_layout: proc_info layout drifted"
fi

head1 "1. Kernel tap pipeline (P3: parse → match → flow table → counters)"
if "./$BUILD/test_tap" | tail -1 | grep -q "0 failure"; then
    PASS=$((PASS+1)); green "test_tap: pipeline checks passed"
else
    red "test_tap: pipeline failures"
fi

# ---------------------------------------------------------------------------
head1 "2. Baseline — interception OFF (telemetry must not disturb traffic)"
run_client "passthrough" --inactive
if [ -n "$RESULT" ]; then
    expect_eq "passthrough" "udp_echo" "$COUNT" "$(val "$RESULT" udp_echo)"
    expect_eq "passthrough" "tcp_echo" "$COUNT" "$(val "$RESULT" tcp_echo)"
    expect_eq "passthrough" "dropped"  "0" "$(val "$STATE" dropped)"
    expect_eq "passthrough" "held"     "0" "$(val "$STATE" held)"
    expect_eq "passthrough" "udp_tx"   "$COUNT" "$(val "$STATE" udp_tx)"
    expect_eq "passthrough" "tcp_tx"   "$COUNT" "$(val "$STATE" tcp_tx)"
fi

# ---------------------------------------------------------------------------
head1 "3. Drop 100% (UDP + TCP)"
run_client "drop-all" --mode drop --ratio 100
if [ -n "$RESULT" ]; then
    expect_eq "drop-all" "udp_echo" "0" "$(val "$RESULT" udp_echo)"
    expect_eq "drop-all" "tcp_echo" "0" "$(val "$RESULT" tcp_echo)"
    expect_eq "drop-all" "dropped" "$((COUNT*2))" "$(val "$STATE" dropped)"
fi

# ---------------------------------------------------------------------------
head1 "4. Hold → flush (⏸ → ▶ releases everything, nothing is lost)"
run_client "hold-flush" --mode hold --ratio 100 --flush --hold-ms 400 --late-pass-ms 500
if [ -n "$RESULT" ]; then
    expect_eq "hold-flush" "mid_udp_during_hold" "0" "$(val "$MID" udp_echo_so_far)"
    expect_ge "hold-flush" "mid_held" "1" "$(val "$MID" held)"
    expect_eq "hold-flush" "udp_after_flush" "$COUNT" "$(val "$RESULT" udp_echo)"
    expect_eq "hold-flush" "tcp_after_flush" "$COUNT" "$(val "$RESULT" tcp_echo)"
    expect_eq "hold-flush" "held_drained" "0" "$(val "$STATE" held)"
fi

# ---------------------------------------------------------------------------
head1 "5. Delay + jitter (all packets still arrive, just later)"
run_client "delay" --mode delay --latency 40
if [ -n "$RESULT" ]; then
    expect_eq "delay" "udp_echo" "$COUNT" "$(val "$RESULT" udp_echo)"
    expect_eq "delay" "tcp_echo" "$COUNT" "$(val "$RESULT" tcp_echo)"
    expect_ge "delay" "elapsed_ms" "600" "$(val "$RESULT" elapsed_ms)"
fi

# ---------------------------------------------------------------------------
head1 "6. Capture ratio 50% (statistical, deterministic RNG)"
run_client "ratio-50" --mode drop --ratio 50
if [ -n "$RESULT" ]; then
    expect_ge "ratio-50" "dropped" "1" "$(val "$STATE" dropped)"
    expect_le "ratio-50" "dropped" "$((COUNT*2-1))" "$(val "$STATE" dropped)"
    expect_ne "ratio-50" "echoes" "0" "$(val "$RESULT" udp_echo)"
fi

# ---------------------------------------------------------------------------
head1 "7. Direction filter — upload only"
run_client "dir-up" --mode drop --dir up --ratio 100
if [ -n "$RESULT" ]; then
    expect_eq "dir-up" "udp_echo" "0" "$(val "$RESULT" udp_echo)"
    expect_eq "dir-up" "tcp_echo" "0" "$(val "$RESULT" tcp_echo)"
    expect_eq "dir-up" "rx_untouched" "0" "$(rx_events)"
fi

head1 "8. Direction filter — download only (peer still receives)"
run_client "dir-down" --mode drop --dir down --ratio 100
if [ -n "$RESULT" ]; then
    expect_eq "dir-down" "udp_echo" "0" "$(val "$RESULT" udp_echo)"
    expect_eq "dir-down" "tcp_echo" "0" "$(val "$RESULT" tcp_echo)"
    expect_eq "dir-down" "tx_untouched" "0" "$(tx_events)"
    expect_ge "dir-down" "rx_dropped" "1" "$(rx_events)"
fi

# ---------------------------------------------------------------------------
head1 "9. Protocol filter — UDP only"
run_client "proto-udp" --mode drop --proto udp --ratio 100
if [ -n "$RESULT" ]; then
    expect_eq "proto-udp" "udp_echo" "0" "$(val "$RESULT" udp_echo)"
    expect_eq "proto-udp" "tcp_echo" "$COUNT" "$(val "$RESULT" tcp_echo)"
fi

head1 "10. Protocol filter — TCP only"
run_client "proto-tcp" --mode drop --proto tcp --ratio 100
if [ -n "$RESULT" ]; then
    expect_eq "proto-tcp" "udp_echo" "$COUNT" "$(val "$RESULT" udp_echo)"
    expect_eq "proto-tcp" "tcp_echo" "0" "$(val "$RESULT" tcp_echo)"
fi

# ---------------------------------------------------------------------------
head1 "11. Tamper (payload bit-flips detected by the peer)"
run_client "tamper" --mode tamper --ratio 100
if [ -n "$RESULT" ]; then
    CORRUPT=$(( $(val "$RESULT" udp_corrupt) + $(val "$RESULT" tcp_corrupt) ))
    expect_ge "tamper" "corrupted_packets" "1" "$CORRUPT"
fi

# ---------------------------------------------------------------------------
head1 "12. Safety auto-flush (held traffic is released on its own)"
run_client "auto-flush" --mode hold --ratio 100 --autoflush 1 --late-pass-ms 700
if [ -n "$RESULT" ]; then
    expect_ge "auto-flush" "udp_recovered" "1" "$(val "$RESULT" udp_echo)"
fi

# ---------------------------------------------------------------------------
head1 "13. UDP duplication (server sees two copies)"
run_client "duplicate" --mode hold --ratio 0 --dup 100 --late-pass-ms 400
if [ -n "$RESULT" ]; then
    expect_ge "duplicate" "udp_echo" "$((COUNT+1))" "$(val "$RESULT" udp_echo)"
fi

# ---------------------------------------------------------------------------
head1 "14. Observe mode (interception ON, but nothing may be touched)"
# The default mode on device: the user wants visibility, not interference.
# Every packet must reach the peer AND must still be counted.
run_client "observe" --mode observe --ratio 100
if [ -n "$RESULT" ]; then
    expect_eq "observe" "udp_echo" "$COUNT" "$(val "$RESULT" udp_echo)"
    expect_eq "observe" "tcp_echo" "$COUNT" "$(val "$RESULT" tcp_echo)"
    expect_eq "observe" "dropped"  "0" "$(val "$STATE" dropped)"
    expect_eq "observe" "held"     "0" "$(val "$STATE" held)"
    expect_eq "observe" "udp_tx"   "$COUNT" "$(val "$STATE" udp_tx)"
    expect_eq "observe" "tcp_tx"   "$COUNT" "$(val "$STATE" tcp_tx)"
fi

# ---------------------------------------------------------------------------
echo ""
echo "══════════════════════════════════════════════════════════════════"
printf " %d scenario(s) · %d assertion(s) passed · %d failed\n" "$SCENARIOS" "$PASS" "$FAIL"
echo "══════════════════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] || exit 1
