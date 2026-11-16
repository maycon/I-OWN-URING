# Syscall-less Shellcode via Linux io_uring: EDR Evasion at the I/O Layer

**Author:** Maycon Vitali (@maycon)

**Affiliation:** Hack N' Roll

**Date:** November 2026

**Repository:** https://github.com/maycon/I-OWN-URING

---

## Abstract

We present a technique for performing file and network I/O operations from
shellcode without emitting the traditional operation-specific syscalls seen by
Linux monitoring attached only to `sys_enter`. By routing all I/O through
the Linux `io_uring` interface, a shellcode can open files, read their
contents, create sockets, connect to a remote host, and exfiltrate data while
generating no `openat()`, `read()`, `connect()`, or `send()` syscall events
visible to `sys_enter`-based monitoring tools. We demonstrate this with a
working x86_64 position-independent shellcode (~1036 bytes), a mission DSL
builder, and a reproducible test matrix with live Falco validation. Commercial
EDR validation remains future work and is not claimed by this repository.

---

## 1. Introduction

Some Linux monitoring designs attach to the kernel's syscall interface to
detect malicious I/O activity. One mechanism is a BPF program or kernel module
attached to the `raw_tracepoint/sys_enter` hook, which fires on every syscall entry.
When a process calls `openat("/etc/shadow", O_RDONLY)`, the hook fires, the
EDR inspects the filename, and may generate an alert.

This model has a structural weakness: it assumes that I/O operations are
initiated through the syscall interface. The Linux `io_uring` subsystem,
merged into the mainline kernel in 5.1 (May 2019), provides an asynchronous I/O
mechanism
that uses shared memory rings between userspace and the kernel. After a one-time
setup, the kernel processes I/O operations submitted to the ring internally,
without returning to the syscall entry path.

The consequence is direct: an EDR relying solely on `sys_enter` tracepoints
is blind to all I/O performed via `io_uring`. The operation appears as a single
opaque `io_uring_enter()` call with no operand context visible at the monitoring
layer.

This paper documents the design and implementation of a shellcode that exploits
this gap, evaluates detection across multiple tools, and describes the correct
architectural response from defenders.

---

## 2. Background

### 2.1 io_uring Architecture

`io_uring` exposes two lock-free ring buffers shared between userspace and the
kernel via `mmap`:

- **Submission Queue (SQ)**: userspace writes Submission Queue Entries (SQEs)
  describing I/O operations.
- **Completion Queue (CQ)**: the kernel writes Completion Queue Entries (CQEs)
  with results.

A single entry point, `io_uring_enter()` (syscall 426), submits pending SQEs
and optionally waits for completions. With `IORING_SETUP_SQPOLL`, even this
call becomes unnecessary: a dedicated kernel thread polls the SQ, making the
process's I/O completely invisible at the syscall level after setup.

### 2.2 SQE Layout

Each SQE is 64 bytes and describes one operation:

```
+0   u8  opcode       (e.g., 18 = IORING_OP_OPENAT)
+4   s32 fd           (file descriptor or domain for socket)
+8   u64 off          (file offset or socket type)
+16  u64 addr         (buffer pointer, path pointer, or sockaddr)
+24  u32 len          (buffer size, flags, or protocol)
+28  u32 op_flags     (opcode-specific: open_flags, msg_flags, etc.)
+40  u64 user_data    (echoed in CQE for correlation)
```

The kernel processes the SQE inside `io_issue_sqe()`, which calls the
appropriate VFS or network function directly.

### 2.3 EDR Hook Architecture

Most Linux EDRs instrument the kernel at one of two layers:

| Layer | Hook point | Mechanism |
|---|---|---|
| Syscall entry | `raw_tracepoint/sys_enter` | eBPF or kprobe |
| Syscall exit  | `raw_tracepoint/sys_exit`  | eBPF or kprobe |
| File access   | `security_file_open` (LSM) | BPF LSM or LKM |
| Network       | `security_socket_connect` (LSM) | BPF LSM or LKM |

Tools relying exclusively on the first two layers cannot observe operations
that never enter the syscall path.

---

## 3. Threat Model

### 3.1 Scope

This technique bypasses syscall-based I/O monitoring. It does **not** bypass:

- LSM hooks (`security_file_open`, `security_socket_connect`)
- File Integrity Monitoring (FIM/fanotify)
- Network-level inspection (NDR, firewall)
- Process creation monitoring (`execve`/`execveat`)
- Memory scanning or process hollowing detection

The technique is relevant for the exfiltration and lateral movement phases of
an attack, where the attacker has already gained code execution and wishes to
read sensitive files or establish a C2 channel without triggering syscall-based
alerts.

### 3.2 Prerequisites

- Code execution in the target process (via shellcode injection, ROP, etc.)
- Linux kernel ≥ 5.1 (basic io_uring); ≥ 5.5 for `IORING_OP_CONNECT`;
  ≥ 5.6 for `IORING_OP_SEND`/`IORING_OP_RECV`; ≥ 5.19 for `IORING_OP_SOCKET`
  (raw syscall-number socket creation remains available below 5.19)
- `io_uring_setup` not blocked by seccomp (default on most systems)
- `CAP_NET_BIND_SERVICE` not required for outbound connections

---

## 4. Shellcode Design

### 4.1 Three-Layer Architecture

The shellcode is organized into three independent layers, each assembled
separately and concatenated:

```
┌─────────────────────────────────────────────────────┐
│ Layer 0: Bootstrap (~150 bytes)                     │
│  io_uring_setup + 3× mmap                           │
│  Only visible syscalls: setup + mmap                │
├─────────────────────────────────────────────────────┤
│ Layer 1: Runtime (~400 bytes)                       │
│  _get_sqe   — allocate and zero SQE slot            │
│  _io_enter  — submit 1 SQE + wait 1 CQE             │
│  _wait_cqe  — spin-poll CQ ring                     │
├─────────────────────────────────────────────────────┤
│ Layer 2: Mission (~300 bytes, variable)             │
│  Sequence of op calls specific to the mission       │
│  Generated from YAML by uring_builder.py            │
└─────────────────────────────────────────────────────┘
```

### 4.2 Position Independence

The shellcode uses the classic `call/pop` delta technique:

```nasm
_start:
    sub rsp, 4288       ; allocate stack frame
    mov r13, rsp        ; r13 = stable frame pointer

    call _get_base
_get_base:
    pop r12             ; r12 = runtime address of _get_base
    ; data: [r12 + (label - _get_base)]
```

All data references use `r12`-relative addressing. The shellcode can execute
at any address without relocation.

### 4.3 Stack Frame Layout

All mutable state lives on the stack (4288 bytes):

```
[rsp+0]   params         104 bytes  io_uring_params (zeroed)
[rsp+104] pointers        56 bytes  sq_tail, cq_head, cq_tail, sqes, sq_array, cqes
[rsp+160] file state      16 bytes  uring_fd, file_fd, sock_fd, bytes_read
[rsp+176] sockaddr_in     16 bytes  built at runtime from config
[rsp+192] read buffer   4096 bytes  exfiltrated file content
```

Using the stack avoids the need for writable static data, making the shellcode
compatible with RX-only injection targets.

### 4.4 exfil_shadow Mission

The active mission YAML (`builder/missions/exfil_shadow.yaml`) drives the
following op sequence, all via io_uring:

```
1. IORING_OP_OPENAT  fd=AT_FDCWD  path=/etc/shadow  flags=O_RDONLY
2. IORING_OP_SOCKET  domain=AF_INET  type=SOCK_STREAM
3. IORING_OP_CONNECT fd=sock_fd   addr=sockaddr_in(config_ip, config_port)
4. IORING_OP_READ + IORING_OP_SEND — chunked loop, 4096 bytes per chunk
   (read/send_until_eof: no silent truncation for larger files)
5. IORING_OP_CLOSE   ×2 (file_fd, sock_fd — teardown, results ignored)
```

The only syscall the target process emits (visible to strace) is:
```
io_uring_enter(3, 1, 1, IORING_ENTER_GETEVENTS, NULL) = 1
```
repeated six times (plus one per chunk of the read/send loop). No filename,
file descriptor context, IP address, or port number is visible at the
syscall boundary.

### 4.5 SQPOLL Zero-Syscall Mode

With `IORING_SETUP_SQPOLL`, the kernel spawns a dedicated polling thread.
After setup, the shellcode only writes to the shared SQ ring and reads from
the CQ ring — no `io_uring_enter()` call is needed for the I/O phase. The
target process emits **zero** I/O syscalls after setup.

### 4.6 Mission Builder

The `uring_builder.py` DSL accepts a YAML mission definition:

```yaml
name: exfil_shadow
config:
  c2_ip: "192.168.1.1"
  c2_port: 4444
ops:
  - openat: { path: /etc/shadow, result: file_fd }
  - socket: { result: sock_fd }
  - connect: { fd: sock_fd, ip: "{{ c2_ip }}", port: "{{ c2_port }}" }
  - read_send: { until_eof: true, fd: file_fd, send_fd: sock_fd, buf: auto, len: 4096 }
  - close: { fd: file_fd }
  - close: { fd: sock_fd }
```

And produces a ready-to-inject binary with documented patchable offsets for
IP and port, allowing rapid mission customization without rewriting assembly.
With `--encode xor`, the artifact additionally gets a null-free
position-independent decoder stub (16-bit rolling-keystream XOR, chosen
because a flat N-byte key cannot eliminate nulls in general) prepended so
the shellcode survives delivery through null-terminated buffers; validation
lives in `builder/tests/test_builder.py` (`TestXorEncode`).

---

## 5. Evaluation

### 5.1 Test Methodology

We used `testing/inject_ptrace.c` to inject the shellcode into a `sleep 60`
process via ptrace. The C2 server (`c2_server.py`) listened on loopback and
verified that received data matched `/etc/shadow` byte-for-byte.

Detection was assessed by running the injection while each tool monitored the
target process. A tool was considered "detected" if it generated an actionable
alert during the injection window. All tests were run on kernel 6.14.0.

A recorded reproduction of the full falco evaluation (both scenarios, live
log streaming, `testing/results/falco_demo.cast`) and a raw-rows capture
(`testing/results/falco_edr_comparison.md`) are included in the repository.

### 5.2 Results Summary

| Tool | Approach | Detects io_uring ops? |
|---|---|:---:|
| strace (default) | sys_enter tracing | ✗ |
| Falco 0.45.1, *live-validated* (default rules) | eBPF on sys_enter | ✗ |
| Falco (io_uring event types, custom rules) | rules referencing `io_uring_setup` | ⚠ setup only |
| Tetragon (default) | eBPF + kprobes | ⚠ not live-validated here |
| Tetragon (LSM policy) | BPF LSM hooks | ✓ (design expectation, pending live validation) |
| Commercial EDR sensors | Product-dependent | ⚠ not validated here |
| seccomp (deny `io_uring_setup`) | syscall filter | ✓ blocks entirely |

Live-validated falco row: with **falco 0.45.1 `modern_ebpf` and the shipped
default ruleset only**, a single mixed session contained exactly three
rule-firings — all from the pure-syscall baseline (the stock
`Redirect stdout/stdin to network connection` rule, one per `dup2`), none
from either io_uring variant, and **zero default-rule alerts on the
`io_uring_setup`/`io_uring_enter` syscalls themselves**.

### 5.3 Falco Deep-Dive

Falco's default detection engine attaches to `sys_enter` tracepoints via
eBPF or kernel module. In April 2025, ARMO published the "Curing" rootkit
demonstrating this exact gap. Falco maintainers responded by supporting
io_uring in later releases: `io_uring_setup`, `io_uring_enter` and
`io_uring_register` became first-class **event types**, so rules referencing
them can be written. However — as validated live on falco 0.45.1 — the
**shipped default ruleset contains no io_uring rule**; out of the box, the
tool still relies on legacy I/O syscall rules, and the entire operation set
of this shellcode produces no default-rule firing (only the classic dup2
phase of a *pure-syscall* baseline trips the stock
`Redirect stdout/stdin to network connection` rule).

Even with the event types available, individual operation visibility (which
files were opened, which hosts were connected to) remains unavailable at the
`io_uring_enter` boundary regardless of the ruleset: the operand context is
inside the submission, not in the syscall arguments. Detection without LSM
hooks is therefore limited to the "this process created a ring" signal.

### 5.4 Why LSM Hooks Are the Correct Solution

LSM hooks are called from inside the VFS and network stack, not from the
syscall handler:

```c
// From fs/open.c — called by both do_sys_open() AND io_issue_sqe()
int do_filp_open(int dfd, struct filename *pathname, ...) {
    ...
    error = security_file_open(f);  // LSM hook fires here
    ...
}
```

This means `security_file_open` is called regardless of whether the caller
entered the kernel via `openat()` (syscall 257) or via `io_uring_enter()`
(syscall 426). The LSM hook is architecture-agnostic with respect to the
I/O submission path.

A properly configured Tetragon `TracingPolicy` targeting `security_file_open`
is expected to detect the io_uring-based file access with full filename
context (design-level expectation from the hook architecture above; live
validation in this repo's test matrix is in progress).

---

## 6. Mitigations

### 6.1 For Operators (Immediate)

**Block io_uring in containers:**
```yaml
# seccompProfile in Kubernetes
syscalls:
  - names: [io_uring_setup, io_uring_enter, io_uring_register]
    action: SCMP_ACT_ERRNO
```

This is the most effective short-term mitigation for containerized environments.
PostgreSQL and nginx do not use io_uring by default; most workloads are unaffected.

**Alert on io_uring_setup:**
```yaml
# Falco rule
- rule: Unexpected io_uring usage
  condition: syscall.type = io_uring_setup and not proc.name in (allowed_list)
  priority: WARNING
```

This does not detect individual operations but identifies processes that
establish an io_uring ring, which is a prerequisite for the technique.

### 6.2 For EDR Vendors (Architectural)

The correct fix is to add BPF LSM hooks alongside existing syscall hooks.
Specifically:
- `security_file_open` for file access monitoring
- `security_socket_connect` for network connection monitoring
- `security_file_receive` for data movement

These hooks provide the same semantic information as syscall monitoring
(filename, address, port) regardless of the submission path used.

### 6.3 For Kernel Developers

Linux 6.6 (2023) introduced the `kernel.io_uring_disabled` sysctl —
backported by several distributions (e.g. RHEL 9.4, Ubuntu 24.04):
- `0` — io_uring available to all processes (default)
- `1` — io_uring available only to privileged processes (CAP_SYS_ADMIN or the
  `kernel.io_uring_group` group, added in a later kernel)
- `2` — io_uring creation completely disabled (`io_uring_setup()` always
  fails with `-EPERM`; existing instances remain usable)

Several distributions already ship io_uring disabled by default (e.g.
RHEL-based 9.x builds). For high-security environments where io_uring is
not needed, `kernel.io_uring_disabled=2` eliminates the attack surface
entirely.

---

## 7. Related Work

**ARMO "Curing" rootkit (April 2025):** First public PoC demonstrating
io_uring as a rootkit C2 mechanism, bypassing Falco and Tetragon.
Confirmed our findings independently.

**Jann Horn (2019):** Documented io_uring security considerations at
kernel introduction. Noted that LSM hooks would need updates.

**io_uring security reviews (2022-2023):** Multiple CVEs in io_uring's
implementation (use-after-free, privilege escalation). This work concerns
the *design* property, not implementation bugs.

**syscall filtering and io_uring:** Several container runtimes (gVisor,
Kata Containers) already restrict io_uring, providing a model for
broader adoption.

---

## 8. Conclusion

The `sys_enter` tracepoint model has a structural blind spot: operations
submitted through io_uring bypass the operation-specific syscall entry path
and are invisible to this layer. We demonstrated this with a working shellcode
that exfiltrates `/etc/shadow` while generating no traditional `openat`,
`read`, `connect`, or `send` events at `sys_enter`.

The correct defensive response is a shift to LSM-hook-based monitoring,
which operates at the VFS and network layer rather than the syscall boundary.
Short-term, operators should restrict io_uring access in containerized
workloads via seccomp.

The source code, builder, and test framework are available at
https://github.com/maycon/I-OWN-URING under the MIT license.

---

## Acknowledgements

Thanks to the Hack N' Roll team for the research environment and to the
Falco maintainers for their rapid response to the responsible disclosure.

---

## References

1. Axboe, J. (2019). *Efficient I/O with io_uring*. kernel.dk.
2. ARMO Security. (2025). *io_uring is Back, This Time as a Rootkit*.
   armosec.io/blog.
3. Sysdig. (2025). *Detecting and Mitigating io_uring Abuse for Malware
   Evasion*. sysdig.com/blog.
4. Linux Kernel Documentation. (2024). *io_uring — Efficient I/O*.
   kernel.org/doc/html/latest/block/io-uring.html.
5. BleepingComputer. (2025). *Linux io_uring security blindspot allows
   stealthy rootkit attacks*. bleepingcomputer.com.
