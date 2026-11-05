# Roadmap

## Released

- [x] Phase 1: C PoCs demonstrating io_uring evasion (`poc/`)
- [x] Phase 2: x64 position-independent shellcode — Layer 0 + 1 + exfil mission
- [x] Phase 3: DSL builder — YAML mission → shellcode.bin + patchable C header
- [x] Phase 4: Testing framework — ptrace injector, C2 server, EDR matrix runner
- [x] Technical writeup and detection matrix
- [x] XOR encoder for null-free delivery: `uring_builder.py --encode xor`
  produces a 39-byte hand-encoded position-independent decoder stub + 16-bit
  rolling-keystream-encoded region; artifact contains **zero null bytes** and
  was validated live (exfil `read` → byte-exact at C2; roundtrip tests in
  builder/tests + live uring run below).

## Community Challenges

Pick one, open a PR. Each has clear acceptance criteria.

---

### 1. Sub-500-byte SQPOLL variant

Implement SQPOLL mode (`IORING_SETUP_SQPOLL`) in Layer 0 and produce a
combined shellcode under 500 bytes. Current best is ~1040 bytes without SQPOLL.
After setup, the process emits zero `io_uring_enter` calls — fully invisible
to any sys_enter-based monitor.

**Acceptance:** `python3 shellcode/combined/extract.py shellcode.bin` reports ≤ 500 bytes,
`strace -c` shows 0 `io_uring_enter` calls during the I/O phase.

---

### 2. Fixed buffers / fixed files optimization

Use `IORING_REGISTER_FILES` and `IORING_REGISTER_BUFFERS` to pre-register
the file table and I/O buffers. Operations then use an index instead of a raw
fd, so the actual fd never appears in any subsequent call.

**Acceptance:** new mission variant that passes all existing tests;
`extract.py` shows a measurable byte reduction.

---

### 3. Full reverse shell mission (`connect_back`) — DONE

Implemented in both variants (originally planned as a single exec-less
stub; decision was "both"):

- **Classic** (`connect_back.yaml`): io_uring socket/connect → native
  `dup2`×3 → native `execve("/bin/sh")`. Validated live via ptrace
  injection: connect-back accepted, `id` output returned over the socket.
- **Zero-exec** (`connect_back_recv.yaml`): `file_exfil_service` composite
  op — recv path → openat → chunked exfil → close → loop; `recv == 0`
  exits cleanly. Validated live via ptrace injection on `/etc/hostname`.
- Remaining stretch goal (kept for polish): interactive command session
  over a pty inside the zero-exec variant.

---

### 4. In-memory ELF loader mission (`in_memory_exec`)

Receive an ELF binary over the socket via `IORING_OP_RECV`, map it
into an anonymous region, parse the ELF headers, fix up relocations,
and jump to the entry point — no `execve`, no file on disk.

**Acceptance:** received ELF runs successfully inside the injected process.

---

### 5. ARM64 port

Translate Layer 0 and Layer 1 to AArch64 assembly (`aarch64-linux-gnu-as`).
io_uring syscall numbers and SQE/CQE layout are identical across
architectures; only the register ABI and instruction encoding differ.

**Acceptance:** assembles for AArch64, passes the same test matrix on a
Raspberry Pi or Apple Silicon VM running Linux.

---

### 6. EDR matrix expansion

Test against commercial EDRs (CrowdStrike Falcon, SentinelOne, Elastic Defend)
and document results with version numbers and configuration details.
Anonymous / responsible disclosure format is fine.

**Acceptance:** a PR adding rows to `testing/results/edr_matrix.md` with
methodology notes and kernel/EDR versions.

---

### 7. XOR encoder for null-byte-free delivery — DONE

Implemented in the builder itself. The flat-N-byte key is impossible for
null removal in general (a 256-byte plaintext window covers every key
value), so the design is a **16-bit linear rolling keystream**
(`plain[i] ^ (((state + i*step) mod 2^16) >> 8)`): each plaintext byte
rejects ~2^8 of 2^32 key pairs, making a null-free key always findable by
search (milliseconds). The 39-byte decoder stub is hand-encoded to stay
null-free (`e8 e8 ff ff ff` backward-call, SIB-encoded `xor [rsi], bh`,
no `call $+5`), position-independent, and usable with the standard
runner/C2 harness; config patching happens BEFORE encoding (build-time
`--ip/--port`).

**Acceptance:** `uring_builder.py --encode xor` produces a binary with
`check_nulls()` returning an empty list. Validated live: encoded
`exfil_shadow` artifact ran through `testing/runner` and exfiltrated the
target file byte-exact to the C2 (`testing/c2_server.py`), with `pytest`
roundtrip/layout tests (46 passing).

---

### 8. Container escape scenario

Document and demonstrate a case where io_uring is available inside a
container (no seccomp restriction) and can be used to read host files
via a shared namespace or volume mount.

**Acceptance:** a reproducible Docker Compose setup + `run_container_test.sh`
that shows exfil working from inside a container to a host C2.

---

## Not Planned

- **Windows port** — IOCP is architecturally different; the evasion technique does not transfer.
- **GUI builder** — the CLI is intentional; build a web frontend on top if you need one.
- **Kernel module / rootkit mode** — out of scope; this is a userspace PoC.
