# AGENTS.md — Instructions for Claude Code / Codex

## Project Context

This is a security research repository implementing io_uring-based shellcode
for Linux x86_64. The goal is demonstrating that EDRs relying solely on
`sys_enter` tracepoints are blind to I/O operations performed via io_uring.

Read `SPEC.md` in full before starting any task. It contains all technical
constraints, register conventions, and quality criteria.

## Rules

1. **No liburing.** All io_uring interaction uses raw `syscall()` in C or
   raw `syscall` instruction in NASM. Never `#include <liburing.h>`.

2. **No libc in assembly.** NASM shellcode must assemble with `nasm -f bin`.
   No external symbols, no PLT, no GOT references.

3. **Position-independent.** All data references in assembly use
   `call get_ip / pop rbx / sub $get_ip, rbx` delta technique, then
   `lea symbol(%rbx+offset), %rax` style addressing.

4. **No null bytes** in assembled shellcode. If a null appears, use
   `xor rax, rax` instead of `mov rax, 0`, etc.

5. **Test before marking done.** Every C file must compile and run.
   Every .asm file must assemble. The builder must produce valid output.

6. **Document offsets.** When a shellcode has runtime-configurable values
   (IP, port, path), document their offsets in a header comment and
   generate a `.h` file with `#define` macros.

7. **Kernel version guards.** Code that requires kernel ≥ 5.5 (CONNECT) or ≥ 5.6 (SEND/OPENAT/READ)
   or ≥ 5.11 (SQPOLL without CAP_SYS_NICE) must check at runtime via
   `uname()` and print a clear error if the requirement isn't met.

8. **One file per task.** Complete one file fully before starting the next.
   Never leave a file in a partial state.

## Build Commands

```bash
# C PoCs
make -C poc

# Assembly shellcode
make -C shellcode

# Verify no nulls in shellcode
python3 shellcode/combined/extract.py shellcode.bin

# Builder tests
python3 -m pytest builder/tests/

# Full test
make test
```

## io_uring Quick Reference

### Key Syscalls
- `io_uring_setup(entries, *params)` → fd  — syscall 425
- `io_uring_enter(fd, to_submit, min_complete, flags, sig)` → n  — syscall 426
- `io_uring_register(fd, opcode, arg, nr_args)` → 0  — syscall 427

### SQE Layout (64 bytes)
```
+0   u8  opcode
+1   u8  flags       (IOSQE_IO_LINK=0x04, IOSQE_FIXED_FILE=0x01)
+2   u16 ioprio
+4   s32 fd
+8   u64 off
+16  u64 addr
+24  u32 len
+28  u32 op_flags
+32  u64 user_data
+40  u16 buf_index
```

### CQE Layout (16 bytes)
```
+0   u64 user_data
+8   s32 res          (bytes or -errno)
+12  u32 flags
```

### Opcodes
```
IORING_OP_READV     = 1
IORING_OP_READ      = 22
IORING_OP_WRITE     = 23
IORING_OP_OPENAT    = 18
IORING_OP_CLOSE     = 19
IORING_OP_SOCKET    = 45   (kernel >= 5.19)
IORING_OP_CONNECT   = 16   (kernel ≥ 5.5)
IORING_OP_SEND      = 26   (kernel ≥ 5.6)
IORING_OP_RECV      = 27   (kernel ≥ 5.6)
IORING_OP_STATX     = 21
```

### mmap Offsets
```
IORING_OFF_SQ_RING = 0
IORING_OFF_CQ_RING = 0x8000000
IORING_OFF_SQES    = 0x10000000
```

### io_uring_params offsets for sq_off / cq_off
```
params.sq_off.head    = params+40
params.sq_off.tail    = params+44
params.sq_off.ring_mask   = params+48
params.sq_off.ring_entries= params+52
params.sq_off.flags   = params+56
params.sq_off.dropped = params+60
params.sq_off.array   = params+64

params.cq_off.head    = params+80
params.cq_off.tail    = params+84
params.cq_off.ring_mask   = params+88
params.cq_off.ring_entries= params+92
params.cq_off.overflow= params+96
params.cq_off.cqes    = params+100
```

## Common Mistakes to Avoid

- Forgetting `MAP_POPULATE` in the mmap flags (causes slow first access).
- Not checking `IORING_FEAT_SINGLE_MMAP`: if set, CQ ring is in the same
  mmap region as SQ ring (just a different offset into the same pointer).
- Using `sq_array[index] = tail` instead of `sq_array[index] = index`.
  The array holds the *slot index*, not the tail value.
- Forgetting the memory barrier (`__sync_synchronize()` in C,
  `mfence` in ASM) before incrementing `sq_tail` in SQPOLL mode.
- Not resetting the SQE struct to zero before filling fields.
