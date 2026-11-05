#!/usr/bin/env python3
"""
c2_server.py — minimal TCP C2 listener for shellcode testing

Usage:
    python3 c2_server.py [options]

Options:
    --port    PORT     Listening port (default: 4444)
    --output  FILE     Save received data to FILE (default: received.bin)
    --verify  FILE     Diff received data against FILE (exit 1 on mismatch)
    --timeout SECS     Connection timeout in seconds (default: 30)
    --host    HOST     Bind address (default: 0.0.0.0)
    --quiet            Suppress progress output

Exit codes:
    0  Data received (and verified if --verify was set)
    1  Timeout, connection error, or verification mismatch
"""

import argparse
import hashlib
import socket
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description='TCP listener for io_uring shellcode exfil testing'
    )
    p.add_argument('--port',    type=int, default=4444)
    p.add_argument('--host',    default='0.0.0.0')
    p.add_argument('--output',  default='received.bin')
    p.add_argument('--verify',  default=None,
                   help='File to diff received data against')
    p.add_argument('--timeout', type=int, default=30)
    p.add_argument('--quiet',   action='store_true')
    return p.parse_args()


def log(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg, flush=True)


def recv_all(conn: socket.socket, timeout: int) -> bytes:
    """Receive until connection closed or timeout."""
    conn.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    return b''.join(chunks)


def verify_data(received: bytes, expected_path: str, quiet: bool) -> bool:
    expected = Path(expected_path).read_bytes()
    if received == expected:
        log(f'[+] VERIFY OK — matches {expected_path} ({len(expected)} bytes)',
            quiet)
        return True
    else:
        rx_hash = hashlib.md5(received).hexdigest()
        ex_hash = hashlib.md5(expected).hexdigest()
        log(f'[!] VERIFY FAIL', quiet)
        log(f'    Received : {len(received)} bytes  md5={rx_hash}', quiet)
        log(f'    Expected : {len(expected)} bytes  md5={ex_hash}', quiet)
        # Show diff of first divergence
        for i, (rb, eb) in enumerate(zip(received, expected)):
            if rb != eb:
                log(f'    First diff at byte {i}: got 0x{rb:02x}, want 0x{eb:02x}',
                    quiet)
                break
        return False


def main() -> None:
    args = parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((args.host, args.port))
    except OSError as e:
        print(f'[-] Cannot bind {args.host}:{args.port}: {e}', file=sys.stderr)
        sys.exit(1)

    sock.listen(1)
    sock.settimeout(args.timeout)

    log(f'[+] Listening on {args.host}:{args.port}', args.quiet)
    log(f'[+] Timeout: {args.timeout}s', args.quiet)
    if args.verify:
        log(f'[+] Will verify against: {args.verify}', args.quiet)

    t0 = time.time()
    try:
        conn, addr = sock.accept()
    except socket.timeout:
        print(f'[-] Timeout — no connection in {args.timeout}s', file=sys.stderr)
        sys.exit(1)
    finally:
        sock.close()

    elapsed_connect = time.time() - t0
    log(f'[+] Connection from {addr[0]}:{addr[1]} (after {elapsed_connect:.1f}s)',
        args.quiet)

    t1 = time.time()
    data = recv_all(conn, args.timeout)
    conn.close()
    elapsed_recv = time.time() - t1

    if not data:
        print('[-] No data received', file=sys.stderr)
        sys.exit(1)

    log(f'[+] Received {len(data)} bytes in {elapsed_recv:.2f}s', args.quiet)

    # Save to output file
    out_path = Path(args.output)
    out_path.write_bytes(data)
    log(f'[+] Saved to {out_path}', args.quiet)

    # Optional verification
    if args.verify:
        ok = verify_data(data, args.verify, args.quiet)
        sys.exit(0 if ok else 1)

    sys.exit(0)


if __name__ == '__main__':
    main()
