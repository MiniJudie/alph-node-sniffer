#!/usr/bin/env python3
"""
Dump the exact bytes (hex) we send for Ping and FindNode discovery messages.
Use to verify encoding against Alephium or compare with a capture.

Usage:
  python scripts/dump_discovery_bytes.py [network_id]
  network_id defaults to 0 (mainnet).

Example:
  python scripts/dump_discovery_bytes.py
  python scripts/dump_discovery_bytes.py 1
"""

import os
import sys

# Run from repo root so sniffer is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sniffer.protocol import (
    magic_bytes,
    checksum,
    build_ping_message,
    build_find_node_message,
    unwrap_message,
    decode_compact_int,
    MAGIC_LENGTH,
    CHECKSUM_LENGTH,
    LENGTH_FIELD_SIZE,
    SIGNATURE_LENGTH,
)


def _hex_line(b: bytes, width: int = 64) -> str:
    h = b.hex()
    return " ".join(h[i : i + 2] for i in range(0, len(h), 2))


def _breakdown(name: str, raw: bytes, network_id: int) -> None:
    magic = magic_bytes(network_id)
    if len(raw) < MAGIC_LENGTH + CHECKSUM_LENGTH + LENGTH_FIELD_SIZE:
        print(f"  [{name}] too short: {len(raw)} bytes")
        return
    m = raw[:MAGIC_LENGTH]
    c = raw[MAGIC_LENGTH : MAGIC_LENGTH + CHECKSUM_LENGTH]
    ln = raw[MAGIC_LENGTH + CHECKSUM_LENGTH : MAGIC_LENGTH + CHECKSUM_LENGTH + LENGTH_FIELD_SIZE]
    data_len = int.from_bytes(ln, "big")
    data = raw[MAGIC_LENGTH + CHECKSUM_LENGTH + LENGTH_FIELD_SIZE :][:data_len]
    print(f"  magic   ({MAGIC_LENGTH} bytes): {_hex_line(m)}")
    print(f"  checksum ({CHECKSUM_LENGTH}): {_hex_line(c)}")
    print(f"  length  (4): {_hex_line(ln)} -> {data_len}")
    if len(data) >= SIGNATURE_LENGTH + 2:
        sig = data[:SIGNATURE_LENGTH]
        rest = data[SIGNATURE_LENGTH:]
        try:
            ver, ver_len = decode_compact_int(rest)
            rest = rest[ver_len:]
            pt, pt_len = decode_compact_int(rest)
            payload = rest[pt_len:]
        except (ValueError, IndexError):
            ver, ver_len, pt, pt_len, payload = None, 0, None, 0, data[SIGNATURE_LENGTH:]
        print(f"  signature (64): {_hex_line(sig)}")
        if ver is not None:
            print(f"  header (version): {data[SIGNATURE_LENGTH : SIGNATURE_LENGTH + ver_len].hex()} (compact -> {ver})")
        if pt is not None:
            print(f"  payload_type: {data[SIGNATURE_LENGTH + ver_len : SIGNATURE_LENGTH + ver_len + pt_len].hex()} (compact -> {pt}, 0=Ping 2=FindNode)")
        if payload:
            print(f"  payload ({len(payload)} bytes): {_hex_line(payload)}")


def main() -> None:
    network_id = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    magic = magic_bytes(network_id)
    session_id = bytes(32)  # all zeros for reproducible dump
    target_id = bytes(33)

    print(f"Network ID: {network_id}")
    print(f"Magic bytes: {_hex_line(magic)}")
    print()

    # Ping
    ping = build_ping_message(network_id, session_id)
    print("=== Ping (sessionId=0, senderInfo=None) ===")
    print(f"Total length: {len(ping)} bytes")
    print(f"Full hex:\n  {_hex_line(ping)}")
    print("\nBreakdown:")
    _breakdown("Ping", ping, network_id)
    # Sanity: our unwrap should accept our own message
    unwrapped = unwrap_message(ping, magic)
    if unwrapped is not None and checksum(unwrapped) == ping[MAGIC_LENGTH : MAGIC_LENGTH + CHECKSUM_LENGTH]:
        print("\n  (unwrap_message + checksum OK)")
    else:
        print("\n  (unwrap_message/checksum mismatch)")
    print()

    # FindNode
    find = build_find_node_message(network_id, target_id)
    print("=== FindNode (targetId=0) ===")
    print(f"Total length: {len(find)} bytes")
    print(f"Full hex:\n  {_hex_line(find)}")
    print("\nBreakdown:")
    _breakdown("FindNode", find, network_id)
    unwrapped_f = unwrap_message(find, magic)
    if unwrapped_f is not None and checksum(unwrapped_f) == find[MAGIC_LENGTH : MAGIC_LENGTH + CHECKSUM_LENGTH]:
        print("\n  (unwrap_message + checksum OK)")
    else:
        print("\n  (unwrap_message/checksum mismatch)")


if __name__ == "__main__":
    main()
