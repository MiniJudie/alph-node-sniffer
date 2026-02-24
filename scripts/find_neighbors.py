#!/usr/bin/env python3
"""
Send a FindNode discovery message to a node and parse the Neighbors response.

Usage:
  python scripts/find_neighbors.py <host:port> [options]

Examples:
  python scripts/find_neighbors.py bootstrap0.alephium.org:9973
  python scripts/find_neighbors.py 1.2.3.4:9973 --network-id 1 --timeout 10
"""

import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sniffer.protocol import (
    build_find_node_message,
    describe_discovery_message,
    extract_neighbors_from_message,
    get_response_payload_type,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send FindNode to a node and print parsed Neighbors response."
    )
    parser.add_argument(
        "node",
        metavar="host:port",
        help="Node address, e.g. bootstrap0.alephium.org:9973",
    )
    parser.add_argument(
        "--network-id",
        type=int,
        default=0,
        help="Network ID (0=mainnet, 1=testnet). Default: 0",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="UDP timeout in seconds. Default: 10",
    )
    args = parser.parse_args()

    if ":" not in args.node:
        parser.error("node must be host:port")
    host, _, port_str = args.node.rpartition(":")
    try:
        port = int(port_str)
    except ValueError:
        parser.error("port must be an integer")

    msg = build_find_node_message(args.network_id, os.urandom(33))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    try:
        sock.sendto(msg, (host, port))
        print(f"FindNode sent to {host}:{port} ({len(msg)} bytes, network_id={args.network_id})")
        raw, from_addr = sock.recvfrom(65535)
    except socket.timeout:
        print(f"No response within {args.timeout}s (timeout).")
        return 1
    except OSError as e:
        print(f"Error: {e}")
        return 1
    finally:
        sock.close()

    payload_type, _ = get_response_payload_type(raw, args.network_id)
    desc = describe_discovery_message(raw, args.network_id)
    print(f"Response from {from_addr[0]}:{from_addr[1]} ({len(raw)} bytes): {desc}")

    if payload_type != 3:
        # 3 = Neighbors
        print("(Not a Neighbors message; expected FindNode -> Neighbors.)")
        return 0

    neighbors = extract_neighbors_from_message(raw, args.network_id)
    if not neighbors:
        print("(Neighbors message but no peers parsed.)")
        return 0

    print(f"\nNeighbors ({len(neighbors)} peers):")
    for i, n in enumerate(neighbors, 1):
        clique_hex = n.clique_id.hex()[:16] + "..." if len(n.clique_id) >= 16 else n.clique_id.hex()
        print(f"  {i}. {n.address}:{n.port}  clique_id={clique_hex}  broker_id={n.broker_id}  broker_num={n.broker_num}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
