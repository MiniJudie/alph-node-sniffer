#!/usr/bin/env python3
"""
Ask a node for its version via TCP broker (Hello message). Optionally update the database.

The server sends Hello first on connect; we read it and parse clientId (version string).
No handshake reply is sent — this is the minimal "ask version" flow.

Usage:
  python scripts/ask_node_version.py <host:port> [options]
  python scripts/ask_node_version.py <host:port> --db nodes.db   # also update DB

Examples:
  python scripts/ask_node_version.py bootstrap0.alephium.org:9973
  python scripts/ask_node_version.py 1.2.3.4:9973 --broker-port 27665 --network-id 1
  python scripts/ask_node_version.py 1.2.3.4:9973 --db nodes.db
"""

import argparse
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Show protocol progress (reference node, connect, Hello, ChainState)
logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)

from sniffer.version_check import get_client_version_tcp, parse_client_id
from sniffer.db import update_node_enrichment, upsert_node


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ask node version via TCP broker (read Hello clientId). Optionally update database."
    )
    parser.add_argument(
        "node",
        metavar="host:port",
        help="Node address (discovery port), e.g. bootstrap0.alephium.org:9973",
    )
    parser.add_argument(
        "--broker-port",
        type=int,
        default=None,
        help="TCP broker port (default: same as port from host:port)",
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
        default=5.0,
        help="TCP timeout in seconds. Default: 5",
    )
    parser.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="If set, update this database with the node version (node must exist)",
    )
    parser.add_argument(
        "--upsert",
        action="store_true",
        help="With --db: create node if missing (upsert), then set version",
    )
    args = parser.parse_args()

    if ":" not in args.node:
        parser.error("node must be host:port")
    host, _, port_str = args.node.rpartition(":")
    try:
        port = int(port_str)
    except ValueError:
        parser.error("port must be an integer")

    broker_port = args.broker_port if args.broker_port is not None else port

    async def run() -> int:
        print(f"Connecting to {host}:{broker_port} (broker) network_id={args.network_id} ...", file=sys.stderr)
        version = await get_client_version_tcp(
            host,
            broker_port,
            args.network_id,
            timeout=args.timeout,
        )
        if version is None:
            print("Could not get version (timeout or not a valid Alephium broker).", file=sys.stderr)
            return 1
        print("Got version:", version, file=sys.stderr)
        print(version)

        parsed = parse_client_id(version)
        version_str = parsed.version if parsed.version else version
        client_str = parsed.client
        os_str = parsed.os
        if args.db:
            if args.upsert:
                await upsert_node(
                    args.db,
                    host,
                    port,
                    domain=None,
                    version=version_str,
                    client=client_str,
                    os=os_str,
                    status="offline",
                )
                print(f"Updated DB: {host}:{port} -> client={client_str} version={version_str} os={os_str}", file=sys.stderr)
            else:
                await update_node_enrichment(
                    args.db,
                    host,
                    port,
                    version=version_str,
                    client=client_str,
                    os=os_str,
                )
                print(f"Updated DB: {host}:{port} -> client={client_str} version={version_str} os={os_str}", file=sys.stderr)
        return 0

    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
