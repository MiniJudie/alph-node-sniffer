#!/usr/bin/env python3
"""
Show ChainState for one node: connect and perform broker handshake, or show stored result from DB.

Usage:
  python scripts/chain_state.py <host:port> [options]
  python scripts/chain_state.py <host:port> --db nodes.db   # show stored chainstate from DB

Examples:
  python scripts/chain_state.py bootstrap0.alephium.org:9973
  python scripts/chain_state.py 1.2.3.4:9973 --broker-port 27665 --network-id 1
  python scripts/chain_state.py 1.2.3.4:9973 --db nodes.db
"""

import argparse
import asyncio
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Show protocol progress (reference node, connect, Hello, ChainState)
logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)

from sniffer.version_check import get_chain_state_tcp
from sniffer.db import chain_heights_for_json, get_node_chain_state


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Show ChainState (synced, per-shard heights) for one node (live handshake or from DB)."
    )
    parser.add_argument(
        "node",
        metavar="host:port",
        help="Node address (discovery port), e.g. bootstrap0.alephium.org:9973",
    )
    parser.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="If set, show stored chainstate from this database instead of connecting",
    )
    parser.add_argument(
        "--broker-port",
        type=int,
        default=None,
        help="TCP broker port (default: use the node's port from host:port)",
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
        default=60.0,
        help="TCP timeout in seconds. Node sends ChainState on sync interval (~30-60s). Default: 60",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of human-readable format",
    )
    args = parser.parse_args()

    if ":" not in args.node:
        parser.error("node must be host:port")
    host, _, port_str = args.node.rpartition(":")
    try:
        port = int(port_str)
    except ValueError:
        parser.error("port must be an integer")

    async def run() -> int:
        if args.db:
            # Show from DB
            row = await get_node_chain_state(args.db, host, port)
            if row is None:
                print(f"Node {host}:{port} not found in database.", file=sys.stderr)
                return 1
            if args.json:
                ch_json = chain_heights_for_json(row["chain_heights"])
                print(json.dumps({
                    "address": row["address"],
                    "port": row["port"],
                    "domain": row["domain"],
                    "version": row["version"],
                    "client": row["client"],
                    "os": row["os"],
                    "synced": row["synced"],
                    "chain_heights": ch_json,
                }, indent=2))
            else:
                print(f"host: {row['address']}:{row['port']}")
                if row.get("domain") and row["domain"] != row["address"]:
                    print(f"domain: {row['domain']}")
                print(f"version: {row['version'] or '(unknown)'}")
                if row.get("client"):
                    print(f"client: {row['client']}")
                if row.get("os"):
                    print(f"os: {row['os']}")
                print(f"synced: {row['synced']}")
                heights = row.get("chain_heights") or {}
                print(f"chains: {len(heights)}")
                if heights:
                    print("heights by chain (fromGroup, toGroup):")
                    for (fg, tg), height in sorted(heights.items()):
                        print(f"  ({fg},{tg}): {height}")
                    print(f"heights JSON: {json.dumps(chain_heights_for_json(heights) or {})}")
            return 0

        # Live handshake
        broker_port = args.broker_port if args.broker_port is not None else port
        reference_nodes = None
        reference_broker_port = None
        try:
            from sniffer.config import Config
            cfg = Config.load()
            ref_list = cfg.reference_nodes or (
                ["bootstrap0.alephium.org:9973", "bootstrap1.alephium.org:9973"]
                if args.network_id == 0
                else ["bootstrap0.testnet.alephium.org:9973"]
            )
            reference_nodes = [cfg.parse_node(s) for s in ref_list]
            reference_broker_port = cfg.broker_port
            print(f"Using {len(reference_nodes)} reference node(s) to get clientId (broker port {reference_broker_port}).", file=sys.stderr)
        except Exception:
            print("No config/reference nodes; using fallback clientId.", file=sys.stderr)
        print(f"Connecting to {host}:{broker_port} (broker) network_id={args.network_id} ...", file=sys.stderr)
        print(f"Waiting up to {args.timeout:.0f}s for ChainState (node may send it on sync interval).", file=sys.stderr)
        cs = await get_chain_state_tcp(
            host,
            port,
            args.network_id,
            timeout=args.timeout,
            broker_port=args.broker_port,
            reference_nodes=reference_nodes,
            reference_broker_port=reference_broker_port,
        )
        if cs is None:
            print("Could not get ChainState (see messages above: timeout, handshake failed, or target closed connection).", file=sys.stderr)
            return 1
        if not cs.tips:
            print("Handshake OK but no ChainState received within timeout (node may use a long sync interval; try --timeout 60).", file=sys.stderr)
            return 1
        print("Got ChainState successfully.", file=sys.stderr)
        if args.json:
            groups = 4 if len(cs.tips) >= 16 else 2
            chain_heights = {f"{i // groups},{i % groups}": height for i, (_, height) in enumerate(cs.tips)}
            out = {
                "client_id": cs.client_id,
                "synced": cs.synced,
                "tips": [{"hash": h.hex(), "height": height} for h, height in cs.tips],
                "heights": [height for _, height in cs.tips],
                "chain_heights": chain_heights,
            }
            print(json.dumps(out, indent=2))
        else:
            print(f"clientId: {cs.client_id or '(none)'}")
            if cs.synced is None:
                print("synced: (unknown from broker; use REST /infos/self-clique-synced for real synced)")
            else:
                print(f"synced: {cs.synced}")
            print(f"chains: {len(cs.tips)}")
            if cs.tips:
                print("heights by chain (fromGroup, toGroup):")
                for i, (h, height) in enumerate(cs.tips):
                    from_g = i // 4
                    to_g = i % 4
                    print(f"  ({from_g},{to_g}): {height}  hash={h.hex()[:16]}...")
                heights = [height for _, height in cs.tips]
                print(f"heights JSON: {json.dumps(heights)}")
        return 0

    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
