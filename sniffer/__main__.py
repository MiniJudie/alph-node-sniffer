"""Entrypoint: python -m sniffer daemon | api | ping."""
import argparse
import asyncio
import logging
import os
import socket
import sys

from sniffer.api import create_app
from sniffer.config import Config
from sniffer.daemon import run_daemon
from sniffer.db import init_db
from sniffer.protocol import (
    build_ping_message,
    describe_discovery_message,
    get_response_payload_type,
    magic_bytes,
)

logging.basicConfig(
    level=logging.DEBUG if (os.environ.get("SNIFFER_DEBUG") or os.environ.get("SNIFFER_NETWORK_DEBUG")) else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
if os.environ.get("SNIFFER_NETWORK_DEBUG"):
    for name in (
        "httpx", "httpcore", "aiosqlite",
        "uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.default",
        "asyncio",
        "sniffer.version_check", "sniffer.geo",
    ):
        logging.getLogger(name).setLevel(logging.WARNING)


def _run_ping(host: str, port: int, network_id: int, timeout: float) -> None:
    """Send a single Ping to host:port and print whether we got a Pong."""
    session_id = os.urandom(32)
    msg = build_ping_message(network_id, session_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, (host, port))
        print(f"Ping sent to {host}:{port} ({len(msg)} bytes, network_id={network_id})")
        raw, addr = sock.recvfrom(4096)
        payload_type, _ = get_response_payload_type(raw, network_id)
        desc = describe_discovery_message(raw, network_id)
        print(f"Response from {addr[0]}:{addr[1]}: {desc} ({len(raw)} bytes)")
        if payload_type == 1:
            print("OK: Pong received.")
        else:
            print(f"(Expected Pong (type=1), got type={payload_type})")
    except socket.timeout:
        print(f"No response within {timeout}s (timeout).")
    except OSError as e:
        print(f"Error: {e}")
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Alephium Node Sniffer / Proxy")
    parser.add_argument(
        "command",
        nargs="?",
        default="daemon",
        choices=["daemon", "api", "ping"],
        help="daemon (default): run proxy + discovery; api: HTTP API only; ping: send Ping to a node",
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Config file path (used for daemon/api)",
    )
    parser.add_argument(
        "--network-id",
        type=int,
        default=0,
        help="Network ID for ping (0=mainnet, 1=testnet). Default: 0",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Seconds to wait for Pong (ping only). Default: 5",
    )
    args, rest = parser.parse_known_args()

    if args.command == "ping":
        if not rest or ":" not in rest[0]:
            parser.error("ping requires host:port, e.g. bootstrap0.alephium.org:9973")
        part = rest[0].rsplit(":", 1)
        host = part[0]
        port = int(part[1])
        _run_ping(host, port, args.network_id, args.timeout)
        return

    config = Config.load(args.config)

    if args.command == "daemon":
        asyncio.run(run_daemon(config))
    elif args.command == "api":
        import uvicorn
        asyncio.run(init_db(config.database_path))
        app = create_app(config, config.database_path)
        uvicorn.run(
            app,
            host=config.http_host,
            port=config.http_port,
            log_level="info",
        )


if __name__ == "__main__":
    main()
