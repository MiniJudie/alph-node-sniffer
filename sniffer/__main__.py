"""Entrypoint: python -m sniffer daemon | api."""
import argparse
import asyncio
import logging
import sys

from sniffer.api import create_app
from sniffer.config import Config
from sniffer.daemon import run_daemon
from sniffer.db import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Alephium Node Sniffer / Proxy")
    parser.add_argument(
        "command",
        nargs="?",
        default="daemon",
        choices=["daemon", "api"],
        help="daemon (default): run proxy + discovery; api: run HTTP API only",
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Config file path",
    )
    args = parser.parse_args()
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
