"""Load config from YAML."""
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import yaml


@dataclass
class Config:
    network_id: int = 0
    bind_address: str = "0.0.0.0:9973"
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    starting_nodes: List[str] = field(default_factory=list)
    reference_nodes: List[str] = field(default_factory=list)
    database_path: str = "nodes.db"
    rest_port_probe: int = 12973
    scan_interval_seconds: int = 300
    udp_timeout_seconds: int = 5

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        if path is None:
            path = os.environ.get("SNIFFER_CONFIG", "config.yaml")
        path = Path(path)
        if not path.exists() and path.name == "config.yaml":
            alt = path.parent / "config.example.yaml"
            if alt.exists():
                path = alt
        if not path.exists():
            return cls()
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(
            network_id=data.get("network_id", 0),
            bind_address=data.get("bind_address", "0.0.0.0:9973"),
            http_host=data.get("http_host", "0.0.0.0"),
            http_port=data.get("http_port", 8080),
            starting_nodes=data.get("starting_nodes", []),
            reference_nodes=data.get("reference_nodes", []),
            database_path=data.get("database_path", "nodes.db"),
            rest_port_probe=data.get("rest_port_probe", 12973),
            scan_interval_seconds=data.get("scan_interval_seconds", 300),
            udp_timeout_seconds=data.get("udp_timeout_seconds", 5),
        )

    def parse_bind(self) -> tuple[str, int]:
        host, _, port = self.bind_address.rpartition(":")
        return (host or "0.0.0.0", int(port or 9973))

    def parse_node(self, s: str) -> tuple[str, int]:
        """Return (host, port) for 'host:port'."""
        if ":" in s:
            host, _, port = s.rpartition(":")
            return (host.strip(), int(port))
        return (s.strip(), 9973)
