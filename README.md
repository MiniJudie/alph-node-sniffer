# Alephium Node Sniffer / Proxy

A small proxy that connects to the Alephium P2P discovery network, discovers nodes, and exposes an HTTP API to explore the network.

## Features

- **Discovery proxy**: Listens on UDP (default 9973), relays discovery requests to reference nodes and returns responses so it appears as a normal node.
- **Node discovery**: Connects to starting/reference nodes, sends FindNode and Ping, collects Neighbors responses, and stores all discovered nodes.
- **Local database**: SQLite store for nodes (address, domain, IP, version, country, city, exposes HTTP API).
- **Daemon mode**: Runs continuously, periodically scanning for more neighbors.
- **HTTP API + Swagger**: REST API with filters (continent, country, has API, version).

## Config

Copy `config.example.yaml` to `config.yaml`. Key options:

- **starting_nodes**: Bootstrap list to connect to first.
- **reference_nodes**: Nodes used to relay incoming discovery requests (e.g. mainnet bootstrap from `alephium/flow/src/main/resources/network_mainnet.conf.tmpl`).
- **network_id**: `0` = mainnet, `1` = testnet.

Reference nodes for mainnet (from Alephium config):

- bootstrap0.alephium.org:9973 … bootstrap5.alephium.org:9973

Testnet (when network_id=1):

- bootstrap0.testnet.alephium.org:9973, bootstrap1.testnet.alephium.org:9973

## Run

Requires **Python 3.10+** (use `python3` on systems where `python` is not 3.x).

```bash
pip install -r requirements.txt
# Edit config.yaml if needed (or it will use config.example.yaml)
python3 -m sniffer daemon
```

Or run the HTTP API only:

```bash
python3 -m sniffer api
```

- Discovery proxy: UDP on `bind_address` (default 0.0.0.0:9973).
- Explorer API: http://localhost:9090 (Swagger at http://localhost:9090/docs).

## API

- `GET /reference-nodes` – reference nodes used.
- `GET /stats` – total discovered, online, offline.
- `GET /versions` – all node versions with counts.
- `GET /nodes` – list nodes (query: `continent`, `country`, `has_api`, `version`).

## Note

The `alephium/` directory contains the upstream fullnode code for reference only; do not modify it. This project only implements a minimal discovery client and proxy.
