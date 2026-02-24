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

## Setup

Requires **Python 3.10+**. On Debian/Ubuntu and other systems that use an externally-managed Python environment, use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

(If you prefer not to use a venv, ensure you have a Python where `pip install` is allowed, e.g. `pip install --user -r requirements.txt` or a non-system Python.)

## Run

Copy `config.example.yaml` to `config.yaml` and edit if needed (or the daemon will use the example config).

```bash
# With venv activated (see Setup)
python3 -m sniffer daemon
```

Or run the HTTP API only:

```bash
python3 -m sniffer api
```

- Discovery proxy: UDP on `bind_address` (default 0.0.0.0:9973).
- Explorer API: http://localhost:9090 (Swagger at http://localhost:9090/docs).

## Debug

To see detailed debug messages (e.g. discovery reply hex, ping/findnode hints), set `SNIFFER_DEBUG` and run the daemon:

```bash
SNIFFER_DEBUG=1 python3 -m sniffer daemon
```

This turns on DEBUG logging for the sniffer and prints extra lines when probing nodes (e.g. raw reply size and magic bytes when a response is received, or a hint when no reply is received).

## API

- `GET /reference-nodes` – reference nodes used.
- `GET /stats` – total discovered, online, offline.
- `GET /versions` – all node versions with counts.
- `GET /nodes` – list nodes (query: `continent`, `country`, `has_api`, `version`).

## Note

The `alephium/` directory contains the upstream fullnode code for reference only; do not modify it. This project only implements a minimal discovery client and proxy.
