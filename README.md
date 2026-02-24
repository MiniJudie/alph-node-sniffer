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
- **reference_nodes**: Nodes used to relay incoming discovery requests; they are **also** added to the discovery list so they get explored for neighbors (merged with starting_nodes, no duplicate).
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
# Activate the venv and install deps first (see Setup) if you haven't yet
source .venv/bin/activate
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

To log **every UDP packet on port 9973** (all discovery messages received and sent by the proxy) and **every discovery Ping/FindNode** sent and received, set `SNIFFER_NETWORK_DEBUG`:

```bash
SNIFFER_NETWORK_DEBUG=1 python3 -m sniffer daemon
```

You will see:
- **UDP 9973 RECV/SEND** – traffic on the proxy socket (port 9973), i.e. when another node talks to your sniffer or the proxy relays to a reference node. If no one sends to your 9973, there will be no lines.
- **DISCOVERY SEND/RECV** – Ping and FindNode traffic to bootstrap/peers (outbound from an ephemeral port). Use this to confirm that discovery packets are sent and whether Pong/Neighbors replies are received or timeout.

Example:
- `DISCOVERY SEND to bootstrap0.alephium.org:9973 [Ping] 99 bytes`
- `DISCOVERY RECV from 3.14.19.103:9973 (Pong timeout)` or `[Pong] 184 bytes`
- `DISCOVERY SEND to bootstrap0.alephium.org:9973 [FindNode] 98 bytes`
- `DISCOVERY RECV from 3.14.19.103:9973 [Neighbors (5 peers)] 200 bytes` or `(Neighbors timeout)`

(DEBUG level is enabled automatically when either `SNIFFER_DEBUG` or `SNIFFER_NETWORK_DEBUG` is set.)

Discovery tries **FindNode first** (no Ping), matching how Alephium bootstraps (`fetchNeighbors` sends FindNode directly). If that times out, it tries Ping then FindNode. It also uses the **proxy socket (port 9973)** first, then falls back to an ephemeral port. The protocol does not require a separate “hello” before FindNode. If you still see timeouts, **incoming UDP** to your host is likely blocked (firewall/NAT): allow port 9973 and ephemeral ports.

## API

- `GET /reference-nodes` – reference nodes used.
- `GET /stats` – total discovered, online, offline.
- `GET /versions` – all node versions with counts.
- `GET /nodes` – list nodes (query: `continent`, `country`, `has_api`, `version`).

## Note

The `alephium/` directory contains the upstream fullnode code for reference only; do not modify it. This project only implements a minimal discovery client and proxy.
