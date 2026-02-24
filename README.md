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
- **broker_port**: TCP broker port (default 27665) used to fetch **client version** via the P2P Hello message when the REST API does not expose a version.

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

To **manually ping a node** (send one Ping and wait for Pong):

```bash
python3 -m sniffer ping bootstrap0.alephium.org:9973
python3 -m sniffer ping 1.2.3.4:9973 --network-id 1 --timeout 10
```

- Discovery proxy: UDP on `bind_address` (default 0.0.0.0:9973).
- Explorer API: http://localhost:9090 (Swagger at http://localhost:9090/docs).

## systemd (optional)

To run the daemon as a system service with automatic restart on crash:

1. Copy the template and set your project path and user (e.g. your own user instead of `sniffer`):
   ```bash
   sudo cp alephium-node-sniffer.service /etc/systemd/system/
   sudo sed -i 's|/path/to/alph-node-sniffer|/home/you/alph-node-sniffer|g' /etc/systemd/system/alephium-node-sniffer.service
   ```
   Edit `/etc/systemd/system/alephium-node-sniffer.service` to set `User=` and `Group=` (e.g. your user) and ensure `ExecStart` uses your venv path or `/usr/bin/python3 -m sniffer daemon` if not using a venv.

2. Reload systemd, enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now alephium-node-sniffer
   ```

3. Check status and logs:
   ```bash
   sudo systemctl status alephium-node-sniffer
   journalctl -u alephium-node-sniffer -f
   ```

The unit uses `Restart=on-failure` and `RestartSec=10` so the process is restarted automatically when it exits unsuccessfully.

## UDP discovery vs TCP broker (real nodes)

A full Alephium node uses **two separate channels**:

1. **UDP discovery (port 9973)** – Handled by `DiscoveryServer`. Receives Ping, Pong, FindNode, Neighbors. **No Hello or client id**. The node responds to FindNode with Neighbors and to Ping with Pong without any prior handshake. At startup it sends FindNode to bootstrap nodes directly (`fetchNeighbors`).

2. **TCP broker (e.g. port 27665)** – Handled by `InterCliqueManager` / `InboundBrokerHandler`. Used for flow data (blocks, sync). The **first** message on TCP is **Hello** (with `clientId` like `scala-alephium/v4.3.0/Linux`). The node validates `ReleaseVersion` and `P2PVersion` from `clientId`; if the version is unknown or unsupported, it logs “Unknown client id” and **bans** that TCP peer (`InvalidClientVersion`). So the bans you see in node logs are for **TCP** connections with an invalid or old client version, not for UDP discovery.

**This sniffer** uses **UDP discovery** (port 9973) for neighbors. It also opens a **TCP** connection to each node’s broker port (configurable `broker_port`, default 27665) when enriching: it connects, **reads** the first Hello message (server sends first on inbound), extracts `clientId` for the version field, then closes without sending anything—so it is **not** subject to InvalidClientVersion. Discovery itself does not require TCP; if discovery times out, the cause is typically **incoming UDP** being blocked (firewall/NAT).

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

To **inspect the exact bytes** we send for Ping and FindNode (e.g. to compare with a capture or the Alephium spec), run:

```bash
python3 scripts/dump_discovery_bytes.py [network_id]
```

This prints full hex and a per-field breakdown (magic, checksum, length, signature, header, payload type, payload). Default `network_id` is 0 (mainnet). Our encoding is documented and verified against `alephium/protocol` (see `sniffer/protocol.py` docstring).

To **send a FindNode and print the parsed Neighbors response**:

```bash
python3 scripts/find_neighbors.py <host:port> [--network-id 0] [--timeout 10]
```

Example: `python3 scripts/find_neighbors.py bootstrap0.alephium.org:9973`. If you get a timeout, incoming UDP to your host may be blocked (firewall/NAT).

## API

- `GET /nodes` – Paginated list of nodes. Response: `{ "stats": { "total", "online", "offline", "dead", "last_update" }, "nodes": [ ... ] }`.  
  Each node includes: address, port, domain, version, country, city, continent, has_api, synced, status, **reverse_dns** (PTR hostname), **hoster** (WHOIS/RDAP org, e.g. ISP or cloud provider).  
  Query: `page` (default 1), `limit` (default 50, max 1000), and filters: `continent`, `country`, `has_api`, `version`, `status`, `synced` (true/false for synced or not).

## Note

The `alephium/` directory contains the upstream fullnode code for reference only; do not modify it. This project only implements a minimal discovery client and proxy.
