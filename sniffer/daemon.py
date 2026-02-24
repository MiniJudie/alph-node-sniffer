"""
Daemon: UDP discovery proxy (relay) + periodic discovery + store nodes.
"""
import asyncio
import logging
import os
import random
import socket
import time
from typing import List, Optional, Set, Tuple

from sniffer.config import Config
from sniffer.db import (
    init_db,
    upsert_node,
    mark_exploration_success,
    mark_exploration_failed,
    get_nodes_to_explore,
    get_nodes_without_version,
    revive_if_dead,
)
from sniffer.geo import geolocate
from sniffer.protocol import (
    BrokerInfo,
    build_find_node_message,
    build_ping_message,
    describe_discovery_message,
    extract_neighbors_from_message,
    get_response_payload_type,
    magic_bytes,
)
from sniffer.version_check import check_rest_api, check_synced, get_client_version_tcp

logger = logging.getLogger(__name__)

# Default bootstrap (mainnet) if config empty
DEFAULT_MAINNET = [
    "bootstrap0.alephium.org:9973",
    "bootstrap1.alephium.org:9973",
    "bootstrap2.alephium.org:9973",
    "bootstrap3.alephium.org:9973",
    "bootstrap4.alephium.org:9973",
    "bootstrap5.alephium.org:9973",
]
DEFAULT_TESTNET = [
    "bootstrap0.testnet.alephium.org:9973",
    "bootstrap1.testnet.alephium.org:9973",
]


def _random_clique_id() -> bytes:
    return os.urandom(33)


def _display_node(host: str, domain: Optional[str]) -> str:
    """Prefer domain for logs when it looks like a hostname (not an IP)."""
    if domain and not (domain.replace(".", "").replace(":", "").isdigit()):
        return domain
    return host


class UDPProxy:
    """Relay discovery UDP: receive -> send to reference -> get response -> send back."""

    def __init__(self, config: Config):
        self.config = config
        self.sock: Optional[socket.socket] = None
        self.loop = asyncio.get_event_loop()
        self._ref_nodes: List[Tuple[str, int]] = []
        self._magic = magic_bytes(config.network_id)
        self._pending: Optional[Tuple[Tuple[str, int], Tuple[str, int], bytes]] = None  # (client_addr, ref_addr, request_data)
        self._network_debug = bool(os.environ.get("SNIFFER_NETWORK_DEBUG"))
        self._discovery_pending: Optional[Tuple[Tuple[str, int], asyncio.Future]] = None  # (target_addr, future) when waiting for discovery response

    def _get_ref_nodes(self) -> List[Tuple[str, int]]:
        if not self._ref_nodes:
            nodes = self.config.reference_nodes or (
                DEFAULT_MAINNET if self.config.network_id == 0 else DEFAULT_TESTNET
            )
            self._ref_nodes = [self.config.parse_node(s) for s in nodes]
        return self._ref_nodes

    async def start(self, bind_host: str, bind_port: int) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_host, bind_port))
        self.sock.setblocking(False)
        logger.info("UDP proxy bound to %s:%s", bind_host, bind_port)

    def stop(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    async def send_discovery_and_wait(
        self, data: bytes, target: Tuple[str, int], timeout: float
    ) -> Optional[bytes]:
        """Send discovery packet from proxy socket (port 9973) and wait for response. Returns response bytes or None on timeout."""
        if not self.sock:
            return None
        future: asyncio.Future[bytes] = self.loop.create_future()
        self._discovery_pending = (target, future)
        try:
            self.sock.sendto(data, target)
            if self._network_debug:
                logger.debug("UDP 9973 SEND (discovery) to %s:%s [%s] %d bytes", target[0], target[1], describe_discovery_message(data, self.config.network_id), len(data))
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self._discovery_pending = None

    async def relay_once(self) -> bool:
        """Read one datagram; if no pending, relay to ref and wait for response; else if from ref, send to client."""
        if not self.sock:
            return False
        try:
            data, addr = self.sock.recvfrom(65535)
        except BlockingIOError:
            return False
        if not data:
            return False
        addr_key = (addr[0], addr[1])
        if self._discovery_pending is not None and self._discovery_pending[0] == addr_key:
            _, future = self._discovery_pending
            self._discovery_pending = None
            if not future.done():
                future.set_result(data)
            return True
        if self._network_debug:
            desc = describe_discovery_message(data, self.config.network_id)
            logger.debug("UDP 9973 RECV from %s:%s [%s] %d bytes", addr[0], addr[1], desc, len(data))
        refs = self._get_ref_nodes()
        if not refs:
            return True
        if self._pending is None:
            ref = random.choice(refs)
            ref_addr = (ref[0], ref[1])
            self.sock.sendto(data, ref_addr)
            if self._network_debug:
                desc = describe_discovery_message(data, self.config.network_id)
                logger.debug("UDP 9973 SEND to %s:%s [%s] %d bytes", ref_addr[0], ref_addr[1], desc, len(data))
            self._pending = (addr, ref_addr, data)
            logger.info("Relay request from %s -> %s:%s (waiting response)", addr, ref[0], ref[1])
            return True
        client_addr, ref_addr, _ = self._pending
        if addr[0] == ref_addr[0] and addr[1] == ref_addr[1]:
            if self._network_debug:
                desc = describe_discovery_message(data, self.config.network_id)
                logger.debug("UDP 9973 RECV from %s:%s [%s] %d bytes", ref_addr[0], ref_addr[1], desc, len(data))
            self.sock.sendto(data, client_addr)
            if self._network_debug:
                desc = describe_discovery_message(data, self.config.network_id)
                logger.debug("UDP 9973 SEND to %s:%s [%s] %d bytes", client_addr[0], client_addr[1], desc, len(data))
            logger.info("Relay response from %s:%s -> %s", ref_addr[0], ref_addr[1], client_addr)
            self._pending = None
        return True

    async def run_relay_loop(self) -> None:
        while self.sock:
            try:
                await self.relay_once()
            except Exception as e:
                logger.warning("Relay error: %s", e)
            await asyncio.sleep(0.01)


def _send_udp_sync(host: str, port: int, data: bytes, timeout: float) -> Optional[bytes]:
    """Blocking: send UDP and wait for one response. Run via run_in_executor to avoid blocking the event loop."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(data, (host, port))
        resp, _ = sock.recvfrom(65535)
        sock.close()
        return resp
    except (socket.timeout, OSError):
        return None


async def _send_udp(host: str, port: int, data: bytes, timeout: float) -> Optional[bytes]:
    """Send UDP and wait for one response (runs in thread so relay loop can receive)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: _send_udp_sync(host, port, data, timeout)
    )


def _discover_node_sync(
    host: str,
    port: int,
    network_id: int,
    timeout: float,
) -> Optional[bytes]:
    """
    Blocking: Try FindNode first (like Alephium bootstrap), then Ping+FindNode. Run via run_in_executor.
    """
    network_debug = bool(os.environ.get("SNIFFER_NETWORK_DEBUG"))
    find_first_timeout = min(timeout, 10.0)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(find_first_timeout)
        find_msg = build_find_node_message(network_id, os.urandom(33))
        sock.sendto(find_msg, (host, port))
        if network_debug:
            logger.debug("DISCOVERY SEND to %s:%s [FindNode first] %d bytes", host, port, len(find_msg))
        try:
            resp, from_addr = sock.recvfrom(65535)
            if network_debug:
                logger.debug("DISCOVERY RECV from %s:%s [%s] %d bytes (FindNode-first)", from_addr[0], from_addr[1], describe_discovery_message(resp, network_id), len(resp))
            return resp
        except socket.timeout:
            if network_debug:
                logger.debug("DISCOVERY RECV from %s:%s (FindNode-first timeout)", host, port)
        # Fallback: Ping then FindNode
        ping_timeout = min(3.0, max(0, timeout - find_first_timeout) / 2)
        find_timeout = max(1.0, timeout - find_first_timeout - ping_timeout)
        ping_msg = build_ping_message(network_id, os.urandom(32))
        sock.settimeout(ping_timeout)
        sock.sendto(ping_msg, (host, port))
        if network_debug:
            logger.debug("DISCOVERY SEND to %s:%s [%s] %d bytes", host, port, describe_discovery_message(ping_msg, network_id), len(ping_msg))
        try:
            first, from_addr = sock.recvfrom(65535)
            if network_debug:
                logger.debug("DISCOVERY RECV from %s:%s [%s] %d bytes", from_addr[0], from_addr[1], describe_discovery_message(first, network_id), len(first))
        except socket.timeout:
            if network_debug:
                logger.debug("DISCOVERY RECV from %s:%s (Pong timeout)", host, port)
        sock.settimeout(find_timeout)
        sock.sendto(find_msg, (host, port))
        if network_debug:
            logger.debug("DISCOVERY SEND to %s:%s [%s] %d bytes", host, port, describe_discovery_message(find_msg, network_id), len(find_msg))
        try:
            resp, from_addr = sock.recvfrom(65535)
        except socket.timeout:
            if network_debug:
                logger.debug("DISCOVERY RECV from %s:%s (Neighbors timeout)", host, port)
            return None
        if network_debug:
            logger.debug("DISCOVERY RECV from %s:%s [%s] %d bytes", from_addr[0], from_addr[1], describe_discovery_message(resp, network_id), len(resp))
        return resp
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


async def _discover_node(
    host: str, port: int, network_id: int, timeout: float
) -> Optional[bytes]:
    """Ping then FindNode on same socket (in thread); returns raw Neighbors bytes or None."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: _discover_node_sync(host, port, network_id, timeout),
    )


async def _discover_node_via_proxy(
    proxy: "UDPProxy",
    host: str,
    port: int,
    network_id: int,
    timeout: float,
) -> Optional[bytes]:
    """Try FindNode first (like Alephium bootstrap), then Ping+FindNode from proxy socket (port 9973). Returns Neighbors bytes or None."""
    target = (host, port)
    find_msg = build_find_node_message(network_id, os.urandom(33))
    ping_msg = build_ping_message(network_id, os.urandom(32))
    # 1) FindNode only first (how real nodes bootstrap: fetchNeighbors sends FindNode with no prior Ping)
    find_timeout = min(timeout, 10.0)
    resp = await proxy.send_discovery_and_wait(find_msg, target, find_timeout)
    if resp is not None:
        if os.environ.get("SNIFFER_NETWORK_DEBUG"):
            logger.debug("UDP 9973 RECV (discovery) from %s:%s [%s] %d bytes (FindNode-first)", host, port, describe_discovery_message(resp, network_id), len(resp))
        return resp
    # 2) Fallback: Ping then FindNode
    ping_timeout = min(3.0, max(0, timeout - find_timeout) / 2)
    find_timeout2 = max(1.0, timeout - find_timeout - ping_timeout)
    pong = await proxy.send_discovery_and_wait(ping_msg, target, ping_timeout)
    if pong is not None and os.environ.get("SNIFFER_NETWORK_DEBUG"):
        logger.debug("UDP 9973 RECV (discovery) from %s:%s [%s] %d bytes", host, port, describe_discovery_message(pong, network_id), len(pong))
    neighbors_resp = await proxy.send_discovery_and_wait(find_msg, target, find_timeout2)
    if neighbors_resp is not None and os.environ.get("SNIFFER_NETWORK_DEBUG"):
        logger.debug("UDP 9973 RECV (discovery) from %s:%s [%s] %d bytes", host, port, describe_discovery_message(neighbors_resp, network_id), len(neighbors_resp))
    return neighbors_resp


async def discover_from_node(
    config: Config,
    host: str,
    port: int,
    network_id: int,
) -> List[BrokerInfo]:
    """Send FindNode to (host, port), return list of BrokerInfo from Neighbors."""
    msg = build_find_node_message(network_id, _random_clique_id())
    resp = await _send_udp(host, port, msg, float(config.udp_timeout_seconds))
    if not resp:
        return []
    neighbors = extract_neighbors_from_message(resp, network_id)
    if neighbors:
        logger.info("FindNode %s:%s -> %d neighbors: %s", host, port, len(neighbors), [(n.address, n.port) for n in neighbors[:5]])
    return neighbors


async def enrich_node(config: Config, db_path: str, address: str, port: int, *, display_name: Optional[str] = None) -> None:
    """Resolve, fetch geolocation and REST version, update DB. Safe to call in background. display_name used in logs when provided."""
    from sniffer.db import update_node_enrichment
    host = address
    if not host.replace(".", "").replace(":", "").isdigit():
        try:
            resolved = await asyncio.get_event_loop().getaddrinfo(
                host, port, type=socket.SOCK_DGRAM
            )
            if resolved:
                host = resolved[0][4][0]
        except Exception:
            pass
    country, city, continent = await geolocate(host)
    has_api, version = await check_rest_api(host, config.rest_port_probe)
    if version is None:
        try:
            version = await get_client_version_tcp(
                host, config.broker_port, config.network_id, timeout=5.0
            )
        except Exception:
            pass
    synced: Optional[bool] = None
    if has_api:
        try:
            synced = await check_synced(host, config.rest_port_probe, timeout=5.0)
        except Exception:
            pass
    await update_node_enrichment(
        db_path,
        host,
        port,
        domain=address if address != host else None,
        version=version,
        country=country,
        city=city,
        continent=continent,
        has_api=has_api,
        synced=synced,
    )
    log_label = display_name if display_name else _display_node(host, address if address != host else None)
    logger.info("Enriched %s:%s version=%s country=%s has_api=%s synced=%s", log_label, port, version, country, has_api, synced)


async def ensure_node_in_db(db_path: str, address: str, port: int, from_neighbors: bool = True) -> None:
    """Ensure node exists in DB with status offline and last_explored=0 so it gets explored. Revive if dead. Resolve hostname to IP for canonical key."""
    host = address
    if not host.replace(".", "").replace(":", "").isdigit():
        try:
            resolved = await asyncio.get_event_loop().getaddrinfo(
                host, port, type=socket.SOCK_DGRAM
            )
            if resolved:
                host = resolved[0][4][0]
        except Exception:
            pass
    if from_neighbors:
        await revive_if_dead(db_path, address, port)
        if host != address:
            await revive_if_dead(db_path, host, port)
    await upsert_node(
        db_path,
        host,
        port,
        domain=address if address != host else None,
        status="offline",
        last_explored=0.0,
    )


async def process_and_store_node(
    config: Config,
    db_path: str,
    info: BrokerInfo,
) -> None:
    """Resolve domain to IP if needed, geolocate, check API, upsert (background enrichment)."""
    host = info.address
    port = info.port
    if not host.replace(".", "").replace(":", "").isdigit():
        try:
            resolved = await asyncio.get_event_loop().getaddrinfo(
                host, port, type=socket.SOCK_DGRAM
            )
            if resolved:
                host = resolved[0][4][0]
        except Exception:
            pass
    country, city, continent = await geolocate(host)
    has_api, version = await check_rest_api(host, config.rest_port_probe)
    if version is None:
        try:
            version = await get_client_version_tcp(
                host, config.broker_port, config.network_id, timeout=5.0
            )
        except Exception:
            pass
    synced: Optional[bool] = None
    if has_api:
        try:
            synced = await check_synced(host, config.rest_port_probe, timeout=5.0)
        except Exception:
            pass
    clique_id_hex = info.clique_id.hex() if info.clique_id else None
    await upsert_node(
        db_path,
        host,
        port,
        domain=info.address if info.address != host else None,
        clique_id=clique_id_hex,
        version=version,
        country=country,
        city=city,
        continent=continent,
        has_api=has_api,
        synced=synced,
        status="offline",
    )
    logger.info("Node %s:%s version=%s country=%s has_api=%s synced=%s", _display_node(host, info.address if info.address != host else None), port, version, country, has_api, synced)


# Delay between each FindNode in a cycle (seconds) to avoid flooding
FINDNODE_DELAY_SEC = 2.0


async def discovery_loop(config: Config, db_path: str, proxy: Optional["UDPProxy"] = None) -> None:
    """Ask every known node for neighbors (one full cycle), then restart from start. On no response 30m -> offline, 48h -> dead."""
    await init_db(db_path)
    network_id = config.network_id
    start_list = config.starting_nodes or (
        DEFAULT_MAINNET if network_id == 0 else DEFAULT_TESTNET
    )
    # Include reference_nodes in discovery so they get explored too (merge, dedupe by (host, port))
    ref_list = config.reference_nodes or []
    seen: Set[Tuple[str, int]] = set()
    to_ask: List[Tuple[str, int]] = []
    for s in start_list:
        t = config.parse_node(s)
        if t not in seen:
            seen.add(t)
            to_ask.append(t)
    for s in ref_list:
        t = config.parse_node(s)
        if t not in seen:
            seen.add(t)
            to_ask.append(t)
    for (h, p) in to_ask:
        await ensure_node_in_db(db_path, h, p, from_neighbors=False)
        asyncio.create_task(enrich_node(config, db_path, h, p))

    while True:
        # Drain to_ask into DB so they appear in get_nodes_to_explore
        while to_ask:
            host, port = to_ask.pop(0)
            await ensure_node_in_db(db_path, host, port, from_neighbors=True)

        # Get ALL nodes to explore (online/offline, ordered by last_explored oldest first)
        candidates = await get_nodes_to_explore(db_path, limit=10000)
        if not candidates:
            logger.info("Discovery: no nodes to explore, waiting %s s then retrying", config.scan_interval_seconds)
            await asyncio.sleep(config.scan_interval_seconds)
            to_ask = list(seen)
            continue

        logger.info("Discovery cycle: asking %d nodes for neighbors", len(candidates))
        for host, port, domain in candidates:
            explore_host = host
            if not host.replace(".", "").replace(":", "").isdigit():
                try:
                    resolved = await asyncio.get_event_loop().getaddrinfo(
                        host, port, type=socket.SOCK_DGRAM
                    )
                    if resolved:
                        explore_host = resolved[0][4][0]
                except Exception:
                    pass

            display = _display_node(explore_host, domain)
            try:
                logger.info("FindNode (discover neighbor) -> %s:%s", display, port)
                resp = None
                if proxy is not None:
                    resp = await _discover_node_via_proxy(proxy, explore_host, port, network_id, float(config.udp_timeout_seconds))
                if resp is None:
                    resp = await _discover_node(
                        explore_host,
                        port,
                        network_id,
                        float(config.udp_timeout_seconds),
                    )
                if not resp:
                    logger.info("FindNode reply from %s:%s: (no response / timeout)", display, port)
                    if os.environ.get("SNIFFER_DEBUG"):
                        logger.debug("Sent Ping then FindNode; no reply (check magic bytes / firewall)")
                    await mark_exploration_failed(db_path, explore_host, port)
                    asyncio.create_task(enrich_node(config, db_path, explore_host, port, display_name=display))
                else:
                    if os.environ.get("SNIFFER_DEBUG"):
                        logger.debug("Raw reply %d bytes, magic(4)=%s", len(resp), resp[:4].hex() if len(resp) >= 4 else "?")
                    neighbors = extract_neighbors_from_message(resp, network_id)
                    if neighbors:
                        logger.info("FindNode reply from %s:%s: %d bytes -> %d neighbors: %s", display, port, len(resp), len(neighbors), [(n.address, n.port) for n in neighbors[:8]])
                        await mark_exploration_success(db_path, explore_host, port)
                        asyncio.create_task(enrich_node(config, db_path, explore_host, port, display_name=display))
                        for info in neighbors:
                            key = (info.address, info.port)
                            if key not in seen:
                                seen.add(key)
                                to_ask.append((info.address, info.port))
                                await ensure_node_in_db(db_path, info.address, info.port, from_neighbors=True)
                                asyncio.create_task(
                                    process_and_store_node(config, db_path, info)
                                )
                    else:
                        payload_type, _ = get_response_payload_type(resp, network_id)
                        if payload_type is not None:
                            logger.info(
                                "FindNode reply from %s:%s: %d bytes, payload_type=%s (expected 3=Neighbors)",
                                display, port, len(resp), payload_type,
                            )
                        else:
                            logger.info(
                                "FindNode reply from %s:%s: %d bytes (unwrap/parse failed)",
                                display, port, len(resp),
                            )
                        await mark_exploration_failed(db_path, explore_host, port)
                        asyncio.create_task(enrich_node(config, db_path, explore_host, port, display_name=display))
            except Exception as e:
                logger.warning("Discovery from %s:%s failed: %s", display, port, e)
                await mark_exploration_failed(db_path, explore_host, port)
                asyncio.create_task(enrich_node(config, db_path, explore_host, port, display_name=display))

            await asyncio.sleep(FINDNODE_DELAY_SEC)

        # Retry enrichment for nodes that still have no version (REST or TCP may have failed earlier)
        without_version = await get_nodes_without_version(db_path, limit=30)
        if without_version:
            logger.info("Re-enriching %d nodes without version", len(without_version))
            for host, port, domain in without_version:
                display = _display_node(host, domain)
                asyncio.create_task(enrich_node(config, db_path, host, port, display_name=display))

        logger.info("Discovery cycle done (%d nodes). Restarting from start in %s s.", len(candidates), config.scan_interval_seconds)
        await asyncio.sleep(config.scan_interval_seconds)


def _run_api_server(config: Config) -> None:
    """Blocking: run HTTP API (for use in a thread)."""
    import uvicorn
    from sniffer.api import create_app
    app = create_app(config, config.database_path)
    log_level = "warning" if os.environ.get("SNIFFER_NETWORK_DEBUG") else "info"
    uvicorn.run(app, host=config.http_host, port=config.http_port, log_level=log_level)


async def run_daemon(config: Config) -> None:
    """Run UDP proxy + discovery loop + HTTP API in a thread."""
    await init_db(config.database_path)
    host, port = config.parse_bind()
    proxy = UDPProxy(config)
    await proxy.start(host, port)
    import threading
    api_thread = threading.Thread(target=_run_api_server, args=(config,), daemon=True)
    api_thread.start()
    logger.info("HTTP API on http://%s:%s/docs", config.http_host, config.http_port)
    try:
        await asyncio.gather(
            proxy.run_relay_loop(),
            discovery_loop(config, config.database_path, proxy),
        )
    finally:
        proxy.stop()
