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
    _heights_within_threshold_of_max,
    get_max_network_heights,
    get_node_geo_dns,
    init_db,
    upsert_node,
    update_node_enrichment,
    mark_exploration_success,
    mark_exploration_failed,
    get_nodes_to_explore,
    get_nodes_without_version,
    revive_if_dead,
    update_synced_for_clique_peers,
    upsert_node_port,
    update_node_port_statuses,
    update_node_status_from_port_statuses,
    PORT_STATUS_REACHABLE,
    PORT_STATUS_CLOSED,
    PORT_TYPE_DISCOVERY,
    PORT_TYPE_BROKER,
    PORT_TYPE_REST,
)
from sniffer.geo import geolocate
from sniffer.lookup import reverse_dns_and_whois
from sniffer.protocol import (
    BrokerInfo,
    build_find_node_message,
    build_ping_message,
    describe_discovery_message,
    extract_neighbors_from_message,
    get_response_payload_type,
    magic_bytes,
    ping_reply_pong,
)
from sniffer.version_check import (
    check_rest_api,
    fetch_chain_heights_rest,
    fetch_inter_clique_peer_info,
    fetch_self_clique,
    _try_port,
    get_client_version_tcp,
    get_chain_state_tcp,
    parse_client_id,
    _try_port,
)

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
    async with _ENRICH_SEMAPHORE:
        await _enrich_node_impl(config, db_path, address, port, display_name=display_name)


async def _enrich_node_impl(config: Config, db_path: str, address: str, port: int, *, display_name: Optional[str] = None) -> None:
    """Internal: actual enrichment logic. Called under _ENRICH_SEMAPHORE."""
    host = address
    if not host.replace(".", "").replace(":", "").isdigit():
        ip = await _resolve_host(host, port)
        if ip:
            host = ip
    existing = await get_node_geo_dns(db_path, host)
    if existing:
        country, city, continent, country_code, isp, org, zip_val, lat, lon, reverse_dns_name, hoster = existing
        has_geo = country is not None or city is not None or isp is not None
        has_dns = reverse_dns_name is not None or hoster is not None
    else:
        has_geo, has_dns = False, False
        country = city = continent = country_code = isp = org = zip_val = reverse_dns_name = hoster = None
        lat = lon = None
    if not has_geo:
        country, city, continent, country_code, isp, org, zip_val, lat, lon = await geolocate(host)
    if not has_dns:
        reverse_dns_name, hoster = await reverse_dns_and_whois(host)
    has_api, version = await check_rest_api(host, config.rest_port_probe, timeout=2.0)
    client_id_raw: Optional[str] = None
    if version is None:
        try:
            version = await get_client_version_tcp(
                host, port, config.network_id, timeout=5.0
            )
            if version is not None:
                client_id_raw = version
        except Exception:
            pass
    if client_id_raw is None:
        try:
            client_id_raw = await get_client_version_tcp(
                host, port, config.network_id, timeout=5.0
            )
        except Exception:
            pass
    synced: Optional[bool] = None
    if has_api:
        try:
            self_clique = await fetch_self_clique(host, config.rest_port_probe, timeout=5.0)
            if self_clique is not None:
                synced, peer_addresses = self_clique
                if peer_addresses:
                    updated = await update_synced_for_clique_peers(db_path, peer_addresses, synced)
                    if updated:
                        logger.debug("Updated synced=%s for %s clique peer(s)", synced, updated)
            inter_peers = await fetch_inter_clique_peer_info(host, config.rest_port_probe, timeout=5.0)
            if inter_peers:
                added = 0
                for addr in inter_peers:
                    ok, _ = await _try_port(addr, 9973, timeout=2.0)
                    if ok:
                        await ensure_node_in_db(db_path, addr, 9973)
                        added += 1
                    resp = await discover_from_node(config, addr, 9973, config.network_id)
                    if resp:
                        await ensure_node_in_db(db_path, addr, 9973)
                        added += 1
                        for info in resp:
                            await ensure_node_in_db(db_path, info.address, info.port)
                            asyncio.create_task(process_and_store_node(config, db_path, info))
                if added > 0:
                    logger.debug("Added inter-clique peer(s) from REST+FindNode for next iteration")
        except Exception:
            pass
    chain_heights: Optional[List[int]] = None
    if has_api:
        try:
            groups = 4 if config.network_id == 0 else 2
            chain_heights = await fetch_chain_heights_rest(
                host, config.rest_port_probe, groups=groups, timeout=3.0
            )
        except Exception:
            pass
    if chain_heights is None:
        ref_list = config.reference_nodes or (
            DEFAULT_MAINNET if config.network_id == 0 else DEFAULT_TESTNET
        )
        reference_nodes = [config.parse_node(s) for s in ref_list]
        try:
            cs = await get_chain_state_tcp(
                host,
                port,
                config.network_id,
                timeout=8.0,
                broker_port=port,
                reference_nodes=reference_nodes,
                reference_broker_port=None,
            )
            if cs is not None:
                chain_heights = [height for _, height in cs.tips]
                if synced is None:
                    synced = cs.synced
                if client_id_raw is None and cs.client_id:
                    client_id_raw = cs.client_id
        except Exception:
            pass
    client_parsed = parse_client_id(client_id_raw) if client_id_raw else None
    version_str = version
    client_str: Optional[str] = None
    os_str: Optional[str] = None
    if client_parsed:
        if client_parsed.version is not None:
            version_str = client_parsed.version
        client_str = client_parsed.client
        os_str = client_parsed.os
    if synced is None and chain_heights:
        max_heights = await get_max_network_heights(db_path)
        if max_heights and _heights_within_threshold_of_max(chain_heights, max_heights):
            synced = True
    await update_node_enrichment(
        db_path,
        host,
        port,
        domain=address if address != host else None,
        version=version_str,
        country=country,
        city=city,
        continent=continent,
        country_code=country_code,
        isp=isp,
        org=org,
        zip=zip_val,
        lat=lat,
        lon=lon,
        has_api=has_api,
        synced=synced,
        reverse_dns=reverse_dns_name,
        hoster=hoster,
        chain_heights=chain_heights,
        client=client_str,
        os=os_str,
    )
    log_label = display_name if display_name else _display_node(host, address if address != host else None)
    logger.info("Enriched %s:%s version=%s client=%s os=%s country=%s has_api=%s synced=%s", log_label, port, version_str, client_str, os_str, country, has_api, synced)


async def ensure_node_in_db(db_path: str, address: str, port: int, from_neighbors: bool = True) -> None:
    """Ensure node exists in DB with status offline and last_explored=0 so it gets explored. Revive if dead. Resolve hostname to IP for canonical key."""
    host = address
    if not host.replace(".", "").replace(":", "").isdigit():
        ip = await _resolve_host(host, port)
        if ip:
            host = ip
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


async def probe_node_ports(
    config: Config,
    db_path: str,
    address: str,
    node_port: int,
    timeout: float = 4.0,
) -> None:
    """Probe broker and REST ports for a node, update node_ports table and nodes.broker_port/rest_port/status columns. Uses node's discovery port for broker (same host:port as P2P)."""
    host = address
    if not host.replace(".", "").replace(":", "").isdigit():
        ip = await _resolve_host(host, node_port)
        if ip:
            host = ip
    now = time.time()

    # Broker port: use the node's own port (discovery port = broker port on same host)
    broker_port = node_port
    try:
        broker_ok = await get_client_version_tcp(host, broker_port, config.network_id, timeout=timeout)
        broker_reachable = broker_ok is not None
    except Exception:
        broker_reachable = False
    status_broker = PORT_STATUS_REACHABLE if broker_reachable else PORT_STATUS_CLOSED
    await upsert_node_port(db_path, host, node_port, broker_port, PORT_TYPE_BROKER, status_broker, now)
    await update_node_port_statuses(
        db_path, host, node_port,
        broker_port=broker_port,
        broker_status=status_broker,
    )

    # REST ports: reachable if GET /infos/version returns 200 (via _try_port)
    rest_ports = [config.rest_port_probe]
    if 80 not in rest_ports:
        rest_ports.append(80)
    if 443 not in rest_ports:
        rest_ports.append(443)
    first_rest_port: Optional[int] = None
    any_rest_reachable = False
    for p in rest_ports:
        try:
            has_api, _ = await _try_port(host, p, timeout)
            reachable = has_api
        except Exception:
            reachable = False
        any_rest_reachable = any_rest_reachable or reachable
        if reachable and first_rest_port is None:
            first_rest_port = p
        st = PORT_STATUS_REACHABLE if reachable else PORT_STATUS_CLOSED
        await upsert_node_port(db_path, host, node_port, p, PORT_TYPE_REST, st, now)
    rest_url: Optional[str] = None
    if first_rest_port is not None:
        if first_rest_port == 443:
            rest_url = f"https://{host}/infos/node"
        elif first_rest_port == 80:
            rest_url = f"http://{host}/infos/node"
        else:
            rest_url = f"http://{host}:{first_rest_port}/infos/node"
    else:
        rest_url = ""
    await update_node_port_statuses(
        db_path, host, node_port,
        rest_port=first_rest_port,
        rest_status=PORT_STATUS_REACHABLE if any_rest_reachable else PORT_STATUS_CLOSED,
        rest_url=rest_url if rest_url is not None else "",
    )


async def process_and_store_node(
    config: Config,
    db_path: str,
    info: BrokerInfo,
) -> None:
    """Resolve domain to IP if needed, geolocate, check API, upsert (background enrichment)."""
    async with _ENRICH_SEMAPHORE:
        await _process_and_store_node_impl(config, db_path, info)


async def _process_and_store_node_impl(
    config: Config,
    db_path: str,
    info: BrokerInfo,
) -> None:
    host = info.address
    port = info.port
    if not host.replace(".", "").replace(":", "").isdigit():
        ip = await _resolve_host(host, port)
        if ip:
            host = ip
    existing = await get_node_geo_dns(db_path, host)
    if existing:
        country, city, continent, country_code, isp, org, zip_val, lat, lon, reverse_dns_name, hoster = existing
        has_geo = country is not None or city is not None or isp is not None
        has_dns = reverse_dns_name is not None or hoster is not None
    else:
        has_geo, has_dns = False, False
        country = city = continent = country_code = isp = org = zip_val = reverse_dns_name = hoster = None
        lat = lon = None
    if not has_geo:
        country, city, continent, country_code, isp, org, zip_val, lat, lon = await geolocate(host)
    if not has_dns:
        reverse_dns_name, hoster = await reverse_dns_and_whois(host)
    has_api, version = await check_rest_api(host, config.rest_port_probe, timeout=2.0)
    client_id_raw: Optional[str] = None
    if version is None:
        try:
            version = await get_client_version_tcp(
                host, port, config.network_id, timeout=5.0
            )
            if version is not None:
                client_id_raw = version
        except Exception:
            pass
    if client_id_raw is None:
        try:
            client_id_raw = await get_client_version_tcp(
                host, port, config.network_id, timeout=5.0
            )
        except Exception:
            pass
    synced: Optional[bool] = None
    if has_api:
        try:
            self_clique = await fetch_self_clique(host, config.rest_port_probe, timeout=5.0)
            if self_clique is not None:
                synced, peer_addresses = self_clique
                if peer_addresses:
                    updated = await update_synced_for_clique_peers(db_path, peer_addresses, synced)
                    if updated:
                        logger.debug("Updated synced=%s for %s clique peer(s)", synced, updated)
            inter_peers = await fetch_inter_clique_peer_info(host, config.rest_port_probe, timeout=5.0)
            if inter_peers:
                added = 0
                for addr in inter_peers:
                    ok, _ = await _try_port(addr, 9973, timeout=2.0)
                    if ok:
                        await ensure_node_in_db(db_path, addr, 9973)
                        added += 1
                    resp = await discover_from_node(config, addr, 9973, config.network_id)
                    if resp:
                        await ensure_node_in_db(db_path, addr, 9973)
                        added += 1
                        for info in resp:
                            await ensure_node_in_db(db_path, info.address, info.port)
                            asyncio.create_task(process_and_store_node(config, db_path, info))
                if added > 0:
                    logger.debug("Added inter-clique peer(s) from REST+FindNode for next iteration")
        except Exception:
            pass
    chain_heights: Optional[List[int]] = None
    if has_api:
        try:
            groups = 4 if config.network_id == 0 else 2
            chain_heights = await fetch_chain_heights_rest(
                host, config.rest_port_probe, groups=groups, timeout=3.0
            )
        except Exception:
            pass
    if chain_heights is None:
        ref_list_p = config.reference_nodes or (
            DEFAULT_MAINNET if config.network_id == 0 else DEFAULT_TESTNET
        )
        reference_nodes_p = [config.parse_node(s) for s in ref_list_p]
        try:
            cs = await get_chain_state_tcp(
                host,
                port,
                config.network_id,
                timeout=8.0,
                broker_port=port,
                reference_nodes=reference_nodes_p,
                reference_broker_port=None,
            )
            if cs is not None:
                chain_heights = [height for _, height in cs.tips]
                if synced is None:
                    synced = cs.synced
                if client_id_raw is None and cs.client_id:
                    client_id_raw = cs.client_id
        except Exception:
            pass
    client_parsed = parse_client_id(client_id_raw) if client_id_raw else None
    version_str = version
    client_str: Optional[str] = None
    os_str: Optional[str] = None
    if client_parsed:
        if client_parsed.version is not None:
            version_str = client_parsed.version
        client_str = client_parsed.client
        os_str = client_parsed.os
    if synced is None and chain_heights:
        max_heights = await get_max_network_heights(db_path)
        if max_heights and _heights_within_threshold_of_max(chain_heights, max_heights):
            synced = True
    clique_id_hex = info.clique_id.hex() if info.clique_id else None
    await upsert_node(
        db_path,
        host,
        port,
        domain=info.address if info.address != host else None,
        clique_id=clique_id_hex,
        version=version_str,
        country=country,
        city=city,
        continent=continent,
        country_code=country_code,
        isp=isp,
        org=org,
        zip=zip_val,
        lat=lat,
        lon=lon,
        has_api=has_api,
        synced=synced,
        status="offline",
        reverse_dns=reverse_dns_name,
        hoster=hoster,
        chain_heights=chain_heights,
        client=client_str,
        os=os_str,
    )
    logger.info("Node %s:%s version=%s client=%s os=%s country=%s has_api=%s synced=%s", _display_node(host, info.address if info.address != host else None), port, version_str, client_str, os_str, country, has_api, synced)


# Delay between each FindNode in a cycle (seconds) to avoid flooding
FINDNODE_DELAY_SEC = 2.0
# Max time per node in discovery loop (skip node if exceeded)
PER_NODE_TIMEOUT_SEC = 120.0
# DNS resolution timeout
DNS_RESOLVE_TIMEOUT_SEC = 5.0
# Limit concurrent enrich_node tasks to avoid HTTP/TCP thundering herd
_ENRICH_SEMAPHORE = asyncio.Semaphore(5)


async def _resolve_host(host: str, port: int) -> Optional[str]:
    """Resolve hostname to IP via getaddrinfo with timeout. Returns IP or None on failure."""
    try:
        resolved = await asyncio.wait_for(
            asyncio.get_event_loop().getaddrinfo(
                host, port, type=socket.SOCK_DGRAM
            ),
            timeout=DNS_RESOLVE_TIMEOUT_SEC,
        )
        if resolved:
            return resolved[0][4][0]
    except (asyncio.TimeoutError, Exception):
        pass
    return None


async def _process_one_node(
    config: Config,
    db_path: str,
    proxy: Optional["UDPProxy"],
    explore_host: str,
    host: str,
    port: int,
    domain: Optional[str],
    network_id: int,
    display: str,
    seen: Set[Tuple[str, int]],
    to_ask: List[Tuple[str, int]],
) -> None:
    """Single-node discovery: Ping -> Pong, FindNode, probe ports, update status, enqueue enrich."""
    timeout_udp = float(config.udp_timeout_seconds)
    loop = asyncio.get_event_loop()
    pong = await loop.run_in_executor(
        None,
        lambda: ping_reply_pong(explore_host, port, network_id, timeout_udp),
    )
    now = time.time()
    discovery_status = PORT_STATUS_REACHABLE if pong else PORT_STATUS_CLOSED
    await upsert_node_port(
        db_path, explore_host, port, port, PORT_TYPE_DISCOVERY, discovery_status, now
    )
    await update_node_port_statuses(
        db_path, explore_host, port, discovery_status=discovery_status
    )
    if pong:
        logger.info("Ping -> Pong from %s:%s", display, port)
    else:
        logger.info("Ping -> no Pong from %s:%s (discovery closed)", display, port)

    resp = None
    if pong:
        if proxy is not None:
            resp = await _discover_node_via_proxy(
                proxy, explore_host, port, network_id, timeout_udp
            )
        if resp is None:
            resp = await _discover_node(
                explore_host, port, network_id, timeout_udp
            )

    if resp:
        if os.environ.get("SNIFFER_DEBUG"):
            logger.debug("Raw reply %d bytes, magic(4)=%s", len(resp), resp[:4].hex() if len(resp) >= 4 else "?")
        neighbors = extract_neighbors_from_message(resp, network_id)
        if neighbors:
            logger.info("FindNode reply from %s:%s: %d neighbors", display, port, len(neighbors))
            for info in neighbors:
                key = (info.address, info.port)
                if key not in seen:
                    seen.add(key)
                    to_ask.append((info.address, info.port))
                    await ensure_node_in_db(db_path, info.address, info.port, from_neighbors=True)
                    asyncio.create_task(
                        process_and_store_node(config, db_path, info)
                    )

    try:
        await probe_node_ports(config, db_path, explore_host, port, timeout=4.0)
    except Exception as e:
        logger.debug("probe_node_ports %s:%s: %s", display, port, e)

    await update_node_status_from_port_statuses(db_path, explore_host, port)
    asyncio.create_task(enrich_node(config, db_path, explore_host, port, display_name=display))


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
        try:
            from sniffer.bigquery import push_nodes_to_bigquery
            asyncio.create_task(push_nodes_to_bigquery(config, db_path))
        except ImportError:
            pass
        for idx, (host, port, domain) in enumerate(candidates):
            if idx > 0 and idx % 50 == 0:
                logger.info("Discovery progress: %d / %d nodes", idx, len(candidates))
            explore_host = host
            if not host.replace(".", "").replace(":", "").isdigit():
                ip = await _resolve_host(host, port)
                if ip:
                    explore_host = ip

            display = _display_node(explore_host, domain)
            try:
                await asyncio.wait_for(
                    _process_one_node(
                        config,
                        db_path,
                        proxy,
                        explore_host,
                        host,
                        port,
                        domain,
                        network_id,
                        display,
                        seen,
                        to_ask,
                    ),
                    timeout=PER_NODE_TIMEOUT_SEC,
                )
            except asyncio.TimeoutError:
                logger.warning("Node %s:%s timed out after %s s, skipping", display, port, PER_NODE_TIMEOUT_SEC)
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
