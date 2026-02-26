"""
Linear daemon: one cycle = push BigQuery, then 4 sequential phases over all nodes in DB.

Each cycle:
  0. Push current nodes to Google BigQuery (if configured).
  1. Load all hosts from DB into memory.
  2. Phase 1: For each host — resolve IP, geolocate, whois, reverse DNS (rate limited).
  3. Phase 2: For each host — probe REST API (which port).
  4. Phase 3: For each host — discovery ping, broker TCP, client/synced (UDP P2P or REST).
  5. Phase 4: For each host — find neighbors (UDP FindNode or REST); add new hosts to DB only (no explore).
"""
import asyncio
import logging
import os
import socket
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from sniffer.config import Config
from sniffer.db import (
    ChainHeightsMap,
    _heights_within_threshold_of_max,
    get_max_network_heights,
    get_node_geo_dns,
    get_all_nodes_list,
    get_node_by_address,
    init_db,
    increment_misbehavior_count,
    update_node_enrichment,
    update_node_port_statuses,
    update_node_status_from_port_statuses,
    upsert_node_port,
    upsert_node,
    update_synced_for_clique_peers,
    revive_if_dead,
    PORT_STATUS_REACHABLE,
    PORT_STATUS_CLOSED,
    PORT_TYPE_DISCOVERY,
    PORT_TYPE_BROKER,
    PORT_TYPE_REST,
)
from sniffer.geo import geolocate
from sniffer.lookup import reverse_dns_and_whois
from sniffer.protocol import (
    build_find_node_message,
    findnode_reply_neighbors,
    ping_reply_pong,
    extract_neighbors_from_message,
)
from sniffer.version_check import (
    _try_port,
    check_rest_api,
    fetch_chain_heights_rest,
    fetch_discovered_neighbors,
    fetch_inter_clique_peer_info,
    fetch_misbehaviors,
    fetch_self_clique,
    get_chain_state_tcp,
    get_client_version_tcp,
    parse_client_id,
    try_rest_with_301_and_cert,
)

logger = logging.getLogger(__name__)

# Bootstrap (same as daemon) for chain_state reference nodes
DEFAULT_MAINNET = [
    "bootstrap0.alephium.org:9973",
    "bootstrap1.alephium.org:9973",
    "bootstrap2.alephium.org:9973",
]
DEFAULT_TESTNET = [
    "bootstrap0.testnet.alephium.org:9973",
    "bootstrap1.testnet.alephium.org:9973",
]


# Concurrency and rate limiting
PHASE1_SEMAPHORE = 5   # geo/whois/DNS in parallel
PHASE2_SEMAPHORE = 10  # REST probes
PHASE3_SEMAPHORE = 5   # UDP/TCP per node
PHASE4_SEMAPHORE = 5   # FindNode / REST neighbors
DELAY_BETWEEN_NODES_SEC = 0.3  # avoid burst on external APIs

# Broker ports to try when probing a node (9973 standard, 19140 common alternative)
BROKER_PORTS_TO_TRY = [9973, 19140]


async def _resolve_host(host: str, port: int) -> Optional[str]:
    """Resolve hostname to IP. Returns IP or None."""
    try:
        resolved = await asyncio.wait_for(
            asyncio.get_event_loop().getaddrinfo(
                host, port, type=socket.SOCK_DGRAM
            ),
            timeout=5.0,
        )
        if resolved:
            return resolved[0][4][0]
    except (asyncio.TimeoutError, Exception):
        pass
    return None


def _icmp_ping_sync(host: str, timeout_sec: float) -> bool:
    """Sync: run system ping (ICMP), return True if host replies. Uses -c 1 -W (Linux/macOS) or -n 1 -w (Windows)."""
    if not host or host in ("127.0.0.1", "::1", "0.0.0.0"):
        return False
    if host.startswith("192.168.") or host.startswith("10."):
        pass  # still try
    try:
        to_int = max(1, min(10, int(timeout_sec)))
        # Linux/macOS
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(to_int), host],
            timeout=timeout_sec + 1,
            capture_output=True,
        )
        if r.returncode == 0:
            return True
        # Windows: -n 1 -w <ms>
        if os.name == "nt":
            r = subprocess.run(
                ["ping", "-n", "1", "-w", str(to_int * 1000), host],
                timeout=timeout_sec + 1,
                capture_output=True,
            )
            return r.returncode == 0
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


async def _icmp_ping(host: str, timeout_sec: float = 2.0) -> bool:
    """Async: ICMP ping host, return True if reply received."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: _icmp_ping_sync(host, timeout_sec),
    )


def _display_node(host: str, domain: Optional[str]) -> str:
    if domain and not (domain.replace(".", "").replace(":", "").isdigit()):
        return domain
    return host


def _run_api_server(config: Config) -> None:
    """Blocking: run HTTP API (for use in a thread)."""
    import uvicorn
    from sniffer.api import create_app
    app = create_app(config, config.database_path)
    log_level = "warning" if os.environ.get("SNIFFER_NETWORK_DEBUG") else "info"
    uvicorn.run(app, host=config.http_host, port=config.http_port, log_level=log_level)


async def _phase1_geo_dns(
    config: Config,
    db_path: str,
    nodes: List[Dict[str, Any]],
    sem: asyncio.Semaphore,
) -> None:
    """Resolve IP, geolocate, whois, reverse DNS. Rate limiting via geo module + semaphore."""
    for i, node in enumerate(nodes):
        async with sem:
            address = node["address"]
            port = int(node["port"])
            host = address
            if not host.replace(".", "").replace(":", "").isdigit():
                ip = await _resolve_host(host, port)
                if ip:
                    host = ip
            display = _display_node(host, node.get("domain"))
            logger.info("Phase 1 [%d/%d]: testing %s (%s:%s)", i + 1, len(nodes), display, host, port)
            existing = await get_node_geo_dns(db_path, host)
            if existing:
                country, city, continent, country_code, isp, org, zip_val, lat, lon, reverse_dns_name, hoster = existing
                has_geo = lat is not None and lon is not None
                has_dns = reverse_dns_name is not None or hoster is not None
            else:
                has_geo, has_dns = False, False
                country = city = continent = country_code = isp = org = zip_val = reverse_dns_name = hoster = None
                lat = lon = None
            if not has_geo:
                country, city, continent, country_code, isp, org, zip_val, lat, lon = await geolocate(host)
            if not has_dns:
                reverse_dns_name, hoster = await reverse_dns_and_whois(host)
            icmp_reachable = await _icmp_ping(host, timeout_sec=2.0)
            icmp_status = PORT_STATUS_REACHABLE if icmp_reachable else PORT_STATUS_CLOSED
            await update_node_port_statuses(db_path, host, port, icmp_status=icmp_status)
            await update_node_status_from_port_statuses(db_path, host, port)
            await update_node_enrichment(
                db_path, host, port,
                domain=address if address != host else None,
                country=country, city=city, continent=continent,
                country_code=country_code, isp=isp, org=org, zip=zip_val,
                lat=lat, lon=lon,
                reverse_dns=reverse_dns_name, hoster=hoster,
            )
            if (i + 1) % 50 == 0:
                logger.info("Phase 1 (geo/DNS): %d/%d nodes", i + 1, len(nodes))
            await asyncio.sleep(DELAY_BETWEEN_NODES_SEC)


async def _phase2_rest_probe(
    config: Config,
    db_path: str,
    nodes: List[Dict[str, Any]],
    sem: asyncio.Semaphore,
) -> None:
    """Probe REST ports (rest_port_probe, 80, 443); handle 301 redirect to new host; try http and https; store cert domains if HTTPS. Set rest_port, rest_status, rest_url, has_api, cert_domains."""
    timeout = 3.0
    for i, node in enumerate(nodes):
        async with sem:
            address = node["address"]
            port = int(node["port"])
            host = address
            if not host.replace(".", "").replace(":", "").isdigit():
                ip = await _resolve_host(host, port)
                if ip:
                    host = ip
            display = _display_node(host, node.get("domain"))
            logger.info("Phase 2 [%d/%d]: testing %s (%s:%s)", i + 1, len(nodes), display, host, port)
            has_api, version, rest_url, cert_domains = await try_rest_with_301_and_cert(
                host, config.rest_port_probe, timeout=timeout
            )
            first_rest_port: Optional[int] = None
            if rest_url:
                try:
                    parsed = urlparse(rest_url)
                    first_rest_port = parsed.port
                    if first_rest_port is None:
                        first_rest_port = 443 if parsed.scheme == "https" else 80
                except Exception:
                    first_rest_port = 443 if rest_url.startswith("https") else config.rest_port_probe
            await update_node_port_statuses(
                db_path, host, port,
                rest_port=first_rest_port,
                rest_status=PORT_STATUS_REACHABLE if has_api else PORT_STATUS_CLOSED,
                rest_url=rest_url or "",
            )
            await update_node_status_from_port_statuses(db_path, host, port)
            await update_node_enrichment(
                db_path, host, port,
                has_api=has_api,
                cert_domains=cert_domains if cert_domains else None,
            )
            if (i + 1) % 100 == 0:
                logger.info("Phase 2 (REST): %d/%d nodes", i + 1, len(nodes))
            await asyncio.sleep(DELAY_BETWEEN_NODES_SEC * 0.5)


async def _phase3_client_synced(
    config: Config,
    db_path: str,
    nodes: List[Dict[str, Any]],
    sem: asyncio.Semaphore,
) -> None:
    """Discovery ping, broker TCP, client/synced/chain_heights (UDP P2P or REST). Then update status from port statuses."""
    network_id = config.network_id
    timeout_udp = float(config.udp_timeout_seconds)
    loop = asyncio.get_event_loop()
    ref_list = config.reference_nodes or (
        DEFAULT_MAINNET if network_id == 0 else DEFAULT_TESTNET
    )
    reference_nodes = [config.parse_node(s) for s in ref_list]

    for i, node in enumerate(nodes):
        async with sem:
            address = node["address"]
            port = int(node["port"])
            host = address
            if not host.replace(".", "").replace(":", "").isdigit():
                ip = await _resolve_host(host, port)
                if ip:
                    host = ip
            display = _display_node(host, node.get("domain"))
            logger.info("Phase 3 [%d/%d]: testing %s (%s:%s)", i + 1, len(nodes), display, host, port)

            # Ports to try for discovery and broker: current first, then 9973, then 19140
            ports_to_try = list(dict.fromkeys([port] + BROKER_PORTS_TO_TRY))

            # Discovery: try FindNode first then Ping on each port until one responds
            discovery_reachable = False
            for p in ports_to_try:
                try:
                    discovery_reachable = await loop.run_in_executor(
                        None,
                        lambda h=host, pt=p: findnode_reply_neighbors(h, pt, network_id, timeout_udp),
                    )
                except Exception:
                    pass
                if discovery_reachable:
                    break
                try:
                    discovery_reachable = await loop.run_in_executor(
                        None,
                        lambda h=host, pt=p: ping_reply_pong(h, pt, network_id, timeout_udp),
                    )
                except Exception:
                    pass
                if discovery_reachable:
                    break
            now = time.time()
            discovery_status = PORT_STATUS_REACHABLE if discovery_reachable else PORT_STATUS_CLOSED
            await upsert_node_port(db_path, host, port, port, PORT_TYPE_DISCOVERY, discovery_status, now)
            await update_node_port_statuses(db_path, host, port, discovery_status=discovery_status)

            # Broker: try 9973 then 19140 (and current port first); store working broker_port
            ports_to_try = list(dict.fromkeys([port] + BROKER_PORTS_TO_TRY))
            working_broker_port: Optional[int] = None
            broker_ok = None
            for p in ports_to_try:
                try:
                    broker_ok = await get_client_version_tcp(host, p, network_id, timeout=4.0)
                    if broker_ok is not None:
                        working_broker_port = p
                        break
                except Exception:
                    pass
            broker_reachable = working_broker_port is not None
            status_broker = PORT_STATUS_REACHABLE if broker_reachable else PORT_STATUS_CLOSED
            await upsert_node_port(db_path, host, port, port, PORT_TYPE_BROKER, status_broker, now)
            if broker_reachable and working_broker_port is not None:
                await update_node_port_statuses(db_path, host, port, broker_port=working_broker_port, broker_status=status_broker)
            else:
                await update_node_port_statuses(db_path, host, port, broker_status=status_broker)
            canonical_port = working_broker_port if working_broker_port is not None else port

            client_id_raw: Optional[str] = broker_ok if broker_reachable else None
            synced: Optional[bool] = None
            chain_heights: Optional[ChainHeightsMap] = None
            rest_port = node.get("rest_port") or config.rest_port_probe
            groups = 4 if network_id == 0 else 2

            if node.get("has_api") and rest_port:
                try:
                    self_clique = await fetch_self_clique(host, rest_port, timeout=5.0)
                    if self_clique is not None:
                        synced, peer_addresses = self_clique
                        if peer_addresses:
                            await update_synced_for_clique_peers(db_path, peer_addresses, synced)
                    chain_heights = await fetch_chain_heights_rest(host, rest_port, groups=groups, timeout=3.0)
                except Exception:
                    pass
            if chain_heights is None or client_id_raw is None or synced is None:
                try:
                    cs = await get_chain_state_tcp(
                        host, canonical_port, network_id, timeout=8.0,
                        broker_port=canonical_port, reference_nodes=reference_nodes, reference_broker_port=None,
                    )
                    if cs is not None:
                        if chain_heights is None and cs.tips:
                            chain_heights = {(i // groups, i % groups): height for i, (_, height) in enumerate(cs.tips)}
                        if synced is None:
                            synced = cs.synced
                        if client_id_raw is None and cs.client_id:
                            client_id_raw = cs.client_id
                except Exception:
                    pass
            if synced is None and chain_heights:
                max_heights = await get_max_network_heights(db_path)
                if max_heights and _heights_within_threshold_of_max(chain_heights, max_heights):
                    synced = True

            client_parsed = parse_client_id(client_id_raw) if client_id_raw else None
            version_str = node.get("version")
            client_str: Optional[str] = None
            os_str: Optional[str] = None
            if client_parsed:
                if client_parsed.version is not None:
                    version_str = client_parsed.version
                client_str = client_parsed.client
                os_str = client_parsed.os

            await update_node_enrichment(
                db_path, host, canonical_port,
                version=version_str,
                synced=synced,
                chain_heights=chain_heights,
                client=client_str,
                os=os_str,
            )
            await update_node_status_from_port_statuses(db_path, host, canonical_port)
            if (i + 1) % 50 == 0:
                logger.info("Phase 3 (client/synced): %d/%d nodes", i + 1, len(nodes))
            await asyncio.sleep(DELAY_BETWEEN_NODES_SEC)


async def _send_udp(host: str, port: int, data: bytes, timeout: float) -> Optional[bytes]:
    """Send UDP and wait for response. Returns response bytes or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(data, (host, port))
        raw, _ = sock.recvfrom(4096)
        sock.close()
        return raw
    except (socket.timeout, OSError):
        return None


def _random_clique_id() -> bytes:
    return os.urandom(33)


async def _phase4_neighbors(
    config: Config,
    db_path: str,
    nodes: List[Dict[str, Any]],
    sem: asyncio.Semaphore,
) -> None:
    """Find neighbors via UDP FindNode or REST; add new (addr, port) to DB only (no explore)."""
    network_id = config.network_id
    timeout_udp = float(config.udp_timeout_seconds)
    added: Set[Tuple[str, int]] = set()

    async def add_node_if_new(addr: str, p: int) -> None:
        if not addr or p <= 0:
            return
        host = addr
        if not host.replace(".", "").replace(":", "").isdigit():
            ip = await _resolve_host(host, p)
            if ip:
                host = ip
        key = (host, p)
        if key in added:
            return
        added.add(key)
        await revive_if_dead(db_path, host, p)
        if addr != host:
            await revive_if_dead(db_path, addr, p)
        await upsert_node(
            db_path, host, p,
            domain=addr if addr != host else None,
            status="offline",
            last_explored=0.0,
            preserve_status=True,
        )

    for i, node in enumerate(nodes):
        async with sem:
            address = node["address"]
            port = int(node["port"])
            host = address
            if not host.replace(".", "").replace(":", "").isdigit():
                ip = await _resolve_host(host, port)
                if ip:
                    host = ip
            display = _display_node(host, node.get("domain"))
            logger.info("Phase 4 [%d/%d]: testing %s (%s:%s)", i + 1, len(nodes), display, host, port)

            # UDP FindNode
            udp_neighbors: List[Tuple[str, int]] = []
            try:
                msg = build_find_node_message(network_id, _random_clique_id())
                resp = await _send_udp(host, port, msg, timeout_udp)
            except Exception:
                resp = None
            if resp:
                try:
                    neighbors = extract_neighbors_from_message(resp, network_id)
                    for info in neighbors:
                        udp_neighbors.append((info.address, info.port))
                        await add_node_if_new(info.address, info.port)
                    if udp_neighbors:
                        logger.info("Phase 4 [%d/%d] UDP FindNode from %s: %d neighbors %s", i + 1, len(nodes), display, len(udp_neighbors), [(a, p) for (a, p) in udp_neighbors[:10]])
                except Exception:
                    pass

            # REST: discovered-neighbors + inter-clique
            rest_port = node.get("rest_port") or config.rest_port_probe
            if node.get("has_api") or rest_port:
                try:
                    discovered = await fetch_discovered_neighbors(host, rest_port, timeout=3.0)
                    if discovered is not None:
                        for n in discovered:
                            await add_node_if_new(n.address, n.port)
                        if discovered:
                            logger.info("Phase 4 [%d/%d] REST discovered-neighbors from %s: %d neighbors %s", i + 1, len(nodes), display, len(discovered), [(n.address, n.port) for n in discovered[:10]])
                except Exception:
                    pass
                try:
                    inter_peers = await fetch_inter_clique_peer_info(host, rest_port, timeout=3.0)
                    if inter_peers:
                        for addr_str in inter_peers:
                            if ":" in addr_str:
                                part = addr_str.rsplit(":", 1)
                                h, p = part[0].strip(), int(part[1])
                            else:
                                h, p = addr_str.strip(), 9973
                            await add_node_if_new(h, p)
                        logger.info("Phase 4 [%d/%d] REST inter-clique from %s: %d peers %s", i + 1, len(nodes), display, len(inter_peers), inter_peers[:10])
                except Exception:
                    pass
                try:
                    misbehaviors = await fetch_misbehaviors(host, rest_port, timeout=3.0)
                    if misbehaviors:
                        for peer_str in misbehaviors:
                            peer_host = await _resolve_host(peer_str, 9973) or peer_str
                            existing = await get_node_by_address(db_path, peer_host)
                            if existing is None:
                                await add_node_if_new(peer_host, 9973)
                            await increment_misbehavior_count(db_path, existing["address"] if existing else peer_host)
                        logger.info("Phase 4 [%d/%d] REST misbehaviors from %s: %d peers (added to neighbor list) %s", i + 1, len(nodes), display, len(misbehaviors), misbehaviors[:10])
                except Exception:
                    pass

            if (i + 1) % 50 == 0:
                logger.info("Phase 4 (neighbors): %d/%d nodes, %d new added", i + 1, len(nodes), len(added))
            await asyncio.sleep(DELAY_BETWEEN_NODES_SEC)

    logger.info("Phase 4 done: %d new hosts added to DB (not explored this cycle)", len(added))


async def run_linear_cycle(config: Config, db_path: str) -> None:
    """One full linear cycle: BigQuery push, load nodes, then phases 1–4."""
    # 0. Push to BigQuery first
    try:
        from sniffer.bigquery import push_nodes_to_bigquery
        await push_nodes_to_bigquery(config, db_path)
    except Exception as e:
        logger.warning("BigQuery push failed: %s", e)

    # 1. Load all hosts into memory
    nodes = await get_all_nodes_list(db_path)
    if not nodes and config.starting_nodes:
        logger.info("No nodes in DB; seeding %d starting_nodes from config", len(config.starting_nodes))
        for s in config.starting_nodes:
            if not (s and str(s).strip()):
                continue
            host, port = config.parse_node(str(s).strip())
            await upsert_node(db_path, host, port, status="offline", last_explored=0.0)
        nodes = await get_all_nodes_list(db_path)
    if not nodes:
        logger.warning("No nodes in DB; linear cycle has nothing to do")
        return
    logger.info("Linear cycle: %d nodes in memory", len(nodes))

    sem1 = asyncio.Semaphore(PHASE1_SEMAPHORE)
    sem2 = asyncio.Semaphore(PHASE2_SEMAPHORE)
    sem3 = asyncio.Semaphore(PHASE3_SEMAPHORE)
    sem4 = asyncio.Semaphore(PHASE4_SEMAPHORE)

    logger.info("Phase 1: geo + whois + reverse DNS (rate limited)")
    await _phase1_geo_dns(config, db_path, nodes, sem1)

    logger.info("Phase 2: REST API probe")
    await _phase2_rest_probe(config, db_path, nodes, sem2)

    logger.info("Phase 3: discovery ping, broker TCP, client/synced")
    await _phase3_client_synced(config, db_path, nodes, sem3)

    logger.info("Phase 4: neighbors (UDP + REST), add new hosts to DB only")
    await _phase4_neighbors(config, db_path, nodes, sem4)

    logger.info("Linear cycle done.")


async def run_linear_daemon(config: Config) -> None:
    """Run linear daemon: init DB, start REST API in a thread, then loop run_linear_cycle every scan_interval_seconds."""
    await init_db(config.database_path)
    db_path = config.database_path

    api_thread = threading.Thread(target=_run_api_server, args=(config,), daemon=True)
    api_thread.start()
    logger.info("HTTP API on http://%s:%s/docs", config.http_host, config.http_port)

    interval = max(60, config.scan_interval_seconds)
    logger.info("Linear daemon started (interval=%ds). Each cycle: BigQuery push, then 4 phases over all nodes.", interval)
    while True:
        try:
            await run_linear_cycle(config, db_path)
        except Exception as e:
            logger.exception("Linear cycle failed: %s", e)
        logger.info("Sleeping %ds until next cycle", interval)
        await asyncio.sleep(interval)


# Main entry point: "daemon" command runs the linear daemon.
run_daemon = run_linear_daemon
