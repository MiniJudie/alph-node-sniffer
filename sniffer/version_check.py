"""Check if node exposes Alephium REST API and get version; fallback to TCP broker Hello for clientId."""
import asyncio
import logging
import ssl
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx

from sniffer.protocol import fetch_client_version_tcp, fetch_chain_state_tcp

logger = logging.getLogger(__name__)

# Ports to try for REST (linear daemon: after 301, retry redirect host on these)
REST_PROBE_PORTS = [12973, 80, 443]

# When REST API is reachable, store Swagger doc deep link; otherwise /infos/version is used only for probing
REST_URL_PATH_REACHABLE = "/docs/#/Infos/getInfosVersion"


def _get_ssl_cert_domains_sync(host: str, port: int, timeout: float = 5.0) -> List[str]:
    """Sync: connect to host:port with TLS, return list of DNS names from cert (SAN + CN)."""
    domains: List[str] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return []
                san = cert.get("subjectAltName") or []
                for name_type, name_value in san:
                    if name_type == "DNS" and isinstance(name_value, str) and name_value.strip():
                        v = name_value.strip()
                        if v not in domains:
                            domains.append(v)
                subject = cert.get("subject") or []
                for attr in subject:
                    if isinstance(attr, (list, tuple)) and len(attr) >= 1:
                        name, value = attr[0] if isinstance(attr[0], (list, tuple)) else (None, None)
                        if name == "commonName" and isinstance(value, str) and value.strip() and value not in domains:
                            domains.append(value.strip())
                            break
    except Exception as e:
        logger.debug("get_ssl_cert_domains %s:%s %s", host, port, e)
    return domains


async def get_ssl_cert_domains(host: str, port: int, timeout: float = 5.0) -> List[str]:
    """Async: get TLS cert DNS names for host:port (run sync helper in executor)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: _get_ssl_cert_domains_sync(host, port, timeout),
    )


@dataclass
class ClientIdParsed:
    """Parsed broker clientId: client name, version, operating system."""
    client: Optional[str]   # e.g. "scala-alephium"
    version: Optional[str]  # e.g. "v3.1.1"
    os: Optional[str]       # e.g. "Linux"


def parse_client_id(client_id: Optional[str]) -> ClientIdParsed:
    """
    Parse broker clientId string into client, version, and OS.
    Format: "client/version/os" e.g. "scala-alephium/v3.1.1/Linux".
    Returns ClientIdParsed(client, version, os); missing parts are None.
    """
    if not client_id or not isinstance(client_id, str):
        return ClientIdParsed(None, None, None)
    s = client_id.strip()
    if not s:
        return ClientIdParsed(None, None, None)
    parts = s.split("/")
    if len(parts) >= 3:
        return ClientIdParsed(
            parts[0].strip() or None,
            parts[1].strip() or None,
            parts[2].strip() or None,
        )
    if len(parts) == 2:
        return ClientIdParsed(
            parts[0].strip() or None,
            parts[1].strip() or None,
            None,
        )
    return ClientIdParsed(None, s, None)


@dataclass
class ChainStateResult:
    """Result of broker handshake + ChainState: client_id, optional synced flag, and per-chain tips (hash, height)."""
    client_id: Optional[str]
    synced: Optional[bool]  # None = unknown from broker (use REST /infos/self-clique-synced for real synced)
    tips: List[Tuple[bytes, int]]


async def _try_port(host: str, port: int, timeout: float) -> Tuple[bool, Optional[str]]:
    """
    Try GET /infos/version on (host, port). REST is considered reachable if we get HTTP 200.
    Returns (reachable, version_string); reachable is True when /infos/version responds successfully.
    """
    scheme = "https" if port == 443 else "http"
    if port in (80, 443):
        url = f"{scheme}://{host}/infos/version"
    else:
        url = f"{scheme}://{host}:{port}/infos/version"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return (False, None)
            data = r.json()
            version = data.get("releaseVersion") or data.get("version")
            if version is not None:
                if isinstance(version, dict):
                    version = version.get("releaseVersion") or version.get("version")
                if isinstance(version, str) and version.strip():
                    return (True, version.strip())
            return (True, None)
    except Exception as e:
        logger.debug("check_rest %s:%s %s", host, port, e)
        return (False, None)


def _parse_redirect_location(location: Optional[str]) -> Optional[Tuple[str, int]]:
    """Parse Location header URL; return (host, port) or None."""
    if not location or not location.strip():
        return None
    try:
        parsed = urlparse(location.strip())
        host = (parsed.hostname or "").strip()
        if not host:
            return None
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return (host, port)
    except Exception:
        return None


def _is_alephium_version_response(response: "httpx.Response") -> bool:
    """
    Return True only if the response looks like Alephium REST /infos/version:
    status 200, JSON body, and has releaseVersion or version (string or nested).
    Rejects HTML or other non-API responses.
    """
    if response.status_code != 200:
        return False
    ct = (response.headers.get("content-type") or "").lower().split(";")[0].strip()
    if ct == "text/html" or ct.startswith("text/"):
        return False
    try:
        data = response.json()
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    ver = data.get("releaseVersion") or data.get("version")
    if isinstance(ver, dict):
        ver = ver.get("releaseVersion") or ver.get("version")
    return isinstance(ver, str) and bool(ver.strip())


async def try_rest_with_301_and_cert(
    host: str,
    rest_port_probe: int,
    timeout: float = 3.0,
) -> Tuple[bool, Optional[str], Optional[str], List[str]]:
    """
    Try REST /infos/version on host with ports rest_port_probe, 80, 443 (http and https).
    On 301/302: extract Location host and retry with that host on 12973, 80, 443 (http and https).
    On 200 over HTTPS: fetch TLS cert and extract certificate domains (SAN + CN).
    Returns (has_api, version, rest_url, cert_domains).
    rest_url is only set when GET /infos/version returns 200 with valid Alephium JSON
    (not 404, not an HTML webpage).
    """
    cert_domains: List[str] = []
    ports_to_try = [rest_port_probe, 80, 443]
    if 80 not in ports_to_try:
        ports_to_try.append(80)
    if 443 not in ports_to_try:
        ports_to_try.append(443)

    async def do_one(h: str, port: int, use_https: bool) -> Tuple[Optional[int], Optional[str], Optional[Tuple[str, int]]]:
        scheme = "https" if use_https else "http"
        if port in (80, 443):
            url = f"{scheme}://{h}/infos/version"
        else:
            url = f"{scheme}://{h}:{port}/infos/version"
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                r = await client.get(url)
                if _is_alephium_version_response(r):
                    version = None
                    try:
                        data = r.json()
                        ver = data.get("releaseVersion") or data.get("version")
                        if isinstance(ver, dict):
                            ver = ver.get("releaseVersion") or ver.get("version")
                        if isinstance(ver, str) and ver.strip():
                            version = ver.strip()
                    except Exception:
                        pass
                    return (200, version, None)
                if r.status_code in (301, 302):
                    loc = r.headers.get("Location")
                    redir = _parse_redirect_location(loc)
                    return (r.status_code, None, redir)
                return (r.status_code, None, None)
        except Exception as e:
            logger.debug("try_rest %s %s:%s %s", scheme, h, port, e)
            return (None, None, None)

    redirect_hosts: List[Tuple[str, int]] = []
    seen_redirect_hosts: Set[str] = set()

    for port in ports_to_try:
        for use_https in ([True] if port == 443 else [False] if port == 80 else [False, True]):
            status, version, redir = await do_one(host, port, use_https)
            if status == 200:
                if port == 443:
                    rest_url = f"https://{host}{REST_URL_PATH_REACHABLE}"
                    cert_domains = await get_ssl_cert_domains(host, port, timeout)
                elif port == 80:
                    rest_url = f"http://{host}{REST_URL_PATH_REACHABLE}"
                else:
                    rest_url = f"http://{host}:{port}{REST_URL_PATH_REACHABLE}"
                    if use_https:
                        rest_url = f"https://{host}:{port}{REST_URL_PATH_REACHABLE}"
                        cert_domains = await get_ssl_cert_domains(host, port, timeout)
                return (True, version, rest_url, cert_domains)
            if redir and redir[0] not in seen_redirect_hosts:
                seen_redirect_hosts.add(redir[0])
                redirect_hosts.append(redir)

    for redir_host, _ in redirect_hosts:
        for port in REST_PROBE_PORTS:
            for use_https in ([True] if port == 443 else [False] if port == 80 else [False, True]):
                status, version, _ = await do_one(redir_host, port, use_https)
                if status == 200:
                    if port == 443:
                        rest_url = f"https://{redir_host}{REST_URL_PATH_REACHABLE}"
                        cert_domains = await get_ssl_cert_domains(redir_host, port, timeout)
                    elif port == 80:
                        rest_url = f"http://{redir_host}{REST_URL_PATH_REACHABLE}"
                    else:
                        rest_url = f"http://{redir_host}:{port}{REST_URL_PATH_REACHABLE}"
                        if use_https:
                            rest_url = f"https://{redir_host}:{port}{REST_URL_PATH_REACHABLE}"
                            cert_domains = await get_ssl_cert_domains(redir_host, port, timeout)
                    return (True, version, rest_url, cert_domains)

    return (False, None, None, [])


async def check_rest_api(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Tuple[bool, Optional[str]]:
    """
    GET /infos/version on node. Tries port (e.g. 12973), then 80, then 443.
    Return (has_api, version_string).
    """
    ports_to_try = [port]
    if 80 not in ports_to_try:
        ports_to_try.append(80)
    if 443 not in ports_to_try:
        ports_to_try.append(443)
    for p in ports_to_try:
        has_api, version = await _try_port(host, p, timeout)
        if has_api or version:
            return (True, version)
    return (False, None)


async def get_client_version_tcp(
    host: str,
    broker_port: int,
    network_id: int,
    timeout: float = 5.0,
) -> Optional[str]:
    """
    Get client version from node's TCP broker (Hello message). Runs sync fetch in executor.
    Returns clientId string (e.g. 'scala-alephium/v3.1.1/Linux') or None.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: fetch_client_version_tcp(host, broker_port, network_id, timeout),
    )


async def get_chain_state_tcp(
    host: str,
    discovery_port: int,
    network_id: int,
    timeout: float = 10.0,
    broker_port: Optional[int] = None,
    reference_nodes: Optional[List[Tuple[str, int]]] = None,
    reference_broker_port: Optional[int] = None,
) -> Optional[ChainStateResult]:
    """
    Perform broker handshake and read ChainState (synced + per-shard heights).
    reference_nodes: optional list of (host, port) to get a valid Hello clientId from; uses fallback if None or all fail.
    Runs sync fetch in executor. Returns ChainStateResult or None on failure.
    """
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: fetch_chain_state_tcp(
            host,
            discovery_port,
            network_id,
            timeout,
            broker_port,
            reference_nodes,
            reference_broker_port,
        ),
    )
    if result is None:
        return None
    client_id, synced, tips = result
    return ChainStateResult(client_id=client_id, synced=synced, tips=tips)


async def fetch_chain_heights_rest(
    host: str,
    port: int,
    groups: int = 4,
    timeout: float = 3.0,
) -> Optional[Dict[Tuple[int, int], int]]:
    """
    GET /blockflow/chain-info for all chain indices (fromGroup, toGroup).
    Returns dict {(fromGroup, toGroup): currentHeight} or None on failure.
    """
    ports_to_try = [port]
    if 80 not in ports_to_try:
        ports_to_try.append(80)
    if 443 not in ports_to_try:
        ports_to_try.append(443)
    for p in ports_to_try:
        scheme = "https" if p == 443 else "http"
        base = f"{scheme}://{host}" if p in (80, 443) else f"{scheme}://{host}:{p}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                result: Dict[Tuple[int, int], int] = {}
                for from_group in range(groups):
                    for to_group in range(groups):
                        r = await client.get(
                            f"{base}/blockflow/chain-info?fromGroup={from_group}&toGroup={to_group}"
                        )
                        if r.status_code != 200:
                            return None
                        data = r.json()
                        h = data.get("currentHeight")
                        if not isinstance(h, (int, float)):
                            return None
                        result[(from_group, to_group)] = int(h)
                return result
        except Exception as e:
            logger.debug("fetch_chain_heights_rest %s:%s %s", host, p, e)
    return None


async def check_synced(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Optional[bool]:
    """
    Check if node reports itself as synced via REST.
    Tries GET /infos/self-clique-synced (returns boolean), then GET /infos/self-clique (read .synced).
    Tries port, then 80, then 443 (same order as check_rest_api).
    Returns True/False if known, None if no API or error.
    """
    result = await fetch_self_clique(host, port, timeout)
    return result[0] if result else None


async def fetch_self_clique(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Optional[Tuple[bool, List[str]]]:
    """
    GET /infos/self-clique on node. Tries port, then 80, then 443.
    Returns (synced, peer_addresses) where peer_addresses are the 'address' of each node in the clique
    (IP or hostname strings). Returns None on failure.
    """
    ports_to_try = [port]
    if 80 not in ports_to_try:
        ports_to_try.append(80)
    if 443 not in ports_to_try:
        ports_to_try.append(443)
    for p in ports_to_try:
        scheme = "https" if p == 443 else "http"
        base = f"{scheme}://{host}" if p in (80, 443) else f"{scheme}://{host}:{p}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.get(f"{base}/infos/self-clique")
                if r.status_code != 200:
                    continue
                data = r.json()
                if not isinstance(data, dict) or "synced" not in data:
                    continue
                synced = bool(data["synced"])
                addresses: List[str] = []
                nodes = data.get("nodes")
                if isinstance(nodes, list):
                    for node in nodes:
                        if isinstance(node, dict) and "address" in node:
                            addr = node["address"]
                            if isinstance(addr, str) and addr.strip():
                                addresses.append(addr.strip())
                return (synced, addresses)
        except Exception as e:
            logger.debug("fetch_self_clique %s:%s %s", host, p, e)
    return None


async def fetch_inter_clique_peer_info(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Optional[List[str]]:
    """
    GET /infos/inter-clique-peer-info on node. Tries port, then 80, then 443.
    Returns list of peer addresses (IP/hostname strings) or None on failure.
    """
    ports_to_try = [port]
    if 80 not in ports_to_try:
        ports_to_try.append(80)
    if 443 not in ports_to_try:
        ports_to_try.append(443)
    for p in ports_to_try:
        scheme = "https" if p == 443 else "http"
        base = f"{scheme}://{host}" if p in (80, 443) else f"{scheme}://{host}:{p}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.get(f"{base}/infos/inter-clique-peer-info")
                if r.status_code != 200:
                    continue
                data = r.json()
                if not isinstance(data, list):
                    continue
                addresses: List[str] = []
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    addr_obj = item.get("address")
                    if not isinstance(addr_obj, dict):
                        continue
                    addr = addr_obj.get("addr")
                    if not isinstance(addr, str) or not addr.strip():
                        continue
                    addresses.append(addr.strip())
                return addresses
        except Exception as e:
            logger.debug("fetch_inter_clique_peer_info %s:%s %s", host, p, e)
    return None


@dataclass
class DiscoveredNeighbor:
    """One neighbor from GET /infos/discovered-neighbors (BrokerInfo)."""
    address: str   # host (IP or hostname)
    port: int
    clique_id: Optional[str] = None  # hex string if present
    broker_id: Optional[int] = None
    broker_num: Optional[int] = None


async def fetch_discovered_neighbors(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Optional[List[DiscoveredNeighbor]]:
    """
    GET /infos/discovered-neighbors on node. Tries port, then 80, then 443.
    Returns list of DiscoveredNeighbor (address, port, cliqueId, brokerId, brokerNum) or None on failure.
    """
    ports_to_try = [port]
    if 80 not in ports_to_try:
        ports_to_try.append(80)
    if 443 not in ports_to_try:
        ports_to_try.append(443)
    for p in ports_to_try:
        scheme = "https" if p == 443 else "http"
        base = f"{scheme}://{host}" if p in (80, 443) else f"{scheme}://{host}:{p}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.get(f"{base}/infos/discovered-neighbors")
                if r.status_code != 200:
                    continue
                data = r.json()
                if not isinstance(data, list):
                    continue
                neighbors: List[DiscoveredNeighbor] = []
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    addr_obj = item.get("address")
                    if not isinstance(addr_obj, dict):
                        continue
                    addr = addr_obj.get("addr")
                    port_val = addr_obj.get("port")
                    if not isinstance(addr, str) or not addr.strip():
                        continue
                    if not isinstance(port_val, (int, float)):
                        continue
                    neighbor_port = int(port_val)
                    clique_id = item.get("cliqueId")
                    if isinstance(clique_id, str) and clique_id.strip():
                        clique_id = clique_id.strip()
                    else:
                        clique_id = None
                    broker_id = item.get("brokerId")
                    if isinstance(broker_id, (int, float)):
                        broker_id = int(broker_id)
                    else:
                        broker_id = None
                    broker_num = item.get("brokerNum")
                    if isinstance(broker_num, (int, float)):
                        broker_num = int(broker_num)
                    else:
                        broker_num = None
                    neighbors.append(DiscoveredNeighbor(
                        address=addr,
                        port=neighbor_port,
                        clique_id=clique_id,
                        broker_id=broker_id,
                        broker_num=broker_num,
                    ))
                return neighbors
        except Exception as e:
            logger.debug("fetch_discovered_neighbors %s:%s %s", host, p, e)
    return None


async def fetch_misbehaviors(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Optional[List[str]]:
    """
    GET /infos/misbehaviors on node. Tries port, then 80, then 443.
    Returns list of peer addresses (IP/host strings) from the misbehaviors list, or None on failure.
    """
    ports_to_try = [port]
    if 80 not in ports_to_try:
        ports_to_try.append(80)
    if 443 not in ports_to_try:
        ports_to_try.append(443)
    for p in ports_to_try:
        scheme = "https" if p == 443 else "http"
        base = f"{scheme}://{host}" if p in (80, 443) else f"{scheme}://{host}:{p}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.get(f"{base}/infos/misbehaviors")
                if r.status_code != 200:
                    continue
                data = r.json()
                if not isinstance(data, list):
                    continue
                peers: List[str] = []
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    peer = item.get("peer")
                    if isinstance(peer, str) and peer.strip():
                        peers.append(peer.strip())
                return peers
        except Exception as e:
            logger.debug("fetch_misbehaviors %s:%s %s", host, p, e)
    return None
