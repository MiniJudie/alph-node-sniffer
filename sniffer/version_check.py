"""Check if node exposes Alephium REST API and get version; fallback to TCP broker Hello for clientId."""
import asyncio
import logging
from typing import Optional, Tuple

import httpx

from sniffer.protocol import fetch_client_version_tcp

logger = logging.getLogger(__name__)


async def _try_port(host: str, port: int, timeout: float) -> Tuple[bool, Optional[str]]:
    """Try GET /infos/version on one (host, port). Use https for 443, http otherwise."""
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
                r = await client.get(f"{base}/infos/self-clique-synced")
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, bool):
                        return data
                r2 = await client.get(f"{base}/infos/self-clique")
                if r2.status_code == 200:
                    data = r2.json()
                    if isinstance(data, dict) and "synced" in data:
                        return bool(data["synced"])
        except Exception as e:
            logger.debug("check_synced %s:%s %s", host, p, e)
    return None
