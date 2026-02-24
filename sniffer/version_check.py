"""Check if node exposes Alephium REST API and get version."""
import logging
from typing import Optional, Tuple

import httpx

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
            if version:
                return (True, str(version))
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
