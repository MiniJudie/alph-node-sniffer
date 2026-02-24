"""Geolocation via free ip-api.com (no key)."""
import asyncio
import logging
from typing import Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

# Rate limit: 45 req/min for free
SEM = asyncio.Semaphore(10)


async def geolocate(ip: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (country, city, continent) for IP. Skip private/localhost."""
    if ip in ("127.0.0.1", "::1", "0.0.0.0") or ip.startswith("192.168.") or ip.startswith("10."):
        return (None, None, None)
    async with SEM:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(
                    f"http://ip-api.com/json/{ip}?fields=country,city,continentCode"
                )
                if r.status_code != 200:
                    return (None, None, None)
                data = r.json()
                country = data.get("country")
                city = data.get("city")
                continent = data.get("continentCode")
                return (country, city, continent)
        except Exception as e:
            logger.debug("geolocate %s: %s", ip, e)
            return (None, None, None)
