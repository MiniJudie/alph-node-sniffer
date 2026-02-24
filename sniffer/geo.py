"""Geolocation via free ip-api.com (no key)."""
import asyncio
import logging
import threading
import time
from collections import deque
from typing import Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

# ip-api.com free tier: 45 requests per minute
RATE_LIMIT_PER_MINUTE = 45
RATE_WINDOW_SEC = 60.0

# (country, city, continent, country_code, isp, org)
GeoResult = Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]

_rate_timestamps: deque = deque()
_rate_lock = threading.Lock()
_sem = asyncio.Semaphore(10)


def _release_rate_slot() -> None:
    with _rate_lock:
        _rate_timestamps.append(time.monotonic())


async def _acquire_rate_slot() -> None:
    """Wait until we're under the 45/min limit."""
    while True:
        with _rate_lock:
            now = time.monotonic()
            while _rate_timestamps and _rate_timestamps[0] < now - RATE_WINDOW_SEC:
                _rate_timestamps.popleft()
            if len(_rate_timestamps) < RATE_LIMIT_PER_MINUTE:
                return
            wait_until = _rate_timestamps[0] + RATE_WINDOW_SEC - now
        if wait_until > 0:
            await asyncio.sleep(wait_until)


async def geolocate(ip: str) -> GeoResult:
    """Return (country, city, continent, country_code, isp, org) for IP. Skip private/localhost."""
    if ip in ("127.0.0.1", "::1", "0.0.0.0") or ip.startswith("192.168.") or ip.startswith("10."):
        return (None, None, None, None, None, None)
    await _acquire_rate_slot()
    async with _sem:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(
                    f"http://ip-api.com/json/{ip}?fields=country,city,continentCode,countryCode,isp,org"
                )
                if r.status_code == 429:
                    logger.warning("ip-api rate limit (429); consider lowering discovery rate")
                    return (None, None, None, None, None, None)
                if r.status_code != 200:
                    return (None, None, None, None, None, None)
                data = r.json()
                country = data.get("country")
                city = data.get("city")
                continent = data.get("continentCode")
                country_code = data.get("countryCode")
                isp = data.get("isp")
                org = data.get("org")
                return (country, city, continent, country_code, isp, org)
        except Exception as e:
            logger.debug("geolocate %s: %s", ip, e)
            return (None, None, None, None, None, None)
        finally:
            _release_rate_slot()
