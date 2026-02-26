"""Reverse DNS (PTR) and WHOIS/RDAP lookups for IP enrichment."""
import asyncio
import logging
import socket
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Timeouts for blocking lookups (run in executor)
REVERSE_DNS_TIMEOUT_SEC = 3.0
WHOIS_TIMEOUT_SEC = 5.0


def _reverse_dns_sync(ip: str) -> Optional[str]:
    """Blocking: PTR lookup for IP. Returns hostname or None."""
    if not ip or ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return None
    if ip.startswith("192.168.") or ip.startswith("10."):
        return None
    try:
        socket.setdefaulttimeout(REVERSE_DNS_TIMEOUT_SEC)
        name, _, _ = socket.gethostbyaddr(ip)
        return name if name else None
    except (socket.herror, socket.gaierror, socket.timeout, OSError) as e:
        logger.debug("reverse_dns %s: %s", ip, e)
        return None


def _whois_hoster_sync(ip: str) -> Optional[str]:
    """Blocking: RDAP lookup for IP. Returns org/hoster name or None."""
    if not ip or ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return None
    if ip.startswith("192.168.") or ip.startswith("10."):
        return None
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        obj.timeout = WHOIS_TIMEOUT_SEC
        # depth=1 fetches entity details so we get org names from objects (e.g. "Google LLC")
        res = obj.lookup_rdap(
            depth=1,
            get_asn_description=True,
            rate_limit_timeout=5,
        )
        if not res:
            return None
        # 1) Top-level ASN description (e.g. "GOOGLE, US")
        org = res.get("asn_description")
        if org and isinstance(org, str):
            s = org.strip()
            if s:
                return s
        # 2) Network name (e.g. "GOOGLE")
        network = res.get("network")
        if isinstance(network, dict):
            name = network.get("name")
            if name and isinstance(name, str):
                s = name.strip()
                if s:
                    return s
        # 3) First registrant/org from entities
        entities = res.get("entities") or []
        objects = res.get("objects") or {}
        for handle in entities:
            obj_entry = objects.get(handle) if isinstance(handle, str) else None
            if not isinstance(obj_entry, dict):
                continue
            roles = obj_entry.get("roles") or []
            if "registrant" not in roles and "technical" not in roles:
                continue
            contact = obj_entry.get("contact")
            if isinstance(contact, dict):
                name = contact.get("name")
                if name and isinstance(name, str):
                    s = name.strip()
                    if s:
                        return s
        # 4) Any entity with a name
        for handle in entities:
            obj_entry = objects.get(handle) if isinstance(handle, str) else None
            if isinstance(obj_entry, dict):
                contact = obj_entry.get("contact")
                if isinstance(contact, dict):
                    name = contact.get("name")
                    if name and isinstance(name, str):
                        s = name.strip()
                        if s:
                            return s
        return None
    except Exception as e:
        logger.debug("whois_hoster %s: %s", ip, e)
        return None


async def reverse_dns(ip: str) -> Optional[str]:
    """Async: PTR lookup for IP. Returns hostname or None. Never raises."""
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _reverse_dns_sync, ip)
    except Exception as e:
        logger.debug("reverse_dns %s: %s", ip, e)
        return None


async def whois_hoster(ip: str) -> Optional[str]:
    """Async: RDAP lookup for IP. Returns org/hoster name or None. Never raises."""
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _whois_hoster_sync, ip)
    except Exception as e:
        logger.debug("whois_hoster %s: %s", ip, e)
        return None


async def reverse_dns_and_whois(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """Run reverse DNS and WHOIS in parallel. If one fails, the other still returns. Returns (reverse_dns_name, hoster)."""
    rev_result, hoster_result = await asyncio.gather(
        reverse_dns(ip), whois_hoster(ip), return_exceptions=True
    )
    rev = rev_result if not isinstance(rev_result, BaseException) else None
    hoster = hoster_result if not isinstance(hoster_result, BaseException) else None
    return (rev, hoster)
