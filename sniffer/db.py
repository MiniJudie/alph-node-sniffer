"""SQLite storage for discovered nodes."""
import aiosqlite
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# chain_heights: stored as {(fromGroup, toGroup): height}. JSON uses keys "fromGroup,toGroup".
ChainHeightsMap = Dict[Tuple[int, int], int]


def _chain_heights_to_json(d: Optional[ChainHeightsMap]) -> Optional[str]:
    """Serialize chain_heights dict to JSON string. Keys as 'fg,tg'."""
    if not d:
        return None
    return json.dumps({f"{k[0]},{k[1]}": v for k, v in d.items()})


def _chain_heights_from_json(s: Optional[str]) -> Optional[ChainHeightsMap]:
    """Deserialize chain_heights from JSON. Supports both {'0,0': 123} and legacy [h0,h1,...]."""
    if not s or not s.strip():
        return None
    try:
        raw = json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(raw, dict):
        out: ChainHeightsMap = {}
        for k, v in raw.items():
            if not isinstance(k, str) or not isinstance(v, (int, float)):
                continue
            parts = k.split(",")
            if len(parts) != 2:
                continue
            try:
                fg, tg = int(parts[0].strip()), int(parts[1].strip())
                out[(fg, tg)] = int(v)
            except ValueError:
                continue
        return out if out else None
    if isinstance(raw, list):
        # Legacy: list of heights in order (0,0), (0,1), ..., (g-1,g-1)
        groups = 4 if len(raw) >= 16 else 2
        out = {}
        for i, h in enumerate(raw):
            if not isinstance(h, (int, float)):
                continue
            if i >= groups * groups:
                break
            fg, tg = i // groups, i % groups
            out[(fg, tg)] = int(h)
        return out if out else None
    return None


def chain_heights_for_json(m: Optional[ChainHeightsMap]) -> Optional[Dict[str, int]]:
    """Convert chain_heights to a dict with string keys for JSON/API/BigQuery. Returns e.g. {'0,0': 123, '0,1': 456}."""
    if not m:
        return None
    return {f"{k[0]},{k[1]}": v for k, v in m.items()}


# Status: online, offline, dead (no response 30m -> offline, 48h -> dead)
STATUS_ONLINE = "online"
STATUS_OFFLINE = "offline"
STATUS_DEAD = "dead"
OFFLINE_THRESHOLD_SEC = 60 * 60   # 30 minutes without response
DEAD_THRESHOLD_SEC = 48 * 3600    # 48 hours without response

# Port status (reachable / closed)
PORT_STATUS_REACHABLE = "reachable"
PORT_STATUS_CLOSED = "closed"
PORT_TYPE_DISCOVERY = "discovery"
PORT_TYPE_BROKER = "broker"
PORT_TYPE_REST = "rest"


async def init_db(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                domain TEXT,
                clique_id TEXT,
                version TEXT,
                country TEXT,
                city TEXT,
                continent TEXT,
                country_code TEXT,
                isp TEXT,
                org TEXT,
                zip TEXT,
                lat REAL,
                lon REAL,
                has_api INTEGER NOT NULL DEFAULT 0,
                synced INTEGER,
                status TEXT NOT NULL DEFAULT 'offline',
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                last_explored REAL,
                reverse_dns TEXT,
                hoster TEXT,
                chain_heights TEXT,
                client TEXT,
                os TEXT,
                broker_port INTEGER,
                rest_port INTEGER,
                discovery_status TEXT,
                broker_status TEXT,
                rest_status TEXT,
                rest_url TEXT,
                cert_domains TEXT,
                icmp_status TEXT,
                misbehavior_count INTEGER NOT NULL DEFAULT 0,
                UNIQUE(address)
            )
        """)
        await db.commit()

        # Migration: add status/last_explored to existing tables that have old schema (before creating indexes)
        async with db.execute("PRAGMA table_info(nodes)") as cur:
            cols = [row[1] for row in await cur.fetchall()]
        if "status" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN status TEXT NOT NULL DEFAULT 'offline'")
            if "online" in cols:
                await db.execute(
                    "UPDATE nodes SET status = CASE WHEN online = 1 THEN 'online' ELSE 'offline' END"
                )
            await db.commit()
        if "last_explored" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN last_explored REAL")
            await db.execute("UPDATE nodes SET last_explored = last_seen WHERE last_explored IS NULL")
            await db.commit()
        if "clique_id" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN clique_id TEXT")
            await db.commit()
        if "synced" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN synced INTEGER")
            await db.commit()
        if "chain_heights" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN chain_heights TEXT")
            await db.commit()
        if "client" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN client TEXT")
            await db.commit()
        if "os" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN os TEXT")
            await db.commit()

        if "reverse_dns" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN reverse_dns TEXT")
            await db.commit()
        if "hoster" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN hoster TEXT")
            await db.commit()

        if "country_code" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN country_code TEXT")
            await db.commit()
        if "isp" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN isp TEXT")
            await db.commit()
        if "org" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN org TEXT")
            await db.commit()
        if "zip" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN zip TEXT")
            await db.commit()
        if "lat" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN lat REAL")
            await db.commit()
        if "lon" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN lon REAL")
            await db.commit()

        # Port discovery: per-port status (reachable/closed) for discovery, broker, rest
        if "broker_port" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN broker_port INTEGER")
            await db.commit()
        if "rest_port" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN rest_port INTEGER")
            await db.commit()
        if "discovery_status" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN discovery_status TEXT")
            await db.commit()
        if "broker_status" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN broker_status TEXT")
            await db.commit()
        if "rest_status" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN rest_status TEXT")
            await db.commit()
        if "rest_url" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN rest_url TEXT")
            await db.commit()

        if "cert_domains" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN cert_domains TEXT")
            await db.commit()

        if "icmp_status" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN icmp_status TEXT")
            await db.commit()

        if "misbehavior_count" not in cols:
            await db.execute("ALTER TABLE nodes ADD COLUMN misbehavior_count INTEGER NOT NULL DEFAULT 0")
            await db.commit()

        # Migration: one row per IP (address) instead of per (address, port)
        async with db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nodes'"
        ) as cur:
            has_nodes = await cur.fetchone() is not None
        if has_nodes:
            async with db.execute(
                "SELECT address FROM nodes GROUP BY address HAVING COUNT(*) > 1 LIMIT 1"
            ) as cur:
                has_dups = await cur.fetchone() is not None
            if has_dups:
                await db.execute("""
                    CREATE TABLE nodes_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        address TEXT NOT NULL UNIQUE,
                        port INTEGER NOT NULL,
                        domain TEXT,
                        clique_id TEXT,
                        version TEXT,
                        country TEXT,
                        city TEXT,
                        continent TEXT,
                        country_code TEXT,
                        isp TEXT,
                        org TEXT,
                        zip TEXT,
                        lat REAL,
                        lon REAL,
                        has_api INTEGER NOT NULL DEFAULT 0,
                        synced INTEGER,
                        status TEXT NOT NULL DEFAULT 'offline',
                        first_seen REAL NOT NULL,
                        last_seen REAL NOT NULL,
                        last_explored REAL,
                        reverse_dns TEXT,
                        hoster TEXT,
                        chain_heights TEXT,
                        client TEXT,
                        os TEXT,
                        broker_port INTEGER,
                        rest_port INTEGER,
                        discovery_status TEXT,
                        broker_status TEXT,
                        rest_status TEXT,
                        rest_url TEXT,
                        cert_domains TEXT,
                        icmp_status TEXT,
                        misbehavior_count INTEGER NOT NULL DEFAULT 0
                    )
                """)
                await db.execute("""
                    INSERT INTO nodes_new
                    SELECT n.id, n.address, n.port, n.domain, n.clique_id, n.version, n.country, n.city,
                           n.continent, n.country_code, n.isp, n.org, n.zip, n.lat, n.lon, n.has_api, n.synced,
                           n.status, n.first_seen, n.last_seen, n.last_explored, n.reverse_dns, n.hoster,
                           n.chain_heights, n.client, n.os, n.broker_port, n.rest_port, n.discovery_status,
                           n.broker_status, n.rest_status, n.rest_url, n.cert_domains, n.icmp_status, n.misbehavior_count
                    FROM nodes n
                    WHERE NOT EXISTS (
                        SELECT 1 FROM nodes n2
                        WHERE n2.address = n.address AND n2.last_seen > n.last_seen
                    )
                """)
                await db.execute("DROP TABLE nodes")
                await db.execute("ALTER TABLE nodes_new RENAME TO nodes")
                await db.commit()

        # Indexes (after migration so columns exist)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_last_explored ON nodes(last_explored)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_country ON nodes(country)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_version ON nodes(version)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_has_api ON nodes(has_api)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_synced ON nodes(synced)")
        await db.commit()

        # Table: one row per (node address, node discovery port, probed port) with type and status
        await db.execute("""
            CREATE TABLE IF NOT EXISTS node_ports (
                address TEXT NOT NULL,
                node_port INTEGER NOT NULL,
                port INTEGER NOT NULL,
                port_type TEXT NOT NULL,
                status TEXT NOT NULL,
                last_checked REAL,
                PRIMARY KEY (address, node_port, port)
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_node_ports_node ON node_ports(address, node_port)")
        await db.commit()


async def upsert_node(
    db_path: str,
    address: str,
    port: int,
    *,
    domain: Optional[str] = None,
    clique_id: Optional[str] = None,
    version: Optional[str] = None,
    country: Optional[str] = None,
    city: Optional[str] = None,
    continent: Optional[str] = None,
    country_code: Optional[str] = None,
    isp: Optional[str] = None,
    org: Optional[str] = None,
    zip: Optional[str] = None,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    has_api: bool = False,
    synced: Optional[bool] = None,
    status: Optional[str] = None,
    first_seen: Optional[float] = None,
    last_seen: Optional[float] = None,
    last_explored: Optional[float] = None,
    reverse_dns: Optional[str] = None,
    hoster: Optional[str] = None,
    revive_dead: bool = False,
    chain_heights: Optional[ChainHeightsMap] = None,
    client: Optional[str] = None,
    os: Optional[str] = None,
    preserve_status: bool = False,
) -> None:
    """Insert or update node. If revive_dead=True and node exists as dead, set status to offline. If preserve_status=True, on conflict do not overwrite status (used by enrichment to keep port-derived online/offline). clique_id is hex string (66 chars). chain_heights: dict (fromGroup,toGroup) -> height from broker ChainState or REST. When updating on conflict, existing non-null values are never overwritten with null (COALESCE keeps existing)."""
    now = time.time()
    st = status or STATUS_OFFLINE
    fse = first_seen if first_seen is not None else now
    lse = last_seen if last_seen is not None else 0.0   # 0 = never got a response yet
    lex = last_explored if last_explored is not None else 0.0  # 0 = never explored, explore first
    async with aiosqlite.connect(db_path) as db:
        if revive_dead:
            await db.execute(
                "UPDATE nodes SET status = ? WHERE address = ? AND status = ?",
                (STATUS_OFFLINE, address, STATUS_DEAD),
            )
            await db.commit()
        await db.execute(
            """
            INSERT INTO nodes (address, port, domain, clique_id, version, country, city, continent, has_api, synced, status, first_seen, last_seen, last_explored, reverse_dns, hoster, country_code, isp, org, zip, lat, lon, chain_heights, client, os)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
                port = excluded.port,
                domain = COALESCE(excluded.domain, domain),
                clique_id = COALESCE(excluded.clique_id, clique_id),
                version = COALESCE(excluded.version, version),
                country = COALESCE(excluded.country, country),
                city = COALESCE(excluded.city, city),
                continent = COALESCE(excluded.continent, continent),
                has_api = excluded.has_api OR has_api,
                synced = COALESCE(excluded.synced, synced),
                status = CASE WHEN ? THEN nodes.status ELSE excluded.status END,
                last_seen = CASE WHEN excluded.last_seen > 0 THEN excluded.last_seen ELSE nodes.last_seen END,
                first_seen = nodes.first_seen,
                last_explored = nodes.last_explored,
                reverse_dns = COALESCE(excluded.reverse_dns, reverse_dns),
                hoster = COALESCE(excluded.hoster, hoster),
                country_code = COALESCE(excluded.country_code, country_code),
                isp = COALESCE(excluded.isp, isp),
                org = COALESCE(excluded.org, org),
                zip = COALESCE(excluded.zip, zip),
                lat = COALESCE(excluded.lat, lat),
                lon = COALESCE(excluded.lon, lon),
                chain_heights = COALESCE(excluded.chain_heights, chain_heights),
                client = COALESCE(excluded.client, client),
                os = COALESCE(excluded.os, os)
            """,
            (
                address,
                port,
                domain or address,
                clique_id,
                version,
                country,
                city,
                continent,
                1 if has_api else 0,
                (1 if synced is True else (0 if synced is False else None)),
                st,
                fse,
                lse,
                lex,
                reverse_dns,
                hoster,
                country_code,
                isp,
                org,
                zip,
                lat,
                lon,
                _chain_heights_to_json(chain_heights),
                client,
                os,
                1 if preserve_status else 0,
            ),
        )
        await db.commit()


async def update_node_enrichment(
    db_path: str,
    address: str,
    port: int,
    *,
    domain: Optional[str] = None,
    clique_id: Optional[str] = None,
    version: Optional[str] = None,
    country: Optional[str] = None,
    city: Optional[str] = None,
    continent: Optional[str] = None,
    has_api: Optional[bool] = None,
    synced: Optional[bool] = None,
    reverse_dns: Optional[str] = None,
    hoster: Optional[str] = None,
    country_code: Optional[str] = None,
    isp: Optional[str] = None,
    org: Optional[str] = None,
    zip: Optional[str] = None,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    chain_heights: Optional[ChainHeightsMap] = None,
    client: Optional[str] = None,
    os: Optional[str] = None,
    cert_domains: Optional[List[str]] = None,
) -> None:
    """Update only enrichment fields (version, geo, has_api, clique_id, synced, reverse_dns, hoster, country_code, isp, org, client, os, port, cert_domains); does not change status or timestamps."""
    async with aiosqlite.connect(db_path) as db:
        updates = []
        params: List[Any] = []
        if port is not None:
            updates.append("port = ?")
            params.append(port)
        if domain is not None:
            updates.append("domain = ?")
            params.append(domain)
        if clique_id is not None:
            updates.append("clique_id = ?")
            params.append(clique_id)
        if version is not None:
            updates.append("version = ?")
            params.append(version)
        if country is not None:
            updates.append("country = ?")
            params.append(country)
        if city is not None:
            updates.append("city = ?")
            params.append(city)
        if continent is not None:
            updates.append("continent = ?")
            params.append(continent)
        if has_api is not None:
            updates.append("has_api = ?")
            params.append(1 if has_api else 0)
        if synced is not None:
            updates.append("synced = ?")
            params.append(1 if synced else 0)
        if reverse_dns is not None:
            updates.append("reverse_dns = ?")
            params.append(reverse_dns)
        if hoster is not None:
            updates.append("hoster = ?")
            params.append(hoster)
        if country_code is not None:
            updates.append("country_code = ?")
            params.append(country_code)
        if isp is not None:
            updates.append("isp = ?")
            params.append(isp)
        if org is not None:
            updates.append("org = ?")
            params.append(org)
        if zip is not None:
            updates.append("zip = ?")
            params.append(zip)
        if lat is not None:
            updates.append("lat = ?")
            params.append(lat)
        if lon is not None:
            updates.append("lon = ?")
            params.append(lon)
        if chain_heights is not None:
            updates.append("chain_heights = ?")
            params.append(_chain_heights_to_json(chain_heights))
        if client is not None:
            updates.append("client = ?")
            params.append(client)
        if os is not None:
            updates.append("os = ?")
            params.append(os)
        if cert_domains is not None:
            updates.append("cert_domains = ?")
            params.append(json.dumps(cert_domains) if cert_domains else None)
        if not updates:
            return
        params.append(address)
        await db.execute(
            f"UPDATE nodes SET {', '.join(updates)} WHERE address = ?",
            params,
        )
        await db.commit()


async def update_synced_for_clique_peers(
    db_path: str,
    peer_addresses: List[str],
    synced: bool,
) -> int:
    """
    Set synced for all nodes whose address or domain equals one of peer_addresses
    (e.g. from /infos/self-clique nodes). Returns number of rows updated.
    """
    if not peer_addresses:
        return 0
    synced_int = 1 if synced else 0
    total = 0
    async with aiosqlite.connect(db_path) as db:
        for peer in peer_addresses:
            cursor = await db.execute(
                "UPDATE nodes SET synced = ? WHERE address = ? OR domain = ?",
                (synced_int, peer, peer),
            )
            total += cursor.rowcount
        await db.commit()
    return total


async def mark_exploration_success(db_path: str, address: str, port: int) -> None:
    """Called when we got a response from the node. Updates port to the one we probed."""
    now = time.time()
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "UPDATE nodes SET status = ?, last_seen = ?, last_explored = ?, port = ? WHERE address = ?",
            (STATUS_ONLINE, now, now, port, address),
        )
        await db.commit()


async def mark_exploration_failed(db_path: str, address: str, port: int) -> None:
    """Called when we got no response. Sets last_explored=now; offline if last_seen > 30m ago, dead if > 48h."""
    now = time.time()
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT last_seen, status FROM nodes WHERE address = ?",
            (address,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return
        last_seen = row["last_seen"] or 0
        age = now - last_seen
        if age >= DEAD_THRESHOLD_SEC:
            new_status = STATUS_DEAD
        elif age >= OFFLINE_THRESHOLD_SEC:
            new_status = STATUS_OFFLINE
        else:
            new_status = row["status"]
        await db.execute(
            "UPDATE nodes SET status = ?, last_explored = ?, port = ? WHERE address = ?",
            (new_status, now, port, address),
        )
        await db.commit()


async def upsert_node_port(
    db_path: str,
    address: str,
    node_port: int,
    port: int,
    port_type: str,
    status: str,
    last_checked: Optional[float] = None,
) -> None:
    """Insert or replace one row in node_ports. status: reachable | closed."""
    now = time.time()
    ts = last_checked if last_checked is not None else now
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            """
            INSERT INTO node_ports (address, node_port, port, port_type, status, last_checked)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(address, node_port, port) DO UPDATE SET
                port_type = excluded.port_type,
                status = excluded.status,
                last_checked = excluded.last_checked
            """,
            (address, node_port, port, port_type, status, ts),
        )
        await db.commit()


async def update_node_port_statuses(
    db_path: str,
    address: str,
    port: int,
    *,
    discovery_status: Optional[str] = None,
    broker_port: Optional[int] = None,
    broker_status: Optional[str] = None,
    rest_port: Optional[int] = None,
    rest_status: Optional[str] = None,
    rest_url: Optional[str] = None,
    icmp_status: Optional[str] = None,
) -> None:
    """Update nodes table port columns (and icmp_status). When broker_port is set, also set nodes.port = broker_port (main port in DB is broker port)."""
    updates = []
    params: List[Any] = []
    if discovery_status is not None:
        updates.append("discovery_status = ?")
        params.append(discovery_status)
    if broker_port is not None:
        updates.append("broker_port = ?")
        params.append(broker_port)
        updates.append("port = ?")
        params.append(broker_port)
    if broker_status is not None:
        updates.append("broker_status = ?")
        params.append(broker_status)
    if rest_port is not None:
        updates.append("rest_port = ?")
        params.append(rest_port)
    if rest_status is not None:
        updates.append("rest_status = ?")
        params.append(rest_status)
    if rest_url is not None:
        updates.append("rest_url = ?")
        params.append(rest_url)
    if icmp_status is not None:
        updates.append("icmp_status = ?")
        params.append(icmp_status)
    if not updates:
        return
    params.append(address)
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            f"UPDATE nodes SET {', '.join(updates)} WHERE address = ?",
            params,
        )
        await db.commit()


async def increment_misbehavior_count(db_path: str, address: str) -> int:
    """Increment misbehavior_count for the node with this address (e.g. after seeing it in /infos/misbehaviors). Returns new count or 0 if not found."""
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "UPDATE nodes SET misbehavior_count = COALESCE(misbehavior_count, 0) + 1 WHERE address = ?",
            (address,),
        )
        await db.commit()
        async with db.execute("SELECT misbehavior_count FROM nodes WHERE address = ?", (address,)) as cur:
            row = await cur.fetchone()
    return int(row[0]) if row else 0


async def update_node_status_from_port_statuses(db_path: str, address: str, port: int) -> None:
    """
    Set node status from discovery/broker/rest/icmp statuses: online if any is reachable,
    else offline/dead (based on last_seen age). Updates last_seen when any port is reachable,
    and last_explored always.
    """
    now = time.time()
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT discovery_status, broker_status, rest_status, icmp_status, last_seen, status FROM nodes WHERE address = ?",
            (address,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return
        d = (row["discovery_status"] or "").strip().lower() == "reachable"
        b = (row["broker_status"] or "").strip().lower() == "reachable"
        r = (row["rest_status"] or "").strip().lower() == "reachable"
        icmp = (row["icmp_status"] or "").strip().lower() == "reachable"
        any_reachable = d or b or r or icmp
        if any_reachable:
            await db.execute(
                "UPDATE nodes SET status = ?, last_seen = ?, last_explored = ?, port = ? WHERE address = ?",
                (STATUS_ONLINE, now, now, port, address),
            )
        else:
            last_seen = row["last_seen"] or 0
            age = now - last_seen
            if age >= DEAD_THRESHOLD_SEC:
                new_status = STATUS_DEAD
            elif age >= OFFLINE_THRESHOLD_SEC:
                new_status = STATUS_OFFLINE
            else:
                new_status = row["status"] or STATUS_OFFLINE
            await db.execute(
                "UPDATE nodes SET status = ?, last_explored = ?, port = ? WHERE address = ?",
                (new_status, now, port, address),
            )
        await db.commit()


async def get_node_ports(db_path: str, address: str, node_port: int) -> List[dict]:
    """Return list of { port, port_type, status, last_checked } for the given node."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT port, port_type, status, last_checked FROM node_ports WHERE address = ? AND node_port = ? ORDER BY port_type, port",
            (address, node_port),
        ) as cur:
            rows = await cur.fetchall()
    return [
        {"port": r["port"], "port_type": r["port_type"], "status": r["status"], "last_checked": r["last_checked"]}
        for r in rows
    ]


async def get_nodes_to_explore(db_path: str, limit: int = 1) -> List[tuple]:
    """Return (address, port, domain) of nodes to explore next: status in (online, offline), order by last_explored ASC (longest ago first)."""
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            """
            SELECT address, port, domain FROM nodes
            WHERE status IN (?, ?)
            ORDER BY COALESCE(last_explored, 0) ASC
            LIMIT ?
            """,
            (STATUS_ONLINE, STATUS_OFFLINE, limit),
        ) as cur:
            rows = await cur.fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


async def get_nodes_without_version(db_path: str, limit: int = 50) -> List[tuple]:
    """Return (address, port, domain) of nodes that have no version yet (for retry enrichment). status in (online, offline)."""
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            """
            SELECT address, port, domain FROM nodes
            WHERE (version IS NULL OR version = '') AND status IN (?, ?)
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (STATUS_ONLINE, STATUS_OFFLINE, limit),
        ) as cur:
            rows = await cur.fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


async def revive_if_dead(db_path: str, address: str, port: int) -> bool:
    """If node is dead, set status=offline so it gets explored again. Returns True if was dead and revived."""
    async with aiosqlite.connect(db_path) as db:
        cur = await db.execute(
            "UPDATE nodes SET status = ?, port = ? WHERE address = ? AND status = ?",
            (STATUS_OFFLINE, port, address, STATUS_DEAD),
        )
        await db.commit()
        return cur.rowcount > 0


# Threshold (in blocks) below network max at which a node is still considered synced
SYNCED_HEIGHT_THRESHOLD = 50


async def get_max_network_heights(db_path: str) -> Optional[ChainHeightsMap]:
    """
    Compute max chain height per (fromGroup, toGroup) across all nodes with chain_heights.
    Returns dict {(fromGroup, toGroup): max_height} or None if no nodes have chain_heights.
    """
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT chain_heights FROM nodes WHERE chain_heights IS NOT NULL AND chain_heights != ''"
        ) as cur:
            rows = await cur.fetchall()
    if not rows:
        return None
    max_heights: ChainHeightsMap = {}
    for row in rows:
        raw = row[0]
        heights = _chain_heights_from_json(raw)
        if not heights:
            continue
        for k, h in heights.items():
            if k not in max_heights or h > max_heights[k]:
                max_heights[k] = h
    return max_heights if max_heights else None


def _heights_within_threshold_of_max(
    chain_heights: ChainHeightsMap,
    max_heights: ChainHeightsMap,
    threshold: int = SYNCED_HEIGHT_THRESHOLD,
) -> bool:
    """Return True if each node height (per chain key) is within threshold blocks of the network max."""
    if not chain_heights or not max_heights:
        return False
    for k, h in chain_heights.items():
        max_h = max_heights.get(k)
        if max_h is None:
            continue
        if h < max_h - threshold:
            return False
    return True


async def get_node_chain_state(db_path: str, address: str, port: int) -> Optional[dict]:
    """Return chainstate fields for one node (address, port, synced, chain_heights, version, etc.) or None if not found."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT address, port, domain, version, synced, chain_heights, client, os FROM nodes WHERE address = ?",
            (address,),
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    return {
        "address": row["address"],
        "port": row["port"],
        "domain": row["domain"],
        "version": row["version"],
        "synced": None if row["synced"] is None else bool(row["synced"]),
        "chain_heights": _chain_heights_from_json(row["chain_heights"]),
        "client": row["client"],
        "os": row["os"],
    }


async def get_node_geo_dns(
    db_path: str, address: str
) -> Optional[Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[float], Optional[float], Optional[str], Optional[str]]]:
    """Get geo and DNS fields for node. Returns (country, city, continent, country_code, isp, org, zip, lat, lon, reverse_dns, hoster) or None if not found."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT country, city, continent, country_code, isp, org, zip, lat, lon, reverse_dns, hoster FROM nodes WHERE address = ?",
            (address,),
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    return (
        row["country"],
        row["city"],
        row["continent"],
        row["country_code"],
        row["isp"],
        row["org"],
        row["zip"],
        row["lat"],
        row["lon"],
        row["reverse_dns"],
        row["hoster"],
    )


async def get_stats(db_path: str) -> dict[str, Any]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT status, COUNT(*) AS cnt FROM nodes GROUP BY status"
        ) as cur:
            rows = await cur.fetchall()
        total = 0
        online = 0
        offline = 0
        dead = 0
        for row in rows:
            total += row["cnt"]
            if row["status"] == STATUS_ONLINE:
                online = row["cnt"]
            elif row["status"] == STATUS_OFFLINE:
                offline = row["cnt"]
            elif row["status"] == STATUS_DEAD:
                dead = row["cnt"]
        async with db.execute(
            "SELECT MAX(COALESCE(last_explored, 0)), MAX(COALESCE(last_seen, 0)) FROM nodes"
        ) as cur:
            row = await cur.fetchone()
        last_ts = max((row[0] or 0.0), (row[1] or 0.0)) if row else 0.0
        last_update = datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat() if last_ts else None
        return {
            "total_discovered": total,
            "online": online,
            "offline": offline,
            "dead": dead,
            "last_update": last_update,
        }


async def get_node_by_address(db_path: str, address: str) -> Optional[dict[str, Any]]:
    """Return full node info by address (IP) or None if not found."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT address, port, domain, clique_id, version, country, city, continent, has_api, synced, status, first_seen, last_seen, last_explored, reverse_dns, hoster, country_code, isp, org, zip, lat, lon, chain_heights, client, os, broker_port, rest_port, discovery_status, broker_status, rest_status, rest_url, cert_domains, icmp_status, misbehavior_count FROM nodes WHERE address = ?",
            (address,),
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    return {
        "address": row["address"],
        "port": row["port"],
        "domain": row["domain"],
        "clique_id": row["clique_id"],
        "version": row["version"],
        "country": row["country"],
        "city": row["city"],
        "continent": row["continent"],
        "has_api": bool(row["has_api"]),
        "synced": None if row["synced"] is None else bool(row["synced"]),
        "status": row["status"],
        "date_first_seen": row["first_seen"],
        "date_last_seen": row["last_seen"],
        "date_last_explored": row["last_explored"],
        "reverse_dns": row["reverse_dns"],
        "hoster": row["hoster"],
        "country_code": row["country_code"],
        "isp": row["isp"],
        "org": row["org"],
        "zip": row["zip"],
        "lat": row["lat"],
        "lon": row["lon"],
        "chain_heights": _chain_heights_from_json(row["chain_heights"]),
        "client": row["client"],
        "os": row["os"],
        "broker_port": row["broker_port"],
        "rest_port": row["rest_port"],
        "discovery_status": row["discovery_status"],
        "broker_status": row["broker_status"],
        "rest_status": row["rest_status"],
        "rest_url": row["rest_url"],
        "cert_domains": json.loads(row["cert_domains"]) if row["cert_domains"] else None,
        "icmp_status": row["icmp_status"],
        "misbehavior_count": int(row["misbehavior_count"]) if row["misbehavior_count"] is not None else 0,
    }


async def get_versions(db_path: str) -> List[dict[str, Any]]:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT version, COUNT(*) AS count
            FROM nodes WHERE version IS NOT NULL AND version != ''
            GROUP BY version ORDER BY count DESC
            """
        ) as cur:
            rows = await cur.fetchall()
        return [{"version": r["version"], "count": r["count"]} for r in rows]


async def get_nodes(
    db_path: str,
    *,
    continent: Optional[str] = None,
    country: Optional[str] = None,
    has_api: Optional[bool] = None,
    version: Optional[str] = None,
    status: Optional[str] = None,
    synced: Optional[bool] = None,
) -> AsyncIterator[dict[str, Any]]:
    query = "SELECT address, port, domain, clique_id, version, country, city, continent, has_api, synced, status, first_seen, last_seen, last_explored, reverse_dns, hoster, country_code, isp, org, zip, lat, lon, chain_heights, client, os, broker_port, rest_port, discovery_status, broker_status, rest_status, rest_url, cert_domains, icmp_status, misbehavior_count FROM nodes WHERE 1=1"
    params: List[Any] = []
    if continent is not None:
        query += " AND continent = ?"
        params.append(continent)
    if country is not None:
        query += " AND country = ?"
        params.append(country)
    if has_api is not None:
        query += " AND has_api = ?"
        params.append(1 if has_api else 0)
    if version is not None:
        query += " AND version = ?"
        params.append(version)
    if status is not None:
        query += " AND status = ?"
        params.append(status)
    if synced is not None:
        query += " AND synced = ?"
        params.append(1 if synced else 0)
    query += " ORDER BY last_seen DESC"
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, params) as cur:
            async for row in cur:
                yield {
                    "address": row["address"],
                    "port": row["port"],
                    "domain": row["domain"],
                    "clique_id": row["clique_id"],
                    "version": row["version"],
                    "country": row["country"],
                    "city": row["city"],
                    "continent": row["continent"],
                    "has_api": bool(row["has_api"]),
                    "synced": None if row["synced"] is None else bool(row["synced"]),
                    "status": row["status"],
                    "date_first_seen": row["first_seen"],
                    "date_last_seen": row["last_seen"],
                    "date_last_explored": row["last_explored"],
                    "reverse_dns": row["reverse_dns"],
                    "hoster": row["hoster"],
                    "country_code": row["country_code"],
                    "isp": row["isp"],
                    "org": row["org"],
                    "zip": row["zip"],
                    "lat": row["lat"],
                    "lon": row["lon"],
                    "chain_heights": _chain_heights_from_json(row["chain_heights"]),
                    "client": row["client"],
                    "os": row["os"],
                    "broker_port": row["broker_port"],
                    "rest_port": row["rest_port"],
                    "discovery_status": row["discovery_status"],
                    "broker_status": row["broker_status"],
                    "rest_status": row["rest_status"],
                    "rest_url": row["rest_url"],
                    "cert_domains": json.loads(row["cert_domains"]) if row["cert_domains"] else None,
                    "icmp_status": row["icmp_status"],
                    "misbehavior_count": int(row["misbehavior_count"]) if row["misbehavior_count"] is not None else 0,
                }


async def get_all_nodes_list(
    db_path: str,
    *,
    continent: Optional[str] = None,
    country: Optional[str] = None,
    has_api: Optional[bool] = None,
    version: Optional[str] = None,
    status: Optional[str] = None,
    synced: Optional[bool] = None,
) -> List[dict[str, Any]]:
    """Return all nodes as a list (same dict shape as get_nodes). Used by linear-daemon to iterate in memory."""
    out: List[dict[str, Any]] = []
    async for node in get_nodes(
        db_path,
        continent=continent,
        country=country,
        has_api=has_api,
        version=version,
        status=status,
        synced=synced,
    ):
        out.append(node)
    return out


def _nodes_where_clause(
    continent: Optional[str] = None,
    country: Optional[str] = None,
    has_api: Optional[bool] = None,
    version: Optional[str] = None,
    status: Optional[str] = None,
    synced: Optional[bool] = None,
) -> tuple[str, List[Any]]:
    """Build WHERE clause and params for nodes list (shared by stats and paginated list)."""
    where = "1=1"
    params: List[Any] = []
    if continent is not None:
        where += " AND continent = ?"
        params.append(continent)
    if country is not None:
        where += " AND country = ?"
        params.append(country)
    if has_api is not None:
        where += " AND has_api = ?"
        params.append(1 if has_api else 0)
    if version is not None:
        where += " AND version = ?"
        params.append(version)
    if status is not None:
        where += " AND status = ?"
        params.append(status)
    if synced is not None:
        where += " AND synced = ?"
        params.append(1 if synced else 0)
    return where, params


async def get_nodes_paginated(
    db_path: str,
    *,
    continent: Optional[str] = None,
    country: Optional[str] = None,
    has_api: Optional[bool] = None,
    version: Optional[str] = None,
    status: Optional[str] = None,
    synced: Optional[bool] = None,
    page: int = 1,
    limit: int = 50,
) -> dict[str, Any]:
    """Return { stats: { total, online, offline, dead, last_update }, nodes: [...] } with paging. Stats apply to filtered set."""
    where, params = _nodes_where_clause(
        continent=continent,
        country=country,
        has_api=has_api,
        version=version,
        status=status,
        synced=synced,
    )
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        # Stats: total and breakdown by status (on filtered set)
        stats_query = f"""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS online,
                   SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS offline,
                   SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) AS dead
            FROM nodes WHERE {where}
        """
        stats_params = [STATUS_ONLINE, STATUS_OFFLINE, STATUS_DEAD] + params
        async with db.execute(stats_query, stats_params) as cur:
            row = await cur.fetchone()
        total = row[0] or 0
        online = row[1] or 0
        offline = row[2] or 0
        dead = row[3] or 0
        # last_update: max of last_explored/last_seen (global, not filtered)
        async with db.execute(
            "SELECT MAX(COALESCE(last_explored, 0)), MAX(COALESCE(last_seen, 0)) FROM nodes"
        ) as cur:
            r = await cur.fetchone()
        last_ts = max((r[0] or 0.0), (r[1] or 0.0)) if r else 0.0
        last_update = datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat() if last_ts else None
        # Paginated nodes
        offset = max(0, (page - 1) * limit)
        limit_val = max(1, min(limit, 1000))
        list_query = f"""
            SELECT address, port, domain, clique_id, version, country, city, continent, has_api, synced, status, first_seen, last_seen, last_explored, reverse_dns, hoster, country_code, isp, org, zip, lat, lon, chain_heights, client, os, broker_port, rest_port, discovery_status, broker_status, rest_status, rest_url, cert_domains, icmp_status, misbehavior_count
            FROM nodes WHERE {where}
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
        """
        list_params = params + [limit_val, offset]
        async with db.execute(list_query, list_params) as cur:
            rows = await cur.fetchall()
        nodes = []
        for row in rows:
            nodes.append({
                "address": row["address"],
                "port": row["port"],
                "domain": row["domain"],
                "clique_id": row["clique_id"],
                "version": row["version"],
                "country": row["country"],
                "city": row["city"],
                "continent": row["continent"],
                "has_api": bool(row["has_api"]),
                "synced": None if row["synced"] is None else bool(row["synced"]),
                "status": row["status"],
                "date_first_seen": row["first_seen"],
                "date_last_seen": row["last_seen"],
                "date_last_explored": row["last_explored"],
                "reverse_dns": row["reverse_dns"],
                "hoster": row["hoster"],
                "country_code": row["country_code"],
                "isp": row["isp"],
                "org": row["org"],
                "zip": row["zip"],
                "lat": row["lat"],
                "lon": row["lon"],
                "chain_heights": _chain_heights_from_json(row["chain_heights"]),
                "client": row["client"],
                "os": row["os"],
                "broker_port": row["broker_port"],
                "rest_port": row["rest_port"],
                "discovery_status": row["discovery_status"],
                "broker_status": row["broker_status"],
                "rest_status": row["rest_status"],
                "rest_url": row["rest_url"],
                "cert_domains": json.loads(row["cert_domains"]) if row["cert_domains"] else None,
                "icmp_status": row["icmp_status"],
                "misbehavior_count": int(row["misbehavior_count"]) if row["misbehavior_count"] is not None else 0,
            })
    return {
        "stats": {
            "total": total,
            "online": int(online),
            "offline": int(offline),
            "dead": int(dead),
            "last_update": last_update,
        },
        "nodes": nodes,
    }
