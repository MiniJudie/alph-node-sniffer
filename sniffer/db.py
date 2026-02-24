"""SQLite storage for discovered nodes."""
import aiosqlite
import logging
import time
from pathlib import Path
from typing import Any, AsyncIterator, List, Optional

logger = logging.getLogger(__name__)

# Status: online, offline, dead (no response 30m -> offline, 48h -> dead)
STATUS_ONLINE = "online"
STATUS_OFFLINE = "offline"
STATUS_DEAD = "dead"
OFFLINE_THRESHOLD_SEC = 30 * 60   # 30 minutes without response
DEAD_THRESHOLD_SEC = 48 * 3600    # 48 hours without response


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
                has_api INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'offline',
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                last_explored REAL,
                UNIQUE(address, port)
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

        # Indexes (after migration so columns exist)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_last_explored ON nodes(last_explored)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_country ON nodes(country)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_version ON nodes(version)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_has_api ON nodes(has_api)")
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
    has_api: bool = False,
    status: Optional[str] = None,
    first_seen: Optional[float] = None,
    last_seen: Optional[float] = None,
    last_explored: Optional[float] = None,
    revive_dead: bool = False,
) -> None:
    """Insert or update node. If revive_dead=True and node exists as dead, set status to offline. clique_id is hex string (66 chars)."""
    now = time.time()
    st = status or STATUS_OFFLINE
    fse = first_seen if first_seen is not None else now
    lse = last_seen if last_seen is not None else 0.0   # 0 = never got a response yet
    lex = last_explored if last_explored is not None else 0.0  # 0 = never explored, explore first
    async with aiosqlite.connect(db_path) as db:
        if revive_dead:
            await db.execute(
                "UPDATE nodes SET status = ? WHERE address = ? AND port = ? AND status = ?",
                (STATUS_OFFLINE, address, port, STATUS_DEAD),
            )
            await db.commit()
        await db.execute(
            """
            INSERT INTO nodes (address, port, domain, clique_id, version, country, city, continent, has_api, status, first_seen, last_seen, last_explored)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(address, port) DO UPDATE SET
                domain = COALESCE(excluded.domain, domain),
                clique_id = COALESCE(excluded.clique_id, clique_id),
                version = COALESCE(excluded.version, version),
                country = COALESCE(excluded.country, country),
                city = COALESCE(excluded.city, city),
                continent = COALESCE(excluded.continent, continent),
                has_api = excluded.has_api OR has_api,
                status = excluded.status,
                last_seen = CASE WHEN excluded.last_seen > 0 THEN excluded.last_seen ELSE nodes.last_seen END,
                first_seen = nodes.first_seen,
                last_explored = nodes.last_explored
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
                st,
                fse,
                lse,
                lex,
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
) -> None:
    """Update only enrichment fields (version, geo, has_api, clique_id); does not change status or timestamps."""
    async with aiosqlite.connect(db_path) as db:
        updates = []
        params: List[Any] = []
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
        if not updates:
            return
        params.extend([address, port])
        await db.execute(
            f"UPDATE nodes SET {', '.join(updates)} WHERE address = ? AND port = ?",
            params,
        )
        await db.commit()


async def mark_exploration_success(db_path: str, address: str, port: int) -> None:
    """Called when we got a response from the node."""
    now = time.time()
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "UPDATE nodes SET status = ?, last_seen = ?, last_explored = ? WHERE address = ? AND port = ?",
            (STATUS_ONLINE, now, now, address, port),
        )
        await db.commit()


async def mark_exploration_failed(db_path: str, address: str, port: int) -> None:
    """Called when we got no response. Sets last_explored=now; offline if last_seen > 30m ago, dead if > 48h."""
    now = time.time()
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT last_seen, status FROM nodes WHERE address = ? AND port = ?",
            (address, port),
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
            "UPDATE nodes SET status = ?, last_explored = ? WHERE address = ? AND port = ?",
            (new_status, now, address, port),
        )
        await db.commit()


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


async def revive_if_dead(db_path: str, address: str, port: int) -> bool:
    """If node is dead, set status=offline so it gets explored again. Returns True if was dead and revived."""
    async with aiosqlite.connect(db_path) as db:
        cur = await db.execute(
            "UPDATE nodes SET status = ? WHERE address = ? AND port = ? AND status = ?",
            (STATUS_OFFLINE, address, port, STATUS_DEAD),
        )
        await db.commit()
        return cur.rowcount > 0


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
        return {
            "total_discovered": total,
            "online": online,
            "offline": offline,
            "dead": dead,
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
) -> AsyncIterator[dict[str, Any]]:
    query = "SELECT address, port, domain, clique_id, version, country, city, continent, has_api, status, first_seen, last_seen, last_explored FROM nodes WHERE 1=1"
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
                    "status": row["status"],
                    "date_first_seen": row["first_seen"],
                    "date_last_seen": row["last_seen"],
                    "date_last_explored": row["last_explored"],
                }
