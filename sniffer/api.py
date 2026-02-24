"""HTTP API with Swagger for node explorer."""
import logging
from typing import List, Optional

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

from sniffer.config import Config
from sniffer.db import get_nodes, get_stats, get_versions

logger = logging.getLogger(__name__)


def create_app(config: Config, db_path: str) -> FastAPI:
    app = FastAPI(
        title="Alephium Node Explorer",
        description="API to explore discovered Alephium P2P nodes",
        version="0.1.0",
    )

    def _ref_nodes() -> List[str]:
        nodes = config.reference_nodes or []
        if not nodes and config.network_id == 0:
            nodes = [
                "bootstrap0.alephium.org:9973",
                "bootstrap1.alephium.org:9973",
                "bootstrap2.alephium.org:9973",
                "bootstrap3.alephium.org:9973",
                "bootstrap4.alephium.org:9973",
                "bootstrap5.alephium.org:9973",
            ]
        elif not nodes:
            nodes = [
                "bootstrap0.testnet.alephium.org:9973",
                "bootstrap1.testnet.alephium.org:9973",
            ]
        return nodes

    @app.get("/reference-nodes", response_model=List[str])
    async def reference_nodes():
        """List of reference nodes used for relay and discovery."""
        return _ref_nodes()

    @app.get("/stats")
    async def stats():
        """Total discovered, online, offline, and dead node counts. Offline = no response 30m; dead = no response 48h."""
        return await get_stats(db_path)

    @app.get("/versions")
    async def versions():
        """All node versions found with their count."""
        return await get_versions(db_path)

    @app.get("/nodes")
    async def nodes(
        continent: Optional[str] = Query(None, description="Filter by continent code"),
        country: Optional[str] = Query(None, description="Filter by country"),
        has_api: Optional[bool] = Query(None, description="Filter by HTTP API exposed"),
        version: Optional[str] = Query(None, description="Filter by node version"),
        status: Optional[str] = Query(None, description="Filter by status: online, offline, dead"),
    ):
        """List discovered nodes with date_first_seen, date_last_seen, date_last_explored. Filters: continent, country, has_api, version, status."""
        out: List[dict] = []
        async for row in get_nodes(
            db_path,
            continent=continent,
            country=country,
            has_api=has_api,
            version=version,
            status=status,
        ):
            out.append(row)
        return out

    return app
