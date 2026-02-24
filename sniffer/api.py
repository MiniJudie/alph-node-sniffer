"""HTTP API with Swagger for node explorer."""
import logging
from typing import Optional

from fastapi import FastAPI, Query

from sniffer.config import Config
from sniffer.db import get_nodes_paginated

logger = logging.getLogger(__name__)


def create_app(config: Config, db_path: str) -> FastAPI:
    app = FastAPI(
        title="Alephium Node Explorer",
        description="API to explore discovered Alephium P2P nodes",
        version="0.1.0",
    )

    @app.get("/nodes")
    async def nodes(
        page: int = Query(1, ge=1, description="Page number (1-based)"),
        limit: int = Query(50, ge=1, le=1000, description="Items per page"),
        continent: Optional[str] = Query(None, description="Filter by continent code"),
        country: Optional[str] = Query(None, description="Filter by country"),
        has_api: Optional[bool] = Query(None, description="Filter by HTTP API exposed"),
        version: Optional[str] = Query(None, description="Filter by node version"),
        status: Optional[str] = Query(None, description="Filter by status: online, offline, dead"),
        synced: Optional[bool] = Query(None, description="Filter by sync: true=synced, false=not synced"),
    ):
        """Paginated list of nodes. Response: { stats: { total, online, offline, dead, last_update }, nodes: [] }. Filters: continent, country, has_api, version, status, synced."""
        return await get_nodes_paginated(
            db_path,
            page=page,
            limit=limit,
            continent=continent,
            country=country,
            has_api=has_api,
            version=version,
            status=status,
            synced=synced,
        )

    return app
