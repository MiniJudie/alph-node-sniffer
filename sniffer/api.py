"""HTTP API with Swagger for node explorer."""
import csv
import io
import json
import logging
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import Response

from sniffer.config import Config
from sniffer.db import chain_heights_for_json, get_node_by_address, get_nodes, get_nodes_paginated

logger = logging.getLogger(__name__)


def create_app(config: Config, db_path: str) -> FastAPI:
    app = FastAPI(
        title="Alephium Node Explorer",
        description="API to explore discovered Alephium P2P nodes",
        version="0.1.0",
    )

    @app.get(
        "/nodes/csv",
        tags=["Nodes"],
        summary="Download nodes as CSV",
        responses={
            200: {
                "content": {"text/csv": {"schema": {"type": "string", "format": "binary"}}},
                "description": "CSV file with all nodes (filtered by query params)",
            }
        },
    )
    async def nodes_csv(
        continent: Optional[str] = Query(None, description="Filter by continent code"),
        country: Optional[str] = Query(None, description="Filter by country"),
        has_api: Optional[bool] = Query(None, description="Filter by HTTP API exposed"),
        version: Optional[str] = Query(None, description="Filter by node version"),
        status: Optional[str] = Query(None, description="Filter by status: online, offline, dead"),
        synced: Optional[bool] = Query(None, description="Filter by sync: true=synced, false=not synced"),
    ):
        """Download all nodes (respecting filters) as CSV. Same query params as GET /nodes."""
        fieldnames = [
            "address", "port", "domain", "clique_id", "version", "country", "city", "continent",
            "has_api", "synced", "status", "discovery_status", "broker_port", "broker_status", "rest_port", "rest_status", "rest_url",
            "date_first_seen", "date_last_seen", "date_last_explored",
            "reverse_dns", "hoster", "country_code", "isp", "org", "zip", "lat", "lon", "chain_heights", "client", "os",
        ]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        async for node in get_nodes(
            db_path,
            continent=continent,
            country=country,
            has_api=has_api,
            version=version,
            status=status,
            synced=synced,
        ):
            row = dict(node)
            if row.get("chain_heights") is not None:
                row["chain_heights"] = json.dumps(chain_heights_for_json(row["chain_heights"]) or {})
            for k in ("has_api", "synced"):
                if row.get(k) is not None:
                    row[k] = "true" if row[k] else "false"
            writer.writerow(row)
        return Response(
            content=buf.getvalue().encode("utf-8"),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=nodes.csv"},
        )

    @app.get(
        "/nodes/{address}",
        tags=["Nodes"],
        summary="Get node by IP address",
        responses={200: {"description": "Node info"}, 404: {"description": "Node not found"}},
    )
    async def node_by_address(address: str):
        """Get node info by IP address. Returns 404 if not found."""
        node = await get_node_by_address(db_path, address)
        if node is None:
            raise HTTPException(status_code=404, detail="Node not found")
        if node.get("chain_heights") is not None:
            node["chain_heights"] = chain_heights_for_json(node["chain_heights"])
        return node

    @app.get("/nodes", tags=["Nodes"])
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
        result = await get_nodes_paginated(
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
        for n in result.get("nodes", []):
            if n.get("chain_heights") is not None:
                n["chain_heights"] = chain_heights_for_json(n["chain_heights"])
        return result

    @app.get(
        "/status/node",
        tags=["Status"],
        summary="List all nodes as host:port -> status",
        description="Returns a map of '<address>:<port>' to status (online, offline, dead). Optional status filter.",
        response_model=Dict[str, str],
        responses={200: {"description": "Map of '<host>:<port>' to status (online, offline, dead)"}},
        operation_id="get_status_node",
    )
    async def status_node(
        status: Optional[str] = Query(None, description="Filter by status: online, offline, dead"),
    ):
        """Returns { '<host>:<port>': '<status>', ... }. Use status query to filter (e.g. ?status=online)."""
        out: Dict[str, str] = {}
        async for node in get_nodes(db_path, status=status):
            key = f"{node['address']}:{node['port']}"
            out[key] = node["status"]
        return out

    return app
