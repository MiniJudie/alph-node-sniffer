"""Push node snapshot to Google BigQuery after each discovery loop."""
import asyncio
import json
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def _row_for_bigquery(node: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a node dict from get_nodes() to a BigQuery-friendly row (JSON-serializable)."""
    row = dict(node)
    # BigQuery load accepts FLOAT for timestamps (Unix seconds)
    for key in ("date_first_seen", "date_last_seen", "date_last_explored"):
        if key in row and row[key] is not None:
            try:
                row[key] = float(row[key])
            except (TypeError, ValueError):
                row[key] = None
    if row.get("chain_heights") is not None:
        if isinstance(row["chain_heights"], list):
            row["chain_heights"] = json.dumps(row["chain_heights"])
        else:
            row["chain_heights"] = str(row["chain_heights"])
    # Ensure None instead of missing for optional fields so BQ schema is consistent
    for key in (
        "domain", "clique_id", "version", "country", "city", "continent",
        "reverse_dns", "hoster", "country_code", "isp", "org", "zip",
        "client", "os", "broker_port", "rest_port", "discovery_status",
        "broker_status", "rest_status", "rest_url",
    ):
        if key not in row:
            row[key] = None
    if row.get("lat") is not None:
        row["lat"] = float(row["lat"])
    if row.get("lon") is not None:
        row["lon"] = float(row["lon"])
    return row


def _sync_load_to_bigquery(
    project_id: str,
    dataset_id: str,
    table_id: str,
    rows: List[Dict[str, Any]],
) -> None:
    """Synchronous: load rows into BigQuery table (WRITE_TRUNCATE = replace table content)."""
    from google.cloud import bigquery
    from google.cloud.bigquery import LoadJobConfig

    client = bigquery.Client(project=project_id)
    table_ref = f"{project_id}.{dataset_id}.{table_id}"
    job_config = LoadJobConfig(
        write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
        autodetect=True,
    )
    job = client.load_table_from_json(rows, table_ref, job_config=job_config)
    job.result()
    logger.info("BigQuery: loaded %d rows into %s", len(rows), table_ref)


async def push_nodes_to_bigquery(
    config: "Config",
    db_path: str,
) -> None:
    """
    If BigQuery is configured (project, dataset, table), collect all nodes from the DB
    and load them into the BigQuery table (replacing existing data).
    Runs the load in an executor to avoid blocking. Logs and swallows errors.
    """
    from sniffer.config import Config

    if not isinstance(config, Config):
        return
    project = (config.bigquery_project or "").strip()
    dataset = (config.bigquery_dataset or "").strip()
    table = (config.bigquery_table or "").strip()
    if not project or not dataset or not table:
        return

    from sniffer.db import get_nodes

    rows: List[Dict[str, Any]] = []
    async for node in get_nodes(db_path):
        rows.append(_row_for_bigquery(node))

    if not rows:
        logger.debug("BigQuery: no nodes to push")
        return

    logger.info("BigQuery: pushing %d rows to %s.%s.%s ...", len(rows), project, dataset, table)
    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(
                None,
                _sync_load_to_bigquery,
                project,
                dataset,
                table,
                rows,
            ),
            timeout=300.0,
        )
    except asyncio.TimeoutError:
        logger.warning("BigQuery push timed out after 300s")
    except Exception as e:
        logger.warning("BigQuery push failed: %s", e, exc_info=True)
