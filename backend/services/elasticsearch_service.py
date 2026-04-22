from datetime import datetime, date
from typing import Optional, List, Dict, Any
from elasticsearch import AsyncElasticsearch, NotFoundError
from config import settings
import logging

logger = logging.getLogger(__name__)

es_client: Optional[AsyncElasticsearch] = None


def get_es_client() -> AsyncElasticsearch:
    global es_client
    if es_client is None:
        es_client = AsyncElasticsearch(
            hosts=[settings.ELASTICSEARCH_URL],
            retry_on_timeout=True,
            max_retries=3,
        )
    return es_client


def get_index_name(ts: Optional[datetime] = None) -> str:
    d = ts.date() if ts else date.today()
    return f"{settings.ES_LOG_INDEX_PREFIX}-{d.strftime('%Y-%m-%d')}"


INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "agent_id":     {"type": "keyword"},
            "timestamp":    {"type": "date"},
            "level":        {"type": "keyword"},
            "source":       {"type": "keyword"},
            "message":      {"type": "text", "analyzer": "standard"},
            "raw":          {"type": "text", "index": False},
            "parsed_fields": {"type": "object", "dynamic": True},
        }
    },
    "settings": {
        "number_of_shards":   settings.ES_NUMBER_OF_SHARDS,
        "number_of_replicas": settings.ES_NUMBER_OF_REPLICAS,
        "index.lifecycle.name":   "siem-logs-policy",
        "index.lifecycle.rollover_alias": settings.ES_LOG_INDEX_PREFIX,
        "index.refresh_interval": "5s",
        "index.translog.durability": "async",
    },
}


def _ilm_policy() -> dict:
    return {
        "policy": {
            "phases": {
                "hot": {
                    "actions": {
                        "rollover": {
                            "max_size": "10gb",
                            "max_age":  "1d",
                        },
                        "set_priority": {"priority": 100},
                    }
                },
                "warm": {
                    "min_age": "7d",
                    "actions": {
                        "forcemerge": {"max_num_segments": 1},
                        "set_priority": {"priority": 50},
                    },
                },
                "cold": {
                    "min_age": f"{max(settings.LOG_RETENTION_DAYS // 2, 14)}d",
                    "actions": {
                        "set_priority": {"priority": 0},
                    },
                },
                "delete": {
                    "min_age": f"{settings.LOG_RETENTION_DAYS}d",
                    "actions": {"delete": {}},
                },
            }
        }
    }


async def setup_index_template():
    client = get_es_client()
    try:
        # Create ILM policy
        await client.ilm.put_lifecycle(
            name="siem-logs-policy",
            policy=_ilm_policy()["policy"],
        )
        logger.info(f"ES ILM policy created (retention={settings.LOG_RETENTION_DAYS} days)")
    except Exception as e:
        logger.warning(f"Could not create ILM policy: {e}")

    try:
        await client.indices.put_index_template(
            name="siem-logs-template",
            body={
                "index_patterns": [f"{settings.ES_LOG_INDEX_PREFIX}-*"],
                **INDEX_MAPPING,
                "priority": 100,
            }
        )
        logger.info(
            f"ES index template created "
            f"(shards={settings.ES_NUMBER_OF_SHARDS}, replicas={settings.ES_NUMBER_OF_REPLICAS})"
        )
    except Exception as e:
        logger.warning(f"Could not create ES index template: {e}")


async def index_log(log_doc: dict) -> str:
    client = get_es_client()
    ts_raw = log_doc.get("timestamp")
    if isinstance(ts_raw, str):
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.utcnow()
    elif isinstance(ts_raw, datetime):
        ts = ts_raw
    else:
        ts = datetime.utcnow()

    index = get_index_name(ts)
    try:
        resp = await client.index(index=index, document=log_doc)
        return resp["_id"]
    except Exception as e:
        logger.error(f"Failed to index log: {e}")
        raise


async def bulk_index_logs(logs: List[dict]) -> List[str]:
    client = get_es_client()
    if not logs:
        return []

    operations = []
    for log in logs:
        ts_raw = log.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except Exception:
                ts = datetime.utcnow()
        else:
            ts = datetime.utcnow()
        index = get_index_name(ts)
        operations.append({"index": {"_index": index}})
        operations.append(log)

    try:
        resp = await client.bulk(operations=operations)
        ids = []
        for item in resp.get("items", []):
            ids.append(item.get("index", {}).get("_id", ""))
        return ids
    except Exception as e:
        logger.error(f"Bulk index failed: {e}")
        raise


async def search_logs(
    agent_id: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    keyword: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    page: int = 1,
    size: int = 50,
) -> Dict[str, Any]:
    client = get_es_client()

    must_clauses = []
    if agent_id:
        must_clauses.append({"term": {"agent_id.keyword": agent_id}})
    if level:
        must_clauses.append({"term": {"level.keyword": level.upper()}})
    if event_type:
        must_clauses.append({"term": {"parsed_fields.event_type.keyword": event_type}})
    if source:
        must_clauses.append({"wildcard": {"source": {"value": f"*{source}*", "case_insensitive": True}}})
    if keyword:
        must_clauses.append({"multi_match": {"query": keyword, "fields": ["message", "source", "raw"]}})

    range_filter = {}
    if start_time:
        range_filter["gte"] = start_time.isoformat()
    if end_time:
        range_filter["lte"] = end_time.isoformat()

    query: dict = {"bool": {}}
    if must_clauses:
        query["bool"]["must"] = must_clauses
    if range_filter:
        query["bool"]["filter"] = [{"range": {"timestamp": range_filter}}]
    if not must_clauses and not range_filter:
        query = {"match_all": {}}

    from_offset = (page - 1) * size
    try:
        resp = await client.search(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "query": query,
                "sort": [{"timestamp": {"order": "desc"}}],
                "from": from_offset,
                "size": size,
            }
        )
        hits = resp["hits"]["hits"]
        total = resp["hits"]["total"]["value"]
        logs = []
        for hit in hits:
            doc = hit["_source"]
            doc["id"] = hit["_id"]
            logs.append(doc)
        return {"logs": logs, "total": total, "page": page, "size": size}
    except Exception as e:
        logger.error(f"Log search failed: {e}")
        return {"logs": [], "total": 0, "page": page, "size": size}


async def count_logs_in_range(start: datetime, end: datetime) -> int:
    client = get_es_client()
    try:
        resp = await client.count(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": start.isoformat(),
                            "lte": end.isoformat(),
                        }
                    }
                }
            }
        )
        return resp.get("count", 0)
    except Exception:
        return 0


async def count_logs_per_hour(hours: int = 24) -> List[Dict]:
    client = get_es_client()
    try:
        resp = await client.search(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "size": 0,
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{hours}h",
                            "lte": "now",
                        }
                    }
                },
                "aggs": {
                    "logs_per_hour": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "hour",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": f"now-{hours}h",
                                "max": "now",
                            }
                        }
                    }
                }
            }
        )
        buckets = resp["aggregations"]["logs_per_hour"]["buckets"]
        result = []
        for bucket in buckets:
            result.append({
                "hour": bucket["key_as_string"],
                "count": bucket["doc_count"],
            })
        return result
    except Exception as e:
        logger.error(f"logs_per_hour aggregation failed: {e}")
        return []


async def get_recent_logs_for_agent(agent_id: str, size: int = 10) -> List[dict]:
    client = get_es_client()
    try:
        resp = await client.search(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "query": {"term": {"agent_id.keyword": agent_id}},
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": size,
            }
        )
        result = []
        for hit in resp["hits"]["hits"]:
            doc = hit["_source"]
            doc["id"] = hit["_id"]
            result.append(doc)
        return result
    except Exception:
        return []


async def close_es():
    global es_client
    if es_client:
        await es_client.close()
        es_client = None
