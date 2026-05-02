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
        kwargs: Dict[str, Any] = dict(
            hosts=[settings.ELASTICSEARCH_URL],
            retry_on_timeout=True,
            max_retries=3,
            verify_certs=settings.ELASTICSEARCH_VERIFY_CERTS,
        )
        if settings.ELASTICSEARCH_PASSWORD:
            kwargs["basic_auth"] = (settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD)
        es_client = AsyncElasticsearch(**kwargs)
    return es_client


def get_index_name(ts: Optional[datetime] = None) -> str:
    d = ts.date() if ts else date.today()
    return f"{settings.ES_LOG_INDEX_PREFIX}-{d.strftime('%Y-%m-%d')}"


INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "agent_id":  {"type": "keyword"},
            "hostname":  {"type": "keyword"},
            "timestamp": {"type": "date"},
            "level":     {"type": "keyword"},
            "source":    {"type": "keyword"},
            "message":   {"type": "text", "analyzer": "standard"},
            "raw":       {"type": "text", "index": False},
            "parsed_fields": {
                "type": "object",
                "dynamic": True,
                "properties": {
                    "event_type":       {"type": "keyword"},
                    "src_ip":           {"type": "keyword"},
                    "ssh_user":         {"type": "keyword"},
                    "ssh_src_ip":       {"type": "keyword"},
                    "file_path":        {"type": "keyword"},
                    "process":          {"type": "keyword"},
                    "has_malicious_ip": {"type": "boolean"},
                    "geo_country":      {"type": "keyword"},
                    "geo_country_code": {"type": "keyword"},
                    "geo_city":         {"type": "keyword"},
                    "geo_isp":          {"type": "keyword"},
                },
            },
        }
    },
    "settings": {
        "number_of_shards":   settings.ES_NUMBER_OF_SHARDS,
        "number_of_replicas": settings.ES_NUMBER_OF_REPLICAS,
        "index.lifecycle.name":           "siem-logs-policy",
        "index.lifecycle.rollover_alias": settings.ES_LOG_INDEX_PREFIX,
        "index.refresh_interval":         "5s",
        "index.translog.durability":      "async",
    },
}


def _ilm_policy() -> dict:
    return {
        "policy": {
            "phases": {
                "hot": {
                    "actions": {
                        "rollover":     {"max_size": "10gb", "max_age": "1d"},
                        "set_priority": {"priority": 100},
                    }
                },
                "warm": {
                    "min_age": "7d",
                    "actions": {
                        "forcemerge":   {"max_num_segments": 1},
                        "set_priority": {"priority": 50},
                    },
                },
                "cold": {
                    "min_age": f"{max(settings.LOG_RETENTION_DAYS // 2, 14)}d",
                    "actions": {"set_priority": {"priority": 0}},
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
            },
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
        return [item.get("index", {}).get("_id", "") for item in resp.get("items", [])]
    except Exception as e:
        logger.error(f"Bulk index failed: {e}")
        raise


async def search_logs(
    agent_id:    Optional[str]       = None,
    hostname:    Optional[str]       = None,
    level:       Optional[str]       = None,
    start_time:  Optional[datetime]  = None,
    end_time:    Optional[datetime]  = None,
    keyword:     Optional[str]       = None,
    event_types: Optional[List[str]] = None,
    source:      Optional[str]       = None,
    sort_by:     str                 = "timestamp",
    sort_order:  str                 = "desc",
    page:        int                 = 1,
    size:        int                 = 50,
) -> Dict[str, Any]:
    client = get_es_client()

    # ES stores all string fields as text+keyword sub-field (dynamic mapping).
    # Exact-match / aggregation queries must use the .keyword sub-field.
    must: list = []
    if agent_id:
        must.append({"term": {"agent_id.keyword": agent_id}})
    if hostname:
        must.append({"wildcard": {"hostname.keyword": {"value": f"*{hostname}*", "case_insensitive": True}}})
    if level:
        must.append({"term": {"level.keyword": level.upper()}})
    if event_types:
        if len(event_types) == 1:
            must.append({"term": {"parsed_fields.event_type.keyword": event_types[0]}})
        else:
            must.append({"terms": {"parsed_fields.event_type.keyword": event_types}})
    if source:
        must.append({"wildcard": {"source.keyword": {"value": f"*{source}*", "case_insensitive": True}}})
    if keyword:
        must.append({
            "multi_match": {
                "query":  keyword,
                "fields": ["message^2", "raw", "source", "hostname"],
                "type":   "best_fields",
            }
        })

    filters: list = []
    ts_range: dict = {}
    if start_time:
        ts_range["gte"] = start_time.isoformat()
    if end_time:
        ts_range["lte"] = end_time.isoformat()
    if ts_range:
        filters.append({"range": {"timestamp": ts_range}})

    if must or filters:
        query: dict = {"bool": {}}
        if must:
            query["bool"]["must"] = must
        if filters:
            query["bool"]["filter"] = filters
    else:
        query = {"match_all": {}}

    # Sort: timestamp is a date (no .keyword), level needs .keyword
    sort_field = "level.keyword" if sort_by == "level" else "timestamp"
    sort_dir   = "asc" if sort_order == "asc" else "desc"

    try:
        resp = await client.search(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "query":             query,
                "sort":              [{sort_field: {"order": sort_dir}}],
                "from":              (page - 1) * size,
                "size":              size,
                "track_total_hits":  True,
            },
        )
        hits  = resp["hits"]["hits"]
        total = resp["hits"]["total"]["value"]
        logs  = [{"id": h["_id"], **h["_source"]} for h in hits]
        return {"logs": logs, "total": total, "page": page, "size": size}
    except Exception as e:
        logger.error(f"Log search failed: {e}")
        return {"logs": [], "total": 0, "page": page, "size": size}


async def get_log_sources(limit: int = 50) -> List[str]:
    client = get_es_client()
    try:
        resp = await client.search(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "size": 0,
                "aggs": {
                    "sources": {"terms": {"field": "source.keyword", "size": limit}}
                },
            },
        )
        return [b["key"] for b in resp["aggregations"]["sources"]["buckets"] if b["key"]]
    except Exception as e:
        logger.error(f"get_log_sources failed: {e}")
        return []


async def get_log_stats(hours: int = 24) -> Dict[str, Any]:
    client = get_es_client()
    try:
        resp = await client.search(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "size":             0,
                "track_total_hits": True,
                "query": {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
                "aggs": {
                    "by_level": {
                        "terms": {"field": "level.keyword", "size": 10}
                    },
                    "by_event_type": {
                        "terms": {"field": "parsed_fields.event_type.keyword", "size": 30, "min_doc_count": 1}
                    },
                    "by_agent": {
                        "terms": {"field": "hostname.keyword", "size": 20}
                    },
                },
            },
        )
        aggs = resp["aggregations"]
        return {
            "total":         resp["hits"]["total"]["value"],
            "by_level":      {b["key"]: b["doc_count"] for b in aggs["by_level"]["buckets"]},
            "by_event_type": {b["key"]: b["doc_count"] for b in aggs["by_event_type"]["buckets"] if b["key"]},
            "by_agent":      {b["key"]: b["doc_count"] for b in aggs["by_agent"]["buckets"] if b["key"]},
            "hours":         hours,
        }
    except Exception as e:
        logger.error(f"get_log_stats failed: {e}")
        return {"total": 0, "by_level": {}, "by_event_type": {}, "by_agent": {}, "hours": hours}


async def get_dynamic_event_types(limit: int = 100) -> List[str]:
    client = get_es_client()
    try:
        resp = await client.search(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "size": 0,
                "aggs": {
                    "event_types": {
                        "terms": {"field": "parsed_fields.event_type.keyword", "size": limit, "min_doc_count": 1}
                    }
                },
            },
        )
        return [b["key"] for b in resp["aggregations"]["event_types"]["buckets"] if b["key"]]
    except Exception as e:
        logger.error(f"get_dynamic_event_types failed: {e}")
        return []


async def count_logs_in_range(start: datetime, end: datetime) -> int:
    client = get_es_client()
    try:
        resp = await client.count(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "query": {
                    "range": {"timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}
                }
            },
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
                "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                "aggs": {
                    "logs_per_hour": {
                        "date_histogram": {
                            "field":             "timestamp",
                            "calendar_interval": "hour",
                            "min_doc_count":     0,
                            "extended_bounds":   {"min": f"now-{hours}h", "max": "now"},
                        }
                    }
                },
            },
        )
        return [
            {"hour": b["key_as_string"][:19].replace("T", " ")[11:16], "count": b["doc_count"]}
            for b in resp["aggregations"]["logs_per_hour"]["buckets"]
        ]
    except Exception as e:
        logger.error(f"count_logs_per_hour failed: {e}")
        return []


async def get_recent_logs_for_agent(agent_id: str, size: int = 10) -> List[dict]:
    client = get_es_client()
    try:
        resp = await client.search(
            index=f"{settings.ES_LOG_INDEX_PREFIX}-*",
            body={
                "query": {"term": {"agent_id.keyword": agent_id}},
                "sort":  [{"timestamp": {"order": "desc"}}],
                "size":  size,
            },
        )
        return [{"id": h["_id"], **h["_source"]} for h in resp["hits"]["hits"]]
    except Exception:
        return []


async def close_es():
    global es_client
    if es_client:
        await es_client.close()
        es_client = None
