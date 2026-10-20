"""
Metrics router: Aggregated statistics and time-series query trends.
All values reflect clearly marked DEMO / SAMPLE DATA.
"""

from fastapi import APIRouter
from app.database import get_db_connection
from app.models import MetricSummary, ActivityResponse, ActivityPoint

router = APIRouter(prefix="/api", tags=["Metrics"])


@router.get("/metrics", response_model=MetricSummary)
def get_metrics_summary():
    """Returns overview metric cards for total queries, blocks, cache ratio, and latency."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Query aggregates
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN policy_action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
            SUM(CASE WHEN policy_action = 'ALLOW' THEN 1 ELSE 0 END) as allowed,
            SUM(CASE WHEN cache_status = 'HIT' THEN 1 ELSE 0 END) as hits,
            SUM(CASE WHEN cache_status = 'MISS' THEN 1 ELSE 0 END) as misses,
            AVG(latency_ms) as avg_latency
        FROM queries
    """)
    row = cursor.fetchone()

    total = row["total"] or 0
    blocked = row["blocked"] or 0
    allowed = row["allowed"] or 0
    hits = row["hits"] or 0
    misses = row["misses"] or 0
    avg_latency = round(row["avg_latency"] or 0.0, 2)

    cache_hit_ratio = round((hits / total) if total > 0 else 0.0, 3)
    block_rate = round(((blocked / total) * 100) if total > 0 else 0.0, 1)

    # Active alerts
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'Active'")
    active_alerts = cursor.fetchone()[0]

    conn.close()

    return MetricSummary(
        total_queries=total,
        blocked_queries=blocked,
        allowed_queries=allowed,
        cache_hit_ratio=cache_hit_ratio,
        cache_hits=hits,
        cache_misses=misses,
        avg_latency_ms=avg_latency,
        block_rate_percent=block_rate,
        active_alerts_count=active_alerts,
        is_sample_data=True
    )


@router.get("/activity", response_model=ActivityResponse)
def get_activity_timeline():
    """Returns time-series query activity points suitable for frontend charts."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch last 60 queries ordered by timestamp ascending
    cursor.execute("""
        SELECT timestamp, policy_action, cache_status
        FROM queries
        ORDER BY timestamp ASC
    """)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return ActivityResponse(interval="10m", points=[], is_sample_data=True)

    # Group into buckets of 5 queries for a clean smooth chart line
    points = []
    bucket_size = max(1, len(rows) // 10)
    for i in range(0, len(rows), bucket_size):
        chunk = rows[i:i + bucket_size]
        if not chunk:
            continue
        # Extract HH:MM from ISO string
        time_str = chunk[0]["timestamp"]
        try:
            time_label = time_str.split("T")[1][:5]
        except Exception:
            time_label = f"T-{i}"

        total = len(chunk)
        blocked = sum(1 for r in chunk if r["policy_action"] == "BLOCK")
        allowed = sum(1 for r in chunk if r["policy_action"] == "ALLOW")
        hits = sum(1 for r in chunk if r["cache_status"] == "HIT")

        points.append(ActivityPoint(
            time_label=time_label,
            total=total,
            allowed=allowed,
            blocked=blocked,
            cache_hits=hits
        ))

    return ActivityResponse(interval="10m", points=points, is_sample_data=True)
