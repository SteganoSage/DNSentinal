"""
Queries router: Query log inspection, filtering, and interactive live test simulation.
All logged records represent DEMO / SAMPLE DATA.
"""

from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Query
from app.database import get_db_connection
from app.models import DNSQueriesResponse, DNSQueryItem, SimulateQueryRequest

router = APIRouter(prefix="/api", tags=["DNS Queries"])


@router.get("/queries", response_model=DNSQueriesResponse)
def list_queries(
    search: Optional[str] = Query(None, description="Search domain or client name"),
    status: Optional[str] = Query(None, description="ALLOW or BLOCK"),
    qtype: Optional[str] = Query(None, description="A, AAAA, TXT, etc."),
    cache_status: Optional[str] = Query(None, description="HIT or MISS"),
    client_ip: Optional[str] = Query(None, description="Filter by client IP"),
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=5, le=100)
):
    """Returns paginated and filtered DNS queries from the SQLite database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    conditions = []
    params = []

    if search:
        conditions.append("(qname LIKE ? OR client_name LIKE ? OR client_ip LIKE ?)")
        search_pattern = f"%{search}%"
        params.extend([search_pattern, search_pattern, search_pattern])

    if status and status.upper() in ["ALLOW", "BLOCK"]:
        conditions.append("policy_action = ?")
        params.append(status.upper())

    if qtype:
        conditions.append("qtype = ?")
        params.append(qtype.upper())

    if cache_status and cache_status.upper() in ["HIT", "MISS"]:
        conditions.append("cache_status = ?")
        params.append(cache_status.upper())

    if client_ip:
        conditions.append("client_ip = ?")
        params.append(client_ip)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # Count matching queries
    count_sql = f"SELECT COUNT(*) FROM queries {where_clause}"
    cursor.execute(count_sql, params)
    total_count = cursor.fetchone()[0]

    # Paginate results
    offset = (page - 1) * limit
    data_sql = f"""
        SELECT id, timestamp, client_ip, client_name, qname, qtype, rcode, 
               answer_count, cache_status, latency_ms, policy_action, block_reason, protocol
        FROM queries
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    cursor.execute(data_sql, params + [limit, offset])
    rows = cursor.fetchall()
    conn.close()

    items = [
        DNSQueryItem(
            id=r["id"],
            timestamp=r["timestamp"],
            client_ip=r["client_ip"],
            client_name=r["client_name"],
            qname=r["qname"],
            qtype=r["qtype"],
            rcode=r["rcode"],
            answer_count=r["answer_count"],
            cache_status=r["cache_status"],
            latency_ms=r["latency_ms"],
            policy_action=r["policy_action"],
            block_reason=r["block_reason"],
            protocol=r["protocol"]
        )
        for r in rows
    ]

    return DNSQueriesResponse(
        total=total_count,
        page=page,
        limit=limit,
        queries=items
    )


@router.post("/queries/simulate", response_model=DNSQueryItem)
def simulate_query(req: SimulateQueryRequest):
    """
    Simulates a live DNS query passing through DNSentinel's demo policy engine.
    Inserts the simulated query into SQLite and returns the evaluation.
    """
    domain = req.qname.lower().strip()
    client_ip = req.client_ip or "192.168.1.10"
    client_name = req.client_name or "SOC-Analyst-PC"
    qtype = (req.qtype or "A").upper()
    protocol = req.protocol or "DoH"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Demo policy rules for simulation
    is_blocked = False
    reason = None
    rcode = "NOERROR"
    answer_count = 2
    cache_status = "MISS"
    latency = 14.2

    # Check known threat keywords for demo simulation
    if any(k in domain for k in ["malware", "dga", "botnet", "c2", "evil"]):
        is_blocked = True
        reason = "DGA / Malware Domain Detected"
        rcode = "NXDOMAIN"
        answer_count = 0
        latency = 1.2
    elif any(k in domain for k in ["ad", "doubleclick", "tracker", "analytics", "telemetry"]):
        is_blocked = True
        reason = "Blocklist: Ad Network / Telemetry"
        answer_count = 0
        latency = 0.3
        cache_status = "HIT"
    elif any(k in domain for k in ["exfil", "tunnel", "iodine"]):
        is_blocked = True
        reason = "Covert DNS Tunnel Exfiltration"
        answer_count = 0
        latency = 2.1
    elif any(k in domain for k in ["local", "router", "internal"]) and "bad" in domain:
        is_blocked = True
        reason = "DNS Rebinding Protection (RFC1918 Private IP)"
        answer_count = 0
        latency = 1.5
    else:
        # Legitimate query
        cache_status = "HIT" if ("github" in domain or "google" in domain) else "MISS"
        latency = 0.4 if cache_status == "HIT" else 15.6

    policy_action = "BLOCK" if is_blocked else "ALLOW"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO queries (timestamp, client_ip, client_name, qname, qtype, rcode, answer_count, cache_status, latency_ms, policy_action, block_reason, protocol)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (now_iso, client_ip, client_name, domain, qtype, rcode, answer_count, cache_status, latency, policy_action, reason, protocol))
    
    new_id = cursor.lastrowid

    # Update client total count
    cursor.execute("""
        UPDATE clients 
        SET total_queries = total_queries + 1,
            blocked_queries = blocked_queries + (CASE WHEN ? = 'BLOCK' THEN 1 ELSE 0 END),
            last_seen = ?
        WHERE ip = ?
    """, (policy_action, now_iso, client_ip))

    conn.commit()
    conn.close()

    return DNSQueryItem(
        id=new_id,
        timestamp=now_iso,
        client_ip=client_ip,
        client_name=client_name,
        qname=domain,
        qtype=qtype,
        rcode=rcode,
        answer_count=answer_count,
        cache_status=cache_status,
        latency_ms=latency,
        policy_action=policy_action,
        block_reason=reason,
        protocol=protocol
    )
