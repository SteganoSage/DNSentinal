"""
Clients router: Network device inventory, query metrics, and assigned risk levels.
All values reflect clearly marked DEMO / SAMPLE DATA.
"""

from typing import List
from fastapi import APIRouter
from app.database import get_db_connection
from app.models import ClientDevice

router = APIRouter(prefix="/api", tags=["Clients"])


@router.get("/clients", response_model=List[ClientDevice])
def list_clients():
    """Returns connected network client devices with aggregated DNS query activity and threat risks."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip, hostname, device_type, status, total_queries, blocked_queries, risk_level, last_seen
        FROM clients
        ORDER BY blocked_queries DESC, total_queries DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    return [
        ClientDevice(
            ip=r["ip"],
            hostname=r["hostname"],
            device_type=r["device_type"],
            status=r["status"],
            total_queries=r["total_queries"],
            blocked_queries=r["blocked_queries"],
            risk_level=r["risk_level"],
            last_seen=r["last_seen"],
            is_sample_data=True
        )
        for r in rows
    ]
