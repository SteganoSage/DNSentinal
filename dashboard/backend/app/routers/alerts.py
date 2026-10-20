"""
Alerts router: Suspicious domain threat intelligence, feature importance, and mitigations.
All alerts represent DEMO / SAMPLE DATA.
"""

import json
from typing import List
from fastapi import APIRouter, HTTPException
from app.database import get_db_connection
from app.models import SecurityAlert

router = APIRouter(prefix="/api", tags=["Security Alerts"])


@router.get("/alerts", response_model=List[SecurityAlert])
def list_alerts():
    """Returns detected cybersecurity threat alerts with detailed forensic explanations."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, timestamp, domain, client_ip, threat_type, severity, 
               risk_score, description, detection_evidence, status, action_taken
        FROM alerts
        ORDER BY risk_score DESC, timestamp DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for r in rows:
        try:
            evidence_list = json.loads(r["detection_evidence"])
        except Exception:
            evidence_list = [r["detection_evidence"]]

        alerts.append(SecurityAlert(
            id=r["id"],
            timestamp=r["timestamp"],
            domain=r["domain"],
            client_ip=r["client_ip"],
            threat_type=r["threat_type"],
            severity=r["severity"],
            risk_score=r["risk_score"],
            description=r["description"],
            detection_evidence=evidence_list,
            status=r["status"],
            action_taken=r["action_taken"],
            is_sample_data=True
        ))

    return alerts


@router.post("/alerts/{alert_id}/dismiss")
def dismiss_alert(alert_id: int):
    """Marks an alert as dismissed (demo state modification only)."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE alerts SET status = 'Dismissed' WHERE id = ?", (alert_id,))
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    conn.commit()
    conn.close()
    return {"success": True, "message": f"Alert {alert_id} dismissed in demo database."}


@router.post("/alerts/{alert_id}/toggle-mitigate")
def toggle_mitigate_alert(alert_id: int):
    """Toggles alert status between Active and Mitigated (demo state modification only)."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    current_status = row["status"]
    new_status = "Mitigated" if current_status == "Active" else "Active"

    cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
    conn.commit()
    conn.close()

    return {"success": True, "new_status": new_status, "message": f"Alert {alert_id} status updated to {new_status}."}
