"""
Automated End-to-End Test Suite for DNSentinel Dashboard Backend & Frontend serving.
"""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient
from app.main import app

def run_tests():
    print("========================================")
    print(" Running DNSentinel Dashboard Test Suite")
    print("========================================")

    with TestClient(app) as client:
        # 1. Health check
        res = client.get("/api/health")
        assert res.status_code == 200, f"Health check failed: {res.text}"
        print("[PASS] GET /api/health ->", res.json()["status"])

        # 2. Metrics check
        res = client.get("/api/metrics")
        assert res.status_code == 200, f"Metrics failed: {res.text}"
        data = res.json()
        assert data["total_queries"] > 0
        assert data["cache_hit_ratio"] >= 0.0
        assert data["is_sample_data"] is True
        print(f"[PASS] GET /api/metrics -> {data['total_queries']} queries, {data['blocked_queries']} blocked, {data['avg_latency_ms']}ms avg latency")

        # 3. Activity timeline check
        res = client.get("/api/activity")
        assert res.status_code == 200, f"Activity failed: {res.text}"
        points = res.json()["points"]
        assert len(points) > 0
        print(f"[PASS] GET /api/activity -> {len(points)} chart timeline points returned")

        # 4. Queries listing check
        res = client.get("/api/queries?limit=10")
        assert res.status_code == 200, f"Queries failed: {res.text}"
        q_data = res.json()
        assert len(q_data["queries"]) > 0
        print(f"[PASS] GET /api/queries -> {len(q_data['queries'])} queries returned, total: {q_data['total']}")

        # 5. Queries search & filter check
        res = client.get("/api/queries?status=BLOCK")
        assert res.status_code == 200
        for q in res.json()["queries"]:
            assert q["policy_action"] == "BLOCK"
        print("[PASS] GET /api/queries?status=BLOCK -> correctly filtered blocked queries")

        # 6. Simulate new query
        sim_payload = {"qname": "malware-test-botnet.biz", "qtype": "A"}
        res = client.post("/api/queries/simulate", json=sim_payload)
        assert res.status_code == 200, f"Simulate failed: {res.text}"
        sim_data = res.json()
        assert sim_data["policy_action"] == "BLOCK"
        assert "DGA" in sim_data["block_reason"]
        print(f"[PASS] POST /api/queries/simulate -> '{sim_data['qname']}' evaluated as {sim_data['policy_action']} ({sim_data['block_reason']})")

        # 7. Clients check
        res = client.get("/api/clients")
        assert res.status_code == 200, f"Clients failed: {res.text}"
        clients = res.json()
        assert len(clients) > 0
        print(f"[PASS] GET /api/clients -> {len(clients)} network clients returned")

        # 8. Alerts check
        res = client.get("/api/alerts")
        assert res.status_code == 200, f"Alerts failed: {res.text}"
        alerts = res.json()
        assert len(alerts) > 0
        first_alert = alerts[0]
        assert len(first_alert["detection_evidence"]) > 0
        print(f"[PASS] GET /api/alerts -> {len(alerts)} threat alerts with forensic evidence")

        # 9. Alert mitigate toggle check
        alert_id = first_alert["id"]
        res = client.post(f"/api/alerts/{alert_id}/toggle-mitigate")
        assert res.status_code == 200
        print(f"[PASS] POST /api/alerts/{alert_id}/toggle-mitigate -> new status: {res.json()['new_status']}")

        # 10. Settings check
        res = client.get("/api/settings")
        assert res.status_code == 200, f"Settings failed: {res.text}"
        settings = res.json()
        assert settings["demo_mode"] is True
        print(f"[PASS] GET /api/settings -> DGA threshold: {settings['ml_dga_threshold']}, Rate limit: {settings['rate_limit_rps']} rps")

        # 11. Frontend index.html serving check
        res = client.get("/")
        assert res.status_code == 200, f"Frontend serving failed: {res.status_code}"
        assert 'id="root"' in res.text
        assert "DNSentinel" in res.text
        print("[PASS] GET / -> Successfully served React frontend index.html")

    print("========================================")
    print(" ALL 11 TESTS PASSED SUCCESSFULLY! ")
    print("========================================")

if __name__ == "__main__":
    run_tests()
