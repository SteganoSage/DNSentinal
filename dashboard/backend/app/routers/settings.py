"""
Settings router: Demo configuration knobs for the cybersecurity dashboard.
Safety Guarantee: Updates made here ONLY persist in the demo SQLite database.
The real C++ resolver configuration (config/dnsentinel.yaml) is never touched.
"""

from fastapi import APIRouter
from app.database import get_db_connection
from app.models import DemoSettings
from app.sample_data import seed_sample_data

router = APIRouter(prefix="/api", tags=["Settings"])


@router.get("/settings", response_model=DemoSettings)
def get_settings():
    """Returns the current demo dashboard configuration settings."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT key, value FROM demo_settings")
    rows = cursor.fetchall()
    conn.close()

    settings_dict = {r["key"]: r["value"] for r in rows}

    return DemoSettings(
        ml_dga_threshold=float(settings_dict.get("ml_dga_threshold", 0.75)),
        tunnel_entropy_threshold=float(settings_dict.get("tunnel_entropy_threshold", 4.5)),
        rate_limit_rps=int(settings_dict.get("rate_limit_rps", 100)),
        cache_ttl_seconds=int(settings_dict.get("cache_ttl_seconds", 300)),
        enable_cname_inspection=settings_dict.get("enable_cname_inspection", "true").lower() == "true",
        enable_0x20_encoding=settings_dict.get("enable_0x20_encoding", "true").lower() == "true",
        log_retention_days=int(settings_dict.get("log_retention_days", 7)),
        demo_mode=True,
        notice="Safety: These settings update SQLite demo metrics only. The actual C++ resolver configuration remains untouched."
    )


@router.put("/settings", response_model=DemoSettings)
def update_settings(new_settings: DemoSettings):
    """
    Updates demo dashboard settings in the SQLite database.
    Does NOT modify the real resolver configuration.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    pairs = [
        ("ml_dga_threshold", str(new_settings.ml_dga_threshold)),
        ("tunnel_entropy_threshold", str(new_settings.tunnel_entropy_threshold)),
        ("rate_limit_rps", str(new_settings.rate_limit_rps)),
        ("cache_ttl_seconds", str(new_settings.cache_ttl_seconds)),
        ("enable_cname_inspection", str(new_settings.enable_cname_inspection).lower()),
        ("enable_0x20_encoding", str(new_settings.enable_0x20_encoding).lower()),
        ("log_retention_days", str(new_settings.log_retention_days)),
        ("demo_mode", "true")
    ]

    cursor.executemany("INSERT OR REPLACE INTO demo_settings (key, value) VALUES (?, ?)", pairs)
    conn.commit()
    conn.close()

    return get_settings()


@router.post("/settings/reset-demo-data")
def reset_demo_data():
    """Resets the demo queries, clients, and alerts back to their initial default sample state."""
    seed_sample_data(force=True)
    return {
        "success": True,
        "message": "Demo sample dataset reset to defaults successfully."
    }
