"""
Pydantic schemas and models for the DNSentinel Cybersecurity Dashboard API.
All data managed here represents DEMO / SAMPLE DATA for demonstration purposes.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class DNSQueryItem(BaseModel):
    id: int
    timestamp: str
    client_ip: str
    client_name: str
    qname: str
    qtype: str
    rcode: str
    answer_count: int
    cache_status: str
    latency_ms: float
    policy_action: str
    block_reason: Optional[str] = None
    protocol: str


class DNSQueriesResponse(BaseModel):
    total: int
    page: int
    limit: int
    queries: List[DNSQueryItem]


class MetricSummary(BaseModel):
    total_queries: int
    blocked_queries: int
    allowed_queries: int
    cache_hit_ratio: float
    cache_hits: int
    cache_misses: int
    avg_latency_ms: float
    block_rate_percent: float
    active_alerts_count: int
    is_sample_data: bool = True


class ActivityPoint(BaseModel):
    time_label: str
    total: int
    allowed: int
    blocked: int
    cache_hits: int


class ActivityResponse(BaseModel):
    interval: str
    points: List[ActivityPoint]
    is_sample_data: bool = True


class SecurityAlert(BaseModel):
    id: int
    timestamp: str
    domain: str
    client_ip: str
    threat_type: str
    severity: str
    risk_score: float
    description: str
    detection_evidence: List[str]
    status: str
    action_taken: str
    is_sample_data: bool = True


class ClientDevice(BaseModel):
    ip: str
    hostname: str
    device_type: str
    status: str
    total_queries: int
    blocked_queries: int
    risk_level: str
    last_seen: str
    is_sample_data: bool = True


class DemoSettings(BaseModel):
    ml_dga_threshold: float = Field(0.75, ge=0.0, le=1.0)
    tunnel_entropy_threshold: float = Field(4.5, ge=1.0, le=8.0)
    rate_limit_rps: int = Field(100, ge=10, le=1000)
    cache_ttl_seconds: int = Field(300, ge=10, le=86400)
    enable_cname_inspection: bool = True
    enable_0x20_encoding: bool = True
    log_retention_days: int = Field(7, ge=1, le=90)
    demo_mode: bool = True
    notice: str = "These settings modify demo dashboard visualization only. The core resolver config is unchanged."


class SimulateQueryRequest(BaseModel):
    qname: str
    client_ip: Optional[str] = "192.168.1.10"
    client_name: Optional[str] = "Admin Workstation"
    qtype: Optional[str] = "A"
    protocol: Optional[str] = "DoH"
