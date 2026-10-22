"""Sliding-window DNS tunnelling features and an explainable baseline detector."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
import math
import re
from statistics import mean, pvariance
from typing import Iterable, Mapping

from ml.dga.features import registrable_domain


def _registrable_domain(qname: str) -> str:
    """Find the base domain even when capture text contains encoded labels."""
    try:
        return registrable_domain(qname)
    except ValueError:
        labels = qname.strip().lower().rstrip(".").split(".")
        safe_labels = [
            (re.sub(r"[^a-z0-9_-]", "-", label).strip("-") or "x")[:63]
            for label in labels
        ]
        for count in range(2, min(len(safe_labels), 5) + 1):
            try:
                return registrable_domain(".".join(safe_labels[-count:]))
            except ValueError:
                continue
        return registrable_domain(".".join(safe_labels[-2:]))


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _subdomain(qname: str, base: str) -> str:
    name = qname.strip().lower().rstrip(".")
    if name == base:
        return ""
    suffix = "." + base
    if name.endswith(suffix):
        return name[: -len(suffix)]
    return name


def _query_name(qname: str) -> str:
    return qname.strip().lower().rstrip(".")


def _is_nxdomain(rcode: str) -> bool:
    return rcode.upper() in {"NXDOMAIN", "3"}


@dataclass(frozen=True)
class DnsEvent:
    """Normalized event consumed by the slow path."""

    timestamp: float
    client_id: str
    qname: str
    qtype: str = "A"
    rcode: str = "NOERROR"
    response_size: int = 0

    @classmethod
    def from_mapping(cls, event: Mapping[str, object]) -> "DnsEvent":
        client = event.get("client_id", event.get("client_ip"))
        if not isinstance(client, str) or not client:
            raise ValueError("event requires a non-empty client_id or client_ip")
        qname = event.get("qname")
        if not isinstance(qname, str) or not qname:
            raise ValueError("event requires a non-empty qname")
        timestamp = event.get("timestamp")
        if not isinstance(timestamp, (int, float)):
            raise ValueError("event timestamp must be numeric Unix seconds")
        return cls(
            timestamp=float(timestamp),
            client_id=client,
            qname=qname,
            qtype=str(event.get("qtype", "A")).upper(),
            rcode=str(event.get("rcode", "NOERROR")).upper(),
            response_size=max(0, int(event.get("response_size", 0))),
        )


@dataclass(frozen=True)
class TunnelFeatures:
    """Features for one (client, registrable-domain, time-window) tuple."""

    query_count: int
    query_rate_per_second: float
    mean_query_name_length: float
    max_query_name_length: int
    mean_query_label_length: float
    max_query_label_length: int
    mean_query_name_entropy: float
    unique_subdomain_count: int
    unique_subdomain_ratio: float
    mean_subdomain_length: float
    max_subdomain_length: int
    mean_subdomain_entropy: float
    txt_null_cname_mx_ratio: float
    mean_response_size: float
    mean_interquery_seconds: float
    interquery_variance: float
    nxdomain_ratio: float

    @classmethod
    def names(cls) -> list[str]:
        return list(cls.__dataclass_fields__)

    def vector(self) -> list[float]:
        return [float(getattr(self, name)) for name in self.names()]

    def as_dict(self) -> dict[str, float | int]:
        return asdict(self)


@dataclass(frozen=True)
class TunnelVerdict:
    score: float
    label: str
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class NxdomainBurst:
    """Per-client NXDOMAIN activity over one completed time window."""

    client_id: str
    window_end: float
    query_count: int
    nxdomain_count: int
    nxdomain_ratio: float
    nxdomain_rate_per_second: float
    alert: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class NxdomainBurstDetector:
    """Detect client-wide NXDOMAIN bursts across all queried domains."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        step_seconds: float = 10.0,
        min_count: int = 10,
        min_ratio: float = 0.5,
    ) -> None:
        if window_seconds <= 0 or step_seconds <= 0 or step_seconds > window_seconds:
            raise ValueError("window_seconds must be positive and step_seconds must be in (0, window_seconds]")
        if min_count <= 0 or not 0.0 <= min_ratio <= 1.0:
            raise ValueError("min_count must be positive and min_ratio must be between 0 and 1")
        self.window_seconds = window_seconds
        self.step_seconds = step_seconds
        self.min_count = min_count
        self.min_ratio = min_ratio
        self._events: dict[str, deque[DnsEvent]] = defaultdict(deque)
        self._next_emit: dict[str, float] = {}

    def add(self, event: DnsEvent) -> list[NxdomainBurst]:
        queue = self._events[event.client_id]
        queue.append(event)
        cutoff = event.timestamp - self.window_seconds
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()
        next_emit = self._next_emit.setdefault(
            event.client_id, event.timestamp + self.window_seconds
        )
        emitted: list[NxdomainBurst] = []
        while event.timestamp >= next_emit:
            query_count = len(queue)
            nxdomain_count = sum(_is_nxdomain(item.rcode) for item in queue)
            ratio = nxdomain_count / query_count if query_count else 0.0
            emitted.append(NxdomainBurst(
                client_id=event.client_id,
                window_end=next_emit,
                query_count=query_count,
                nxdomain_count=nxdomain_count,
                nxdomain_ratio=ratio,
                nxdomain_rate_per_second=nxdomain_count / self.window_seconds,
                alert=nxdomain_count >= self.min_count and ratio >= self.min_ratio,
            ))
            next_emit += self.step_seconds
        self._next_emit[event.client_id] = next_emit
        return emitted


def extract_features(events: Iterable[DnsEvent], base_domain: str | None = None) -> TunnelFeatures:
    ordered = sorted(events, key=lambda event: event.timestamp)
    if not ordered:
        raise ValueError("cannot extract tunnel features from an empty window")
    base = base_domain or _registrable_domain(ordered[0].qname)
    subdomains = [_subdomain(event.qname, base) for event in ordered]
    lengths = [len(value.replace(".", "")) for value in subdomains]
    entropies = [_entropy(value.replace(".", "")) for value in subdomains]
    query_names = [_query_name(event.qname) for event in ordered]
    query_name_lengths = [len(value.replace(".", "")) for value in query_names]
    query_label_lengths = [
        len(label) for value in query_names for label in value.split(".") if label
    ]
    query_name_entropies = [_entropy(value.replace(".", "")) for value in query_names]
    intervals = [
        later.timestamp - earlier.timestamp
        for earlier, later in zip(ordered, ordered[1:])
        if later.timestamp >= earlier.timestamp
    ]
    tunnel_types = {"TXT", "NULL", "CNAME", "MX"}
    return TunnelFeatures(
        query_count=len(ordered),
        query_rate_per_second=(
            len(ordered) / (ordered[-1].timestamp - ordered[0].timestamp)
            if ordered[-1].timestamp > ordered[0].timestamp
            else 0.0
        ),
        mean_query_name_length=mean(query_name_lengths),
        max_query_name_length=max(query_name_lengths),
        mean_query_label_length=mean(query_label_lengths),
        max_query_label_length=max(query_label_lengths),
        mean_query_name_entropy=mean(query_name_entropies),
        unique_subdomain_count=len(set(subdomains)),
        unique_subdomain_ratio=len(set(subdomains)) / len(ordered),
        mean_subdomain_length=mean(lengths) if lengths else 0.0,
        max_subdomain_length=max(lengths, default=0),
        mean_subdomain_entropy=mean(entropies) if entropies else 0.0,
        txt_null_cname_mx_ratio=sum(event.qtype in tunnel_types for event in ordered) / len(ordered),
        mean_response_size=mean(event.response_size for event in ordered),
        mean_interquery_seconds=mean(intervals) if intervals else 0.0,
        interquery_variance=pvariance(intervals) if len(intervals) > 1 else 0.0,
        nxdomain_ratio=sum(_is_nxdomain(event.rcode) for event in ordered) / len(ordered),
    )


def score_features(features: TunnelFeatures) -> TunnelVerdict:
    """Score obvious tunnel behavior without silently blocking anything."""

    score = 0.0
    reasons: list[str] = []
    if features.query_count >= 30:
        score += 0.20
        reasons.append("high query count")
    if features.unique_subdomain_ratio >= 0.80 and features.query_count >= 10:
        score += 0.25
        reasons.append("mostly unique subdomains")
    if features.mean_subdomain_length >= 20:
        score += 0.15
        reasons.append("long encoded-looking subdomains")
    if features.mean_query_name_entropy >= 3.5:
        score += 0.15
        reasons.append("high query-name entropy")
    if features.txt_null_cname_mx_ratio >= 0.25:
        score += 0.10
        reasons.append("tunnel-favored record types")
    if features.nxdomain_ratio >= 0.30:
        score += 0.10
        reasons.append("high NXDOMAIN ratio")
    if features.mean_response_size >= 200:
        score += 0.05
        reasons.append("large DNS responses")
    score = min(score, 1.0)
    label = "high" if score >= 0.75 else "medium" if score >= 0.45 else "low"
    return TunnelVerdict(score, label, tuple(reasons))


class SlidingWindowDetector:
    """Maintain bounded event state and emit completed feature windows."""

    def __init__(self, window_seconds: float = 60.0, step_seconds: float = 10.0) -> None:
        if window_seconds <= 0 or step_seconds <= 0 or step_seconds > window_seconds:
            raise ValueError("window_seconds must be positive and step_seconds must be in (0, window_seconds]")
        self.window_seconds = window_seconds
        self.step_seconds = step_seconds
        self._events: dict[tuple[str, str], deque[DnsEvent]] = defaultdict(deque)
        self._next_emit: dict[tuple[str, str], float] = {}

    def add(self, event: DnsEvent) -> list[tuple[str, str, float, TunnelFeatures, TunnelVerdict]]:
        base = _registrable_domain(event.qname)
        key = (event.client_id, base)
        queue = self._events[key]
        queue.append(event)
        cutoff = event.timestamp - self.window_seconds
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()
        next_emit = self._next_emit.setdefault(key, event.timestamp + self.window_seconds)
        emitted: list[tuple[str, str, float, TunnelFeatures, TunnelVerdict]] = []
        while event.timestamp >= next_emit:
            features = extract_features(queue, base)
            emitted.append((event.client_id, base, next_emit, features, score_features(features)))
            next_emit += self.step_seconds
        self._next_emit[key] = next_emit
        return emitted
