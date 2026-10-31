"""The DNS tunnel detector (README §7.8.3) and the NXDOMAIN-burst signal (§7.8.4).

The unit is one (client, registrable domain) over a window of the last 60 s,
judged every 10 s. Training (ml/tunnel) feeds captured queries through the
same SlidingWindowDetector the analyzer feeds live ones through, so a model
is trained on exactly the windows it will be asked about.

Windows end on a fixed grid (every step_seconds since the epoch) and hold
the key's queries in (end - window_seconds, end]. A key is judged at a
window end only if it had a new query since it was last judged: a key gone
quiet has nothing new to say, and an idle key costs nothing. A key's first
judgement comes at most step_seconds after its first query.

Names are in the resolver's text form (Name::to_string: lower case, \\DDD
and \\. escapes); the features decode them back to the label bytes that
were on the wire, so escaping doesn't inflate lengths.
"""

from __future__ import annotations

import math
import re
from collections import Counter, OrderedDict, defaultdict, deque
from dataclasses import asdict, dataclass, fields
from typing import Callable, Iterable, Mapping

from ml.dga.psl import default_list
from ml.tunnel.pcap import text_name

WINDOW_SECONDS = 60.0
STEP_SECONDS = 10.0

# What browsers and operating systems ask for; the rest (TXT, NULL, CNAME,
# MX, SRV, KEY, private types...) carries more data back, which tunnels want.
COMMON_TYPES = frozenset({"A", "AAAA", "HTTPS", "SVCB", "PTR", "SOA", "NS", "DS", "DNSKEY", "CAA"})
NO_RESPONSE = "NONE"  # a captured query whose response wasn't captured (ml/tunnel/pcap.py)

_HOSTNAME_LABEL = re.compile(rb"[a-z0-9_-]+")
_PSL_LABELS = 8  # more than the longest Public Suffix List rule, plus the registrable label


# ─── Names ──────────────────────────────────────────────────────────────────


def labels_of(qname: str) -> list[bytes]:
    """The wire labels of a name in text form: escapes decoded, ASCII lower case."""
    if "\\" not in qname:
        return [label for label in qname.lower().encode("utf-8").split(b".") if label]
    labels, label, i = [], bytearray(), 0
    while i < len(qname):
        char = qname[i]
        digits = qname[i + 1:i + 4]
        if char == "\\" and len(digits) == 3 and digits.isdigit():
            label.append(int(digits) & 0xFF)
            i += 4
            continue
        if char == "\\" and i + 1 < len(qname):
            label.extend(qname[i + 1].encode("utf-8"))
            i += 2
            continue
        if char == ".":
            if label:
                labels.append(bytes(label).lower())
            label = bytearray()
        else:
            label.extend(char.encode("utf-8"))
        i += 1
    if label:
        labels.append(bytes(label).lower())
    return labels


def _registrable_count(labels: list[bytes]) -> int:
    """How many labels, from the right, make the registrable domain (eTLD+1)."""
    tail = labels[-_PSL_LABELS:]
    # A label that can't be a hostname can't match a suffix rule either (a wildcard matches anything).
    safe = ".".join(label.decode("ascii") if _HOSTNAME_LABEL.fullmatch(label) else "x" for label in tail)
    found = default_list().registrable_domain(safe)
    return found.count(".") + 1 if found else len(tail)


def registrable_domain(qname: str) -> str:
    """The name's registrable domain in text form; the name itself if it is a public suffix."""
    labels = labels_of(qname)
    return text_name(labels[-_registrable_count(labels):]) if labels else ""


# ─── Events ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DnsEvent:
    """One query and its answer, as the slow path receives it."""

    timestamp: float
    client_id: str
    qname: str
    qtype: str = "A"
    rcode: str = "NOERROR"
    response_size: int = 0

    @classmethod
    def from_mapping(cls, event: Mapping[str, object]) -> "DnsEvent":
        client = event.get("client_id", event.get("client_ip", event.get("client")))
        if not isinstance(client, str) or not client:
            raise ValueError("event requires a non-empty client_id or client_ip")
        qname = event.get("qname")
        if not isinstance(qname, str) or not qname:
            raise ValueError("event requires a non-empty qname")
        timestamp = event.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = float(timestamp)
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


def _is_nxdomain(rcode: str) -> bool:
    return rcode.upper() in {"NXDOMAIN", "3"}


@dataclass(frozen=True, slots=True)
class _NameStats:
    """What the features need from one query, computed once however many windows it is in."""

    subdomain: bytes  # the labels left of the registrable domain, joined by dots
    length: int       # their bytes, without the dots
    labels: tuple[int, ...]  # each one's length
    entropy: float
    digits: int
    unusual: int      # bytes a hostname can't have (outside a-z 0-9 - _)
    counts: Counter


def _entropy(counts: Counter, total: int) -> float:
    if not total:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _name_stats(labels: list[bytes], keep: int) -> _NameStats:
    below = labels[:keep] if keep > 0 else []
    data = b"".join(below)
    counts = Counter(data)
    digits = sum(count for byte, count in counts.items() if 0x30 <= byte <= 0x39)
    usual = sum(count for byte, count in counts.items()
                if 0x61 <= byte <= 0x7A or 0x30 <= byte <= 0x39 or byte in (0x2D, 0x5F))
    return _NameStats(b".".join(below), len(data), tuple(len(label) for label in below),
                      _entropy(counts, len(data)), digits, len(data) - usual, counts)


def _stats_for(qname: str, base: str | None = None) -> tuple[str, _NameStats]:
    labels = labels_of(qname)
    if base is None:
        count = _registrable_count(labels) if labels else 0
        base = text_name(labels[-count:]) if count else ""
    else:
        count = len(labels_of(base))
    return base, _name_stats(labels, len(labels) - count)


# ─── Features ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TunnelFeatures:
    """Features of one (client, registrable domain, window)."""

    # V, volume and timing
    query_count: int
    active_seconds: float          # first to last query in the window
    mean_interval: float           # between consecutive queries
    interval_cv: float             # their standard deviation over their mean: tunnels poll steadily
    # N, the names below the registrable domain (the subdomain: where tunnels put their data)
    unique_subdomain_count: int
    unique_subdomain_ratio: float
    mean_subdomain_length: float
    max_subdomain_length: int
    mean_label_length: float
    max_label_length: int
    mean_subdomain_labels: float
    mean_subdomain_entropy: float  # Shannon entropy of each subdomain, averaged
    pooled_entropy: float          # of all the window's subdomain bytes together: base32 ~5 bits, words ~4
    distinct_characters: int       # hex has 16, base32 32, base64 and binary encodings more
    digit_ratio: float
    unusual_character_ratio: float
    # R, record types and responses
    data_type_ratio: float         # queries for a type outside COMMON_TYPES
    mean_response_size: float      # of the answered queries
    max_response_size: int
    nxdomain_ratio: float

    @classmethod
    def names(cls) -> list[str]:
        return [f.name for f in fields(cls)]

    def vector(self) -> list[float]:
        return [float(getattr(self, name)) for name in self.names()]

    def as_dict(self) -> dict[str, float | int]:
        return asdict(self)


FEATURE_GROUPS = {
    "V": ["query_count", "active_seconds", "mean_interval", "interval_cv"],
    "N": ["unique_subdomain_count", "unique_subdomain_ratio", "mean_subdomain_length", "max_subdomain_length",
          "mean_label_length", "max_label_length", "mean_subdomain_labels", "mean_subdomain_entropy",
          "pooled_entropy", "distinct_characters", "digit_ratio", "unusual_character_ratio"],
    "R": ["data_type_ratio", "mean_response_size", "max_response_size", "nxdomain_ratio"],
}
assert [n for group in FEATURE_GROUPS.values() for n in group] == TunnelFeatures.names()


def _aggregate(window: list[tuple[DnsEvent, _NameStats]]) -> TunnelFeatures:
    window = sorted(window, key=lambda item: item[0].timestamp)
    n = len(window)
    times = [event.timestamp for event, _ in window]
    intervals = [later - earlier for earlier, later in zip(times, times[1:])]
    mean_interval = sum(intervals) / len(intervals) if intervals else 0.0
    if len(intervals) > 1 and mean_interval > 0:
        variance = sum((gap - mean_interval) ** 2 for gap in intervals) / len(intervals)
        interval_cv = math.sqrt(variance) / mean_interval
    else:
        interval_cv = 0.0
    stats = [s for _, s in window]
    lengths = [s.length for s in stats]
    label_lengths = [length for s in stats for length in s.labels]
    pooled: Counter = Counter()
    for s in stats:
        pooled.update(s.counts)
    total = sum(lengths)
    answered = [event.response_size for event, _ in window if event.rcode != NO_RESPONSE]
    return TunnelFeatures(
        query_count=n,
        active_seconds=times[-1] - times[0],
        mean_interval=mean_interval,
        interval_cv=interval_cv,
        unique_subdomain_count=len({s.subdomain for s in stats}),
        unique_subdomain_ratio=len({s.subdomain for s in stats}) / n,
        mean_subdomain_length=total / n,
        max_subdomain_length=max(lengths),
        mean_label_length=sum(label_lengths) / len(label_lengths) if label_lengths else 0.0,
        max_label_length=max(label_lengths, default=0),
        mean_subdomain_labels=len(label_lengths) / n,
        mean_subdomain_entropy=sum(s.entropy for s in stats) / n,
        pooled_entropy=_entropy(pooled, total),
        distinct_characters=len(pooled),
        digit_ratio=sum(s.digits for s in stats) / total if total else 0.0,
        unusual_character_ratio=sum(s.unusual for s in stats) / total if total else 0.0,
        data_type_ratio=sum(event.qtype not in COMMON_TYPES for event, _ in window) / n,
        mean_response_size=sum(answered) / len(answered) if answered else 0.0,
        max_response_size=max(answered, default=0),
        nxdomain_ratio=sum(_is_nxdomain(event.rcode) for event, _ in window) / n,
    )


def extract_features(events: Iterable[DnsEvent], base_domain: str | None = None) -> TunnelFeatures:
    """The features of one window: these queries, all to base_domain (by default the first one's)."""
    events = list(events)
    if not events:
        raise ValueError("cannot extract tunnel features from an empty window")
    base = base_domain or registrable_domain(events[0].qname)
    return _aggregate([(event, _stats_for(event.qname, base)[1]) for event in events])


@dataclass(frozen=True)
class TunnelVerdict:
    score: float
    label: str
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def score_features(features: TunnelFeatures) -> TunnelVerdict:
    """The hand-written baseline: score obvious tunnel behaviour, explainably."""
    score = 0.0
    reasons: list[str] = []
    for hit, weight, reason in (
        (features.query_count >= 30, 0.20, "high query count"),
        (features.unique_subdomain_ratio >= 0.80 and features.query_count >= 10, 0.25, "mostly unique subdomains"),
        (features.mean_subdomain_length >= 20, 0.15, "long encoded-looking subdomains"),
        (features.mean_subdomain_entropy >= 3.5, 0.15, "high subdomain entropy"),
        (features.data_type_ratio >= 0.25, 0.10, "tunnel-favoured record types"),
        (features.nxdomain_ratio >= 0.30, 0.10, "high NXDOMAIN ratio"),
        (features.mean_response_size >= 200, 0.05, "large DNS responses"),
    ):
        if hit:
            score += weight
            reasons.append(reason)
    score = min(round(score, 6), 1.0)
    label = "high" if score >= 0.75 else "medium" if score >= 0.45 else "low"
    return TunnelVerdict(score, label, tuple(reasons))


# ─── Sliding windows ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TunnelWindow:
    client_id: str
    domain: str
    end: float
    features: TunnelFeatures
    verdict: TunnelVerdict | None


class _Key:
    __slots__ = ("events", "last")

    def __init__(self) -> None:
        self.events: deque[tuple[DnsEvent, _NameStats]] = deque()
        self.last = 0.0


class SlidingWindowDetector:
    """Bounded state per (client, registrable domain); emits each judged window.

    Feed events in time order. flush() judges what is pending: call it at the
    end of input, or as the clock passes a window end with no new query.
    """

    def __init__(
        self,
        window_seconds: float = WINDOW_SECONDS,
        step_seconds: float = STEP_SECONDS,
        scorer: Callable[[TunnelFeatures], TunnelVerdict] | None = score_features,
    ) -> None:
        if window_seconds <= 0 or step_seconds <= 0 or step_seconds > window_seconds:
            raise ValueError("window_seconds must be positive and step_seconds must be in (0, window_seconds]")
        self.window_seconds = window_seconds
        self.step_seconds = step_seconds
        self.scorer = scorer
        self._keys: OrderedDict[tuple[str, str], _Key] = OrderedDict()  # least recently queried first
        self._pending: dict[tuple[str, str], None] = {}  # keys with a query since they were last judged
        self._end: float | None = None  # the window end the pending queries belong to

    def add(self, event: DnsEvent) -> list[TunnelWindow]:
        emitted = self.flush(event.timestamp) if self._end is not None and event.timestamp > self._end else []
        if self._end is None:
            self._end = math.ceil(event.timestamp / self.step_seconds) * self.step_seconds
        base, stats = _stats_for(event.qname)
        key = (event.client_id, base)
        state = self._keys.get(key)
        if state is None:
            state = self._keys[key] = _Key()
        else:
            self._keys.move_to_end(key)
        state.events.append((event, stats))
        state.last = max(state.last, event.timestamp)
        self._pending[key] = None
        return emitted

    def flush(self, now: float | None = None) -> list[TunnelWindow]:
        """Judge the pending keys if `now` (default: the end of input) is past their window's end."""
        if self._end is None or (now is not None and now <= self._end):
            return []
        end, cutoff = self._end, self._end - self.window_seconds
        emitted = []
        for key in self._pending:
            state = self._keys[key]
            while state.events and state.events[0][0].timestamp <= cutoff:
                state.events.popleft()
            features = _aggregate(list(state.events))
            verdict = self.scorer(features) if self.scorer else None
            emitted.append(TunnelWindow(key[0], key[1], end, features, verdict))
        self._pending.clear()
        self._end = None if now is None else math.ceil(now / self.step_seconds) * self.step_seconds
        horizon = cutoff if self._end is None else self._end - self.window_seconds
        while self._keys:  # forget keys with no query a later window could hold
            key, state = next(iter(self._keys.items()))
            if state.last > horizon:
                break
            del self._keys[key]
        return emitted


def windows(events: Iterable[DnsEvent], window_seconds: float = WINDOW_SECONDS,
            step_seconds: float = STEP_SECONDS) -> list[TunnelWindow]:
    """Every window the detector would judge over these (time-ordered) events, unscored."""
    detector = SlidingWindowDetector(window_seconds, step_seconds, scorer=None)
    out = []
    for event in events:
        out.extend(detector.add(event))
    out.extend(detector.flush())
    return out


# ─── NXDOMAIN bursts ────────────────────────────────────────────────────────


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
