"""The slow path, live (README §6.2): read the resolver's event stream, run the
tunnel detector and the NXDOMAIN-burst signal on it, fuse them with the DGA
scores the events carry (analyzer/fusion.py, README §7.8.5), report alerts, and
in enforce mode ask the policy engine for time-limited block rules (§7.6.6).

    python -m analyzer.live                                   # the rules, alerts only
    python -m analyzer.live --model models/tunnel --enforce   # the trained model; block what it alerts on

The resolver publishes one JSON line per answered query on a Unix socket
(telemetry.events in config/dnsentinel.yaml) and takes commands on the same
socket.

**High risk** for a (client, registrable domain), alerted on and blocked in enforce mode:
- the model's consecutive `high` windows (two by default);
- a DGA-flagged domain that resolved while its client is in an NXDOMAIN burst: the
  command server DGA malware found.

In enforce mode it becomes {"op":"add_rule","domain":...,"client":...,"ttl":...}
for that client only, renewed while the alerts go on and left to expire when they
stop.

Popular sites are never alerted on: the Tranco top 100k (--allowlist, the resolver's
ml.dga.allowlist by default), and names a CDN assigns (PROVIDER_SUFFIXES, as the
resolver's ml.dga.provider_suffixes). A tunnel needs its own domain's name servers, which
a popular site's aren't. Wildcard DNS under popular sites (random names, each answered)
otherwise looks like one.

NXDOMAIN bursts are client-wide, not about one domain, so they are only
reported. Every alert is a JSON line on stdout (or --alerts FILE).
"""

from __future__ import annotations

import argparse
import json
import select
import socket
import sys
import time
from pathlib import Path
from typing import Callable, TextIO

from .detectors.tunnel import (
    STEP_SECONDS,
    WINDOW_SECONDS,
    DnsEvent,
    NxdomainBurst,
    NxdomainBurstDetector,
    SlidingWindowDetector,
    TunnelWindow,
    registrable_domain,
)
from .fusion import FusionPolicy, Signals, fuse
from .tunnel_analyzer import ALERT_AFTER, AlertRule

DEFAULT_SOCKET = "/tmp/dnsentinel/events.sock"
ROOT = Path(__file__).resolve().parents[1]
DGA_MODEL = ROOT / "models" / "dga" / "model.json"
ALLOWLIST = ROOT / "config" / "lists" / "feeds" / "tranco_top100k.txt"  # config/lists/download_feeds.sh
PROVIDER_SUFFIXES = frozenset({"cloudfront.net", "cloudapp.net", "global.ssl.fastly.net"})
IGNORED_ACTIONS = {"refused", "rejected", "rate_limited"}  # not answered: nothing to learn from them
REPORT_AGAIN = 600.0  # seconds before a client's burst is reported again


def read_allowlist(path: Path) -> frozenset[str]:
    """Popular domains, "rank,domain" or one per line ("#" comments), as the resolver reads them."""
    domains = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            domains.add(line.rsplit(",", 1)[-1].strip().lower().rstrip("."))
    return frozenset(d for d in domains if d)


def default_fusion() -> FusionPolicy:
    """The DGA threshold the resolver uses (models/dga), so "flagged" means the same on both paths."""
    try:
        return FusionPolicy(dga_threshold=float(json.loads(DGA_MODEL.read_text())["threshold"]))
    except (OSError, KeyError, ValueError):
        return FusionPolicy()


class LiveAnalyzer:
    """The decisions, without the I/O: events in; alerts and rule commands out."""

    def __init__(self, model: Path | None = None, enforce: bool = False, rule_ttl: int = 3600,
                 alert_after: int | None = None, nxdomain_min_count: int = 10, nxdomain_min_ratio: float = 0.5,
                 clock: Callable[[], float] = time.time, fusion: FusionPolicy | None = None,
                 allowlist: frozenset[str] = frozenset(), provider_suffixes: frozenset[str] = PROVIDER_SUFFIXES) -> None:
        if model is not None:
            from ml.tunnel.scorer import TunnelModel

            trained = TunnelModel(model)
            self.detector = SlidingWindowDetector(trained.window_seconds, trained.step_seconds, scorer=trained.verdict)
            self.alert = AlertRule(alert_after or trained.alert_after)
            self.judge = "model " + str(model)
        else:
            self.detector = SlidingWindowDetector(WINDOW_SECONDS, STEP_SECONDS)
            self.alert = AlertRule(alert_after or ALERT_AFTER)
            self.judge = "hand-written rules"
        self.bursts = NxdomainBurstDetector(self.detector.window_seconds, self.detector.step_seconds,
                                            nxdomain_min_count, nxdomain_min_ratio)
        self.enforce = enforce
        self.rule_ttl = rule_ttl
        self.clock = clock
        self.fusion = fusion or default_fusion()
        self.allowlist, self.provider_suffixes = allowlist, provider_suffixes
        self._rules: dict[tuple[str, str], float] = {}  # (client, domain) -> when our rule for it expires
        self._burst_reported: dict[str, float] = {}     # client -> when its last burst was reported
        self._dga: dict[tuple[str, str], float] = {}    # (client, domain) -> the DGA score the resolver gave it
        self._resolved: dict[tuple[str, str], float] = {}  # (client, domain) -> when it last answered
        self._last_prune = 0.0
        self.counts = {"events": 0, "windows": 0, "popular_windows": 0, "tunnel_alerts": 0, "dga_c2_alerts": 0,
                       "burst_alerts": 0, "rules_asked": 0, "dropped": 0}

    def feed(self, record: dict) -> tuple[list[dict], list[dict]]:
        """One line from the stream: (alerts, commands to send)."""
        kind = record.get("type")
        if kind == "dropped":
            self.counts["dropped"] += int(record.get("count", 0))
            return [{"alert": "events_lost", "count": record.get("count"),
                     "note": "this analyzer fell behind the resolver; events were dropped"}], []
        if kind != "query" or record.get("action") in IGNORED_ACTIONS:
            return [], []
        try:
            event = DnsEvent.from_mapping(record)
        except (ValueError, TypeError):
            return [], []
        self.counts["events"] += 1
        key = (event.client_id, registrable_domain(event.qname))
        if isinstance(record.get("dga"), (int, float)):
            self._dga[key] = float(record["dga"])  # one score per registrable domain: the latest will do
        answers = record.get("answers")
        if event.rcode == "NOERROR" and isinstance(answers, int) and answers > 0:
            self._resolved[key] = event.timestamp
        alerts, commands = [], []
        for window in self.detector.add(event):  # first: the windows end before this query, as the bursts' must
            self._judge(window, alerts, commands)
        self._bursts(self.bursts.add(event), alerts)
        return alerts, commands

    def tick(self, now: float | None = None) -> tuple[list[dict], list[dict]]:
        """Judge the windows that ended while no query came (call every second or so)."""
        now = now if now is not None else self.clock()
        alerts, commands = [], []
        for window in self.detector.flush(now):  # first: flushing the bursts forgets old queries
            self._judge(window, alerts, commands)
        self._bursts(self.bursts.flush(now), alerts)  # a quiet client's burst is reported too
        if now - self._last_prune > self.detector.window_seconds:
            self._prune(now)
        return alerts, commands

    def _bursts(self, bursts: list[NxdomainBurst], alerts: list[dict]) -> None:
        for burst in bursts:
            if burst.alert and burst.window_end - self._burst_reported.get(burst.client_id, -1e18) > REPORT_AGAIN:
                self._burst_reported[burst.client_id] = burst.window_end
                self.counts["burst_alerts"] += 1
                alerts.append({**burst.as_dict(), "alert": "nxdomain_burst"})  # its own `alert` is just True

    def _prune(self, now: float) -> None:
        """Forget what no window will ask about again."""
        self._last_prune = now
        horizon = now - 2 * self.detector.window_seconds
        self._resolved = {k: t for k, t in self._resolved.items() if t >= horizon}
        live = {key for key in self._resolved} | set(self.detector.keys())
        self._dga = {k: v for k, v in self._dga.items() if k in live}

    def popular(self, domain: str) -> bool:
        return domain in self.allowlist or domain.split(".", 1)[-1] in self.provider_suffixes

    def _judge(self, window: TunnelWindow, alerts: list[dict], commands: list[dict]) -> None:
        self.counts["windows"] += 1
        if self.popular(window.domain):
            self.counts["popular_windows"] += 1
            return
        key = (window.client_id, window.domain)
        verdict = window.verdict
        signals = Signals(
            tunnel_alert=self.alert(window),
            tunnel_score=verdict.score if verdict else None,
            dga=self._dga.get(key),
            burst=self.bursts.active(window.client_id, window.end),
            resolved=self._resolved.get(key, -1e18) >= window.end - self.detector.window_seconds,
        )
        risk = fuse(signals, self.fusion)
        if risk.level != "high":
            return
        self.counts["tunnel_alerts" if risk.kind == "tunnel" else "dga_c2_alerts"] += 1
        score = verdict.score if risk.kind == "tunnel" and verdict else signals.dga or 0.0
        alert = {"alert": risk.kind, "client": window.client_id, "domain": window.domain, "window_end": window.end,
                 "score": score,
                 "reasons": (list(verdict.reasons) if risk.kind == "tunnel" and verdict else []) + list(risk.reasons),
                 "features": window.features.as_dict(), "risk": risk.as_dict(), "action": "alert"}
        if self.enforce:
            now = self.clock()
            # ask again only when our rule is past half its life: renewing it, not flooding the resolver
            if self._rules.get(key, 0) - now < self.rule_ttl / 2:
                self._rules[key] = now + self.rule_ttl
                self.counts["rules_asked"] += 1
                commands.append({"op": "add_rule", "domain": window.domain, "client": window.client_id,
                                 "ttl": self.rule_ttl, "reason": risk.kind, "score": round(score, 4),
                                 "source": "analyzer.live"})
                alert["action"] = "block"
            else:
                alert["action"] = "blocked already"
        alerts.append(alert)


class Stream:
    """The resolver's event socket: lines in, command lines out."""

    def __init__(self, path: str, retry: float = 2.0, log: Callable[[str], None] = lambda message: None) -> None:
        self.path, self.retry, self.log = path, retry, log
        self.sock: socket.socket | None = None
        self.buffer = b""

    def connect(self) -> None:
        while True:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self.path)
                self.sock, self.buffer = sock, b""
                self.log(f"connected to {self.path}")
                return
            except OSError as error:
                self.log(f"cannot connect to {self.path} ({error.strerror}); retrying in {self.retry:g} s")
                time.sleep(self.retry)

    def lines(self, timeout: float) -> list[dict]:
        """What arrived within `timeout` s: whole lines, parsed. Reconnects if the resolver went away."""
        assert self.sock is not None
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if not ready:
            return []
        chunk = self.sock.recv(1 << 16)
        if not chunk:
            self.log("the resolver closed the stream")
            self.sock.close()
            self.connect()
            return []
        self.buffer += chunk
        *complete, self.buffer = self.buffer.split(b"\n")
        records = []
        for line in complete:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                self.log(f"not JSON, skipped: {line[:80]!r}")
        return records

    def send(self, command: dict) -> None:
        assert self.sock is not None
        self.sock.sendall((json.dumps(command, separators=(",", ":")) + "\n").encode())

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None


def run(stream: Stream, analyzer: LiveAnalyzer, out: TextIO, log: Callable[[str], None],
        stop: Callable[[], bool] = lambda: False) -> None:
    """Read events until `stop()` says so (or forever)."""
    stream.connect()
    try:
        _read(stream, analyzer, out, log, stop)
    finally:
        stream.close()


def _read(stream: Stream, analyzer: LiveAnalyzer, out: TextIO, log: Callable[[str], None],
          stop: Callable[[], bool]) -> None:
    last_tick = 0.0
    while not stop():
        for record in stream.lines(timeout=1.0):
            if record.get("type") == "reply":
                if not record.get("ok"):
                    log(f"the resolver refused {record.get('op')}: {record.get('error')}")
                elif record.get("op") == "add_rule":
                    log(f"rule {record.get('id')} in force for {record.get('ttl')} s"
                        + (" (renewed)" if record.get("renewed") else ""))
                continue
            alerts, commands = analyzer.feed(record)
            _emit(alerts, commands, stream, out)
        if time.monotonic() - last_tick >= 1.0:
            last_tick = time.monotonic()
            _emit(*analyzer.tick(), stream, out)


def _emit(alerts: list[dict], commands: list[dict], stream: Stream, out: TextIO) -> None:
    for alert in alerts:
        out.write(json.dumps(alert, sort_keys=True) + "\n")
    out.flush()
    for command in commands:
        stream.send(command)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--socket", default=DEFAULT_SOCKET, help="telemetry.events.socket in the resolver's config")
    parser.add_argument("--model", type=Path, help="a trained model folder (ml/tunnel pipeline, final mode); "
                                                   "default: the hand-written rules")
    parser.add_argument("--enforce", action="store_true",
                        help="ask the resolver to block (client, domain) pairs the detector alerts on")
    parser.add_argument("--rule-ttl", type=int, default=3600,
                        help="seconds a block rule lasts (renewed while the alerts go on)")
    parser.add_argument("--alert-after", type=int, help="consecutive high windows for an alert (default: the model's)")
    parser.add_argument("--nxdomain-min-count", type=int, default=10)
    parser.add_argument("--nxdomain-min-ratio", type=float, default=0.5)
    parser.add_argument("--dga-threshold", type=float,
                        help="DGA scores at least this are flagged (default: models/dga's, as the resolver)")
    parser.add_argument("--alerts", type=Path, help="write alerts here (JSON lines) instead of stdout")
    parser.add_argument("--allowlist", type=Path, default=ALLOWLIST,
                        help="popular domains, never alerted on (default: the resolver's, %(default)s); "
                             "'none': judge every domain")
    args = parser.parse_args()

    def log(message: str) -> None:
        print(f"analyzer: {message}", file=sys.stderr, flush=True)

    fusion = FusionPolicy(dga_threshold=args.dga_threshold or default_fusion().dga_threshold)
    allowlist: frozenset[str] = frozenset()
    if str(args.allowlist) != "none":
        try:
            allowlist = read_allowlist(args.allowlist)
        except OSError as error:
            if args.allowlist != ALLOWLIST:
                log(f"cannot read {args.allowlist}: {error.strerror}")
                return 1
            log(f"warning: no allowlist ({ALLOWLIST} missing: config/lists/download_feeds.sh gets it); "
                "popular domains under wildcard DNS can be alerted on")
    analyzer = LiveAnalyzer(args.model, args.enforce, args.rule_ttl, args.alert_after, args.nxdomain_min_count,
                            args.nxdomain_min_ratio, fusion=fusion, allowlist=allowlist)
    mode = f"enforce: alerts become block rules for {args.rule_ttl} s" if args.enforce else "monitor: alerts only"
    log(f"judging with the {analyzer.judge}; alerts after {analyzer.alert.after} consecutive high windows; "
        f"DGA scores flagged from {fusion.dga_threshold:.4f}; {len(allowlist):,} popular domains never alerted on; "
        f"{mode}")
    out = open(args.alerts, "a", encoding="utf-8") if args.alerts else sys.stdout
    try:
        run(Stream(args.socket, log=log), analyzer, out, log)
    except KeyboardInterrupt:
        pass
    finally:
        log("since startup: " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in analyzer.counts.items()))
        if args.alerts:
            out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
