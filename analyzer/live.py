"""The slow path, live (README §6.2): read the resolver's event stream, run the
tunnel detector and the NXDOMAIN-burst signal on it, report alerts, and in
enforce mode ask the policy engine for time-limited block rules (§7.6.6).

    python -m analyzer.live                                   # the rules, alerts only
    python -m analyzer.live --model models/tunnel --enforce   # the trained model; block what it alerts on

The resolver publishes one JSON line per answered query on a Unix socket
(telemetry.events in config/dnsentinel.yaml) and takes commands on the same
socket. An alert on a (client, registrable domain) needs the model's
consecutive `high` windows (two by default); in enforce mode it becomes
{"op":"add_rule","domain":...,"client":...,"ttl":...} for that client only,
renewed while the alerts go on and left to expire when they stop. NXDOMAIN
bursts are client-wide, not about one domain, so they are only reported.
Every alert is a JSON line on stdout (or --alerts FILE).
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
    NxdomainBurstDetector,
    SlidingWindowDetector,
    TunnelWindow,
)
from .tunnel_analyzer import ALERT_AFTER, AlertRule

DEFAULT_SOCKET = "/tmp/dnsentinel/events.sock"
IGNORED_ACTIONS = {"refused", "rejected", "rate_limited"}  # not answered: nothing to learn from them


class LiveAnalyzer:
    """The decisions, without the I/O: events in; alerts and rule commands out."""

    def __init__(self, model: Path | None = None, enforce: bool = False, rule_ttl: int = 3600,
                 alert_after: int | None = None, nxdomain_min_count: int = 10, nxdomain_min_ratio: float = 0.5,
                 clock: Callable[[], float] = time.time) -> None:
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
        self._rules: dict[tuple[str, str], float] = {}  # (client, domain) -> when our rule for it expires
        self._burst_reported: dict[str, float] = {}     # client -> when its last burst was reported
        self.counts = {"events": 0, "windows": 0, "tunnel_alerts": 0, "burst_alerts": 0, "rules_asked": 0,
                       "dropped": 0}

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
        alerts, commands = [], []
        for burst in self.bursts.add(event):
            if burst.alert and event.timestamp - self._burst_reported.get(burst.client_id, -1e18) > 600:
                self._burst_reported[burst.client_id] = event.timestamp
                self.counts["burst_alerts"] += 1
                alerts.append({**burst.as_dict(), "alert": "nxdomain_burst"})  # its own `alert` is just True
        for window in self.detector.add(event):
            self._judge(window, alerts, commands)
        return alerts, commands

    def tick(self, now: float | None = None) -> tuple[list[dict], list[dict]]:
        """Judge the windows that ended while no query came (call every second or so)."""
        alerts, commands = [], []
        for window in self.detector.flush(now if now is not None else self.clock()):
            self._judge(window, alerts, commands)
        return alerts, commands

    def _judge(self, window: TunnelWindow, alerts: list[dict], commands: list[dict]) -> None:
        self.counts["windows"] += 1
        if not self.alert(window):
            return
        self.counts["tunnel_alerts"] += 1
        verdict = window.verdict
        alert = {"alert": "tunnel", "client": window.client_id, "domain": window.domain, "window_end": window.end,
                 "score": verdict.score if verdict else None,
                 "reasons": list(verdict.reasons) if verdict else [], "features": window.features.as_dict(),
                 "action": "alert"}
        if self.enforce:
            key = (window.client_id, window.domain)
            now = self.clock()
            # ask again only when our rule is past half its life: renewing it, not flooding the resolver
            if self._rules.get(key, 0) - now < self.rule_ttl / 2:
                self._rules[key] = now + self.rule_ttl
                self.counts["rules_asked"] += 1
                commands.append({"op": "add_rule", "domain": window.domain, "client": window.client_id,
                                 "ttl": self.rule_ttl, "reason": "tunnel",
                                 "score": round(verdict.score, 4) if verdict else 0.0, "source": "analyzer.live"})
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
    parser.add_argument("--alerts", type=Path, help="write alerts here (JSON lines) instead of stdout")
    args = parser.parse_args()

    def log(message: str) -> None:
        print(f"analyzer: {message}", file=sys.stderr, flush=True)

    analyzer = LiveAnalyzer(args.model, args.enforce, args.rule_ttl, args.alert_after, args.nxdomain_min_count,
                            args.nxdomain_min_ratio)
    mode = f"enforce: alerts become block rules for {args.rule_ttl} s" if args.enforce else "monitor: alerts only"
    log(f"judging with the {analyzer.judge}; alerts after {analyzer.alert.after} consecutive high windows; {mode}")
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
