"""Score fusion (README §7.8.5): one risk for a client and a registrable domain, from the slow path's signals.

Each signal comes with its own threshold, already set for a false-positive rate:
- the tunnel model's, with its two-window alert rule;
- the DGA classifier's, which the resolver also acts on;
- the NXDOMAIN-burst rule.

So the signals are not averaged: an average would dilute one certain signal (a tunnel
plainly alerted on) to nothing. Fusion adds what no single signal shows, and only that:

| Signals                                                                    | Risk |
|----------------------------------------------------------------------------|------|
| a tunnel alert: the model's consecutive high windows                       | high |
| a DGA-flagged domain that resolved while its client is in an NXDOMAIN burst | high |
| anything else                                                              | low  |

The second row is DGA malware's own pattern (as in Pleiades, Antonakakis et al., USENIX
Security 2012): of the many generated names it tries, most fail. The one that answers is
the live command server, worth blocking for that client even when the resolver only
monitors DGA names. High is blocked in enforce mode, and alerted on either way. The alert-only
tier of README §7.8.5 is what the other signals report on their own: NXDOMAIN bursts
(client-wide) and every DGA-flagged name (the resolver's log and the `dga` field of each event).

Two other rules were measured and left out (ml/tunnel/README.md, "Score fusion"):
- **One high tunnel window on a random-looking domain.** It catches nothing earlier: no tunnel
  domain in the dataset scores even 0.5, since attackers pick readable names.
- **Every DGA-flagged domain that resolved, as an alert.** It repeats the resolver's own report
  of each flagged name, about 8,000 times a day on a crawl.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Signals:
    """What the slow path knows about one client and registrable domain at the end of a window."""

    tunnel_alert: bool = False          # the tunnel model's consecutive high windows
    tunnel_score: float | None = None   # this window's
    dga: float | None = None            # the DGA score the resolver gave the domain; None: not scored (popular, ...)
    burst: bool = False                 # the client is in an NXDOMAIN burst over the window
    resolved: bool = False              # the domain answered (NOERROR, with answers) in the window

    def as_dict(self) -> dict[str, object]:
        return {"tunnel_alert": self.tunnel_alert, "tunnel_score": self.tunnel_score, "dga": self.dga,
                "burst": self.burst, "resolved": self.resolved}


@dataclass(frozen=True)
class FusionPolicy:
    dga_threshold: float = 0.9558349998164555  # models/dga's: flags 0.1% of benign names

    def __post_init__(self) -> None:
        if not 0.0 < self.dga_threshold < 1.0:
            raise ValueError("dga_threshold must be a probability between 0 and 1")


@dataclass(frozen=True)
class Risk:
    level: str                   # "high" or "low"
    kind: str                    # what was found: "tunnel", "dga_c2", or "" (low)
    reasons: tuple[str, ...]
    signals: Signals

    def as_dict(self) -> dict[str, object]:
        return {"level": self.level, "kind": self.kind, "reasons": list(self.reasons),
                "signals": self.signals.as_dict()}


def fuse(signals: Signals, policy: FusionPolicy = FusionPolicy()) -> Risk:
    if signals.tunnel_alert:
        return Risk("high", "tunnel", ("tunnel-like windows in a row",), signals)
    dga = signals.dga
    if dga is not None and dga >= policy.dga_threshold and signals.resolved and signals.burst:
        return Risk("high", "dga_c2", (f"a generated-looking domain (DGA score {dga:.3f}) that resolved",
                                       "while its client is in an NXDOMAIN burst: likely the live command server"),
                    signals)
    return Risk("low", "", (), signals)
