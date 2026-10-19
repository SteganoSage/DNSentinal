"""The Public Suffix List: which part of a name is its registrable domain.

The DGA classifier scores the registrable domain (eTLD+1), because that is
what a DGA generates (README §7.8.2): `x7kq2.example.co.uk` -> `example.co.uk`.
This implements the algorithm from https://publicsuffix.org/list/:

- the longest matching rule wins;
- an exception rule (`!www.ck`) beats the wildcard it excepts (`*.ck`), and
  its public suffix is the rule minus its leftmost label;
- a wildcard (`*.ck`) matches any one label in its place;
- a name no rule matches has its last label as public suffix (rule "*").

Both sections of the list are used, ICANN and private, so a name under a
dynamic-DNS provider such as `x7k2.ddns.net` is its own registrable domain:
the generated part is what gets scored, not `ddns`.

The resolver reads the same file (config/public_suffix_list.dat), so
training and deployment split every name the same way.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "config" / "public_suffix_list.dat"


def _ascii(label: str) -> str:
    """A rule label in the form DNS names use: lower case, IDNs in punycode."""
    if label in ("*", "") or label.isascii():
        return label.lower()
    return label.encode("idna").decode("ascii").lower()


class PublicSuffixList:
    def __init__(self, rules: Iterable[str], version: str = "") -> None:
        self.version = version
        self._rules: set[str] = set()       # "co.uk"
        self._wildcards: set[str] = set()   # "*.ck" stored as "ck"
        self._exceptions: set[str] = set()  # "!www.ck" stored as "www.ck"
        self.skipped = 0  # rules that can't be written in ASCII
        for rule in rules:
            self._add(rule)

    @classmethod
    def load(cls, path: str | Path = DEFAULT_PATH) -> "PublicSuffixList":
        rules, version = [], ""
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if line.startswith("// VERSION:"):
                    version = line.split(":", 1)[1].strip()
                if line and not line.startswith("//"):
                    rules.append(line.split()[0])  # a rule ends at the first whitespace
        return cls(rules, version)

    def _add(self, rule: str) -> None:
        exception = rule.startswith("!")
        try:
            labels = [_ascii(label) for label in rule.lstrip("!").split(".")]
        except UnicodeError:
            self.skipped += 1
            return
        if exception:
            self._exceptions.add(".".join(labels))
        elif labels[0] == "*":
            self._wildcards.add(".".join(labels[1:]))
        else:
            self._rules.add(".".join(labels))

    def public_suffix(self, name: str) -> str:
        """The public suffix of a normalised name (lower case, no trailing dot)."""
        labels = name.split(".")
        for i in range(len(labels)):  # longest candidate first, so the first match is the longest
            candidate = ".".join(labels[i:])
            if candidate in self._exceptions:
                return ".".join(labels[i + 1 :])
            if candidate in self._rules:
                return candidate
            if i + 1 < len(labels) and ".".join(labels[i + 1 :]) in self._wildcards:
                return candidate
        return labels[-1]

    def registrable_domain(self, name: str) -> str | None:
        """The public suffix plus one label; None if the name is a public suffix itself."""
        suffix = self.public_suffix(name)
        labels = name.split(".")
        wanted = suffix.count(".") + 2
        if len(labels) < wanted:
            return None
        return ".".join(labels[-wanted:])


@lru_cache(maxsize=1)
def default_list() -> PublicSuffixList:
    """The list in config/public_suffix_list.dat, loaded once."""
    return PublicSuffixList.load(DEFAULT_PATH)
