"""Explainable lexical features for domain-generation-algorithm detection.

The extractor is deliberately independent of scikit-learn so it can be used
by both training code and a future C++ inference implementation.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import math
import re
from typing import Iterable, Mapping

# DNS labels may contain underscores (for example, service records and
# tracking names), even though underscores are not valid in ordinary hostnames.
_DOMAIN_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$", re.IGNORECASE)
_COMMON_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "co.jp",
    }
)


def _normalise(domain: str) -> str:
    value = domain.strip().lower().rstrip(".")
    if not value or not _DOMAIN_RE.fullmatch(value):
        raise ValueError(f"invalid domain name: {domain!r}")
    labels = value.split(".")
    if any(not label or len(label) > 63 for label in labels) or len(value) > 253:
        raise ValueError(f"invalid domain name: {domain!r}")
    return value


def registrable_domain(domain: str, public_suffixes: Iterable[str] | None = None) -> str:
    """Return the eTLD+1, using supplied PSL suffixes when available.

    The small built-in suffix set is only a deterministic fallback. Production
    training should pass a current Public Suffix List.
    """

    value = _normalise(domain)
    labels = value.split(".")
    suffixes = {
        suffix.lower().strip(".")
        for suffix in (public_suffixes or _COMMON_MULTI_LABEL_SUFFIXES)
    }
    suffix_len = 2 if ".".join(labels[-2:]) in suffixes else 1
    if len(labels) <= suffix_len:
        return value
    return ".".join(labels[-(suffix_len + 1) :])


def _registrable_label(domain: str) -> str:
    value = registrable_domain(domain)
    labels = value.split(".")
    suffix_len = 2 if ".".join(labels[-2:]) in _COMMON_MULTI_LABEL_SUFFIXES else 1
    return labels[-(suffix_len + 1)]


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _longest_consonant_run(value: str) -> int:
    vowels = set("aeiou")
    best = current = 0
    for char in value:
        if char.isalpha() and char not in vowels:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


@dataclass(frozen=True)
class DomainFeatures:
    """Numeric feature vector with stable names for training and export."""

    label_length: int
    entropy: float
    digit_ratio: float
    vowel_ratio: float
    consonant_ratio: float
    longest_consonant_run: int
    hex_ratio: float
    distinct_ratio: float
    tld_is_common: int
    ngram_log_likelihood: float

    def as_dict(self) -> dict[str, float | int]:
        return asdict(self)

    @classmethod
    def names(cls) -> list[str]:
        return list(cls.__dataclass_fields__)

    def vector(self) -> list[float]:
        return [float(getattr(self, name)) for name in self.names()]


class NgramModel:
    """Laplace-smoothed character n-gram model for benign-domain likelihood."""

    def __init__(self, n: int = 3, alpha: float = 1.0) -> None:
        if n < 1 or alpha <= 0:
            raise ValueError("n must be positive and alpha must be greater than zero")
        self.n = n
        self.alpha = alpha
        self._counts: Counter[str] = Counter()
        self._total = 0
        self._alphabet: set[str] = set()

    def fit(self, domains: Iterable[str]) -> "NgramModel":
        for domain in domains:
            text = _registrable_label(domain)
            padded = "^" * (self.n - 1) + text + "$"
            grams = [padded[i : i + self.n] for i in range(len(padded) - self.n + 1)]
            self._counts.update(grams)
            self._total += len(grams)
            self._alphabet.update(text)
        if not self._total:
            raise ValueError("cannot fit n-gram model with no domains")
        return self

    def score(self, label: str) -> float:
        value = _registrable_label(label)
        padded = "^" * (self.n - 1) + value + "$"
        vocabulary = max(len(self._alphabet) ** self.n, 1)
        denominator = self._total + self.alpha * vocabulary
        return sum(
            math.log((self._counts[gram] + self.alpha) / denominator)
            for gram in (padded[i : i + self.n] for i in range(len(padded) - self.n + 1))
        ) / max(len(value), 1)


def extract_features(domain: str, ngram_model: NgramModel | None = None) -> DomainFeatures:
    value = registrable_domain(domain)
    label = _registrable_label(value)
    tld = value.rsplit(".", 1)[-1] if "." in value else ""
    letters = [char for char in label if char.isalpha()]
    length = len(label)
    return DomainFeatures(
        label_length=length,
        entropy=_entropy(label),
        digit_ratio=sum(char.isdigit() for char in label) / max(length, 1),
        vowel_ratio=sum(char in "aeiou" for char in label) / max(len(letters), 1),
        consonant_ratio=sum(char.isalpha() and char not in "aeiou" for char in label) / max(len(letters), 1),
        longest_consonant_run=_longest_consonant_run(label),
        hex_ratio=sum(char in "0123456789abcdef" for char in label) / max(length, 1),
        distinct_ratio=len(set(label)) / max(length, 1),
        tld_is_common=int(tld in {"com", "org", "net", "edu", "gov", "io", "co", "uk", "in"}),
        ngram_log_likelihood=ngram_model.score(value) if ngram_model else 0.0,
    )


def feature_rows(domains: Iterable[str], ngram_model: NgramModel | None = None) -> list[Mapping[str, float | int]]:
    return [extract_features(domain, ngram_model).as_dict() for domain in domains]
