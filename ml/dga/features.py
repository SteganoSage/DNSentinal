"""Explainable lexical features for domain-generation-algorithm detection.

Every feature is computed on the registrable label: the label just left of
the public suffix (README §7.8.2), found with the Public Suffix List
(psl.py). For `x7kq2.example.co.uk` that is `example`; for
`cvyh1po636.ddns.net` it is `cvyh1po636`, the part a DGA generated.

The features come in groups, which the pipeline can switch on and off
(--features) to measure what each adds:

A  character statistics   label_length, entropy, digit_ratio, vowel_ratio,
                          consonant_ratio, longest_consonant_run, hex_ratio,
                          distinct_ratio
B  fitted on benign names ngram_log_likelihood (3-gram), tld_log_share
C  structure              is_idn, letter_digit_switches, hyphens,
                          longest_digit_run
D  words                  word_coverage, longest_word
E  more fitted models     bigram_log_likelihood (benign 2-gram),
                          dga_likelihood_ratio (benign minus DGA 3-gram)
F  popularity             label_in_allowlist

Groups B and E are fitted on training names only, per split; D and F look
words and labels up in fixed lists. Deliberately independent of
scikit-learn, and simple enough to reimplement exactly in C++ for the
resolver's fast path (plan §6.4).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from functools import lru_cache
import math
from pathlib import Path
import re
from typing import Iterable

from .psl import PublicSuffixList, default_list

# DNS labels may contain underscores (service records, some tracking names),
# even though ordinary host names may not.
_DOMAIN_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?$")
_VOWELS = frozenset("aeiou")
_HEX = frozenset("0123456789abcdef")
WORDS_PATH = Path(__file__).resolve().parents[2] / "config" / "english_words.txt"


def normalise(domain: str) -> str:
    """Lower case, no trailing dot; ValueError unless it is a valid DNS name."""
    value = domain.strip().lower().rstrip(".")
    if not value or len(value) > 253 or not _DOMAIN_RE.fullmatch(value):
        raise ValueError(f"invalid domain name: {domain!r}")
    if any(not label or len(label) > 63 for label in value.split(".")):
        raise ValueError(f"invalid domain name: {domain!r}")
    return value


def split_name(domain: str, psl: PublicSuffixList | None = None) -> tuple[str, str]:
    """(registrable label, public suffix): ("example", "co.uk") for www.example.co.uk.

    A name that is itself a public suffix has no registrable label; its
    leftmost label stands in, so every name can be scored.
    """
    psl = psl or default_list()
    value = normalise(domain)
    suffix = psl.public_suffix(value)
    labels = value.split(".")
    keep = len(labels) - (suffix.count(".") + 1)
    if keep <= 0:
        return labels[0], ".".join(labels[1:])
    return labels[keep - 1], suffix


def registrable_domain(domain: str, psl: PublicSuffixList | None = None) -> str:
    """The eTLD+1, or the name itself if it is a public suffix."""
    psl = psl or default_list()
    value = normalise(domain)
    return psl.registrable_domain(value) or value


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _longest_run(value: str, belongs) -> int:
    best = current = 0
    for char in value:
        current = current + 1 if belongs(char) else 0
        best = max(best, current)
    return best


def _switches(value: str) -> int:
    """How often the label switches between letters and digits (hyphens don't count)."""
    kinds = [char.isdigit() for char in value if char.isalnum()]
    return sum(a != b for a, b in zip(kinds, kinds[1:]))


@dataclass(frozen=True)
class DomainFeatures:
    """Numeric feature vector with stable names for training and export."""

    # A: character statistics
    label_length: int
    entropy: float
    digit_ratio: float
    vowel_ratio: float
    consonant_ratio: float
    longest_consonant_run: int
    hex_ratio: float
    distinct_ratio: float
    # B: fitted on benign names
    ngram_log_likelihood: float
    tld_log_share: float
    # C: structure
    is_idn: int
    letter_digit_switches: int
    hyphens: int
    longest_digit_run: int
    # D: words
    word_coverage: float
    longest_word: int
    # E: more fitted models
    bigram_log_likelihood: float
    dga_likelihood_ratio: float
    # F: popularity
    label_in_allowlist: int

    def as_dict(self) -> dict[str, float | int]:
        return asdict(self)

    @classmethod
    def names(cls) -> list[str]:
        return list(cls.__dataclass_fields__)

    def vector(self) -> list[float]:
        return [float(getattr(self, name)) for name in self.names()]


FEATURE_GROUPS = {
    "A": ["label_length", "entropy", "digit_ratio", "vowel_ratio", "consonant_ratio", "longest_consonant_run",
          "hex_ratio", "distinct_ratio"],
    "B": ["ngram_log_likelihood", "tld_log_share"],
    "C": ["is_idn", "letter_digit_switches", "hyphens", "longest_digit_run"],
    "D": ["word_coverage", "longest_word"],
    "E": ["bigram_log_likelihood", "dga_likelihood_ratio"],
    "F": ["label_in_allowlist"],
}
assert sum(FEATURE_GROUPS.values(), []) == DomainFeatures.names()


class NgramModel:
    """Laplace-smoothed character n-gram model of registrable labels.

    Fit it on training labels only: a model that has seen the test names
    makes them look more familiar than they are.
    """

    def __init__(self, n: int = 3, alpha: float = 1.0) -> None:
        if n < 1 or alpha <= 0:
            raise ValueError("n must be positive and alpha must be greater than zero")
        self.n = n
        self.alpha = alpha
        self._counts: Counter[str] = Counter()
        self._total = 0
        self._alphabet: set[str] = set()

    def grams(self, label: str) -> list[str]:
        padded = "^" * (self.n - 1) + label + "$"
        return [padded[i : i + self.n] for i in range(len(padded) - self.n + 1)]

    def fit(self, labels: Iterable[str]) -> "NgramModel":
        for label in labels:
            self._counts.update(self.grams(label))
            self._alphabet.update(label)
        self._total = sum(self._counts.values())
        if not self._total:
            raise ValueError("cannot fit an n-gram model on no labels")
        return self

    def state(self) -> dict:
        """Everything score() needs, as plain JSON data (saved with the classifier, read by the C++ export)."""
        return {"n": self.n, "alpha": self.alpha, "alphabet": "".join(sorted(self._alphabet)),
                "total": self._total, "counts": dict(sorted(self._counts.items()))}

    @classmethod
    def from_state(cls, state: dict) -> "NgramModel":
        model = cls(state["n"], state["alpha"])
        model._alphabet = set(state["alphabet"])
        model._counts = Counter(state["counts"])
        model._total = state["total"]
        return model

    def score(self, label: str, exclude_self: bool = False) -> float:
        """Mean log-likelihood per character: higher is more like the names it was fitted on.

        exclude_self scores a label the model was fitted on as if it had been
        left out (leave-one-out), so training labels look as unfamiliar to
        it as new ones would. The alphabet is kept as fitted.
        """
        grams = self.grams(label)
        own = Counter(grams) if exclude_self else Counter()
        vocabulary = max(len(self._alphabet) ** self.n, 1)
        denominator = self._total - sum(own.values()) + self.alpha * vocabulary
        return sum(math.log((max(self._counts[gram] - own[gram], 0) + self.alpha) / denominator)
                   for gram in grams) / max(len(label), 1)


class TldPrior:
    """How common a top-level domain is among benign names: log10 of its share.

    Some DGAs favour TLDs few popular sites use (.biz, .kz, .info), so a rare
    TLD is evidence (README §7.8.2, "TLD category"). Fitted on benign training
    names only, like the n-gram model; a TLD it never saw gets the smoothed
    share of a single name.
    """

    def __init__(self, alpha: float = 1.0) -> None:
        self.alpha = alpha
        self._counts: Counter[str] = Counter()
        self._total = 0

    def fit(self, suffixes: Iterable[str]) -> "TldPrior":
        self._counts.update(suffix.rsplit(".", 1)[-1] for suffix in suffixes)
        self._total = sum(self._counts.values())
        return self

    def score(self, suffix: str) -> float:
        tld = suffix.rsplit(".", 1)[-1]
        return math.log10((self._counts[tld] + self.alpha) / (self._total + self.alpha * (len(self._counts) + 1)))

    def state(self) -> dict:
        return {"alpha": self.alpha, "total": self._total, "counts": dict(sorted(self._counts.items()))}

    @classmethod
    def from_state(cls, state: dict) -> "TldPrior":
        prior = cls(state["alpha"])
        prior._counts = Counter(state["counts"])
        prior._total = state["total"]
        return prior


class WordList:
    """English words (config/english_words.txt, from SCOWL) for the word features."""

    MIN_LENGTH = 3

    def __init__(self, words: Iterable[str]) -> None:
        self._words = frozenset(w for w in words if len(w) >= self.MIN_LENGTH and w.isascii() and w.isalpha())
        self.longest = max(map(len, self._words), default=0)

    @classmethod
    def load(cls, path: str | Path = WORDS_PATH) -> "WordList":
        with open(path, encoding="utf-8") as stream:
            return cls(line.strip() for line in stream if line.strip() and not line.startswith("#"))

    def __len__(self) -> int:
        return len(self._words)

    def cover(self, label: str) -> tuple[int, int]:
        """(letters covered by non-overlapping words, length of the longest word in the label).

        best[i] is the most letters of label[:i] that whole words can cover;
        the C++ version walks a trie instead of slicing.
        """
        best = [0] * (len(label) + 1)
        longest = 0
        for end in range(1, len(label) + 1):
            best[end] = best[end - 1]
            for length in range(self.MIN_LENGTH, min(self.longest, end) + 1):
                if label[end - length : end] in self._words:
                    best[end] = max(best[end], best[end - length] + length)
                    longest = max(longest, length)
        return best[-1], longest


@lru_cache(maxsize=1)
def default_words() -> WordList:
    """The list in config/english_words.txt, loaded once."""
    return WordList.load(WORDS_PATH)


@dataclass
class FeatureContext:
    """What the fitted and looked-up features need; a feature whose model is missing is 0."""

    ngram: NgramModel | None = None       # benign 3-gram (B)
    tld_prior: TldPrior | None = None     # (B)
    words: WordList | None = None         # (D)
    bigram: NgramModel | None = None      # benign 2-gram (E)
    dga_ngram: NgramModel | None = None   # 3-gram of DGA training labels (E)
    allow_labels: frozenset[str] | None = None  # registrable labels of the allowlist (F)


def label_features(label: str, suffix: str, context: FeatureContext | None = None) -> DomainFeatures:
    """The features of one registrable label and its public suffix."""
    c = context or FeatureContext()
    letters = sum(char.isalpha() for char in label)
    length = len(label)
    covered, longest_word = c.words.cover(label) if c.words else (0, 0)
    ngram = c.ngram.score(label) if c.ngram else 0.0
    return DomainFeatures(
        label_length=length,
        entropy=_entropy(label),
        digit_ratio=sum(char.isdigit() for char in label) / max(length, 1),
        vowel_ratio=sum(char in _VOWELS for char in label) / max(letters, 1),
        consonant_ratio=sum(char.isalpha() and char not in _VOWELS for char in label) / max(letters, 1),
        longest_consonant_run=_longest_run(label, lambda ch: ch.isalpha() and ch not in _VOWELS),
        hex_ratio=sum(char in _HEX for char in label) / max(length, 1),
        distinct_ratio=len(set(label)) / max(length, 1),
        ngram_log_likelihood=ngram,
        tld_log_share=c.tld_prior.score(suffix) if c.tld_prior else 0.0,
        is_idn=int(label.startswith("xn--")),
        letter_digit_switches=_switches(label),
        hyphens=label.count("-"),
        longest_digit_run=_longest_run(label, str.isdigit),
        word_coverage=covered / max(length, 1),
        longest_word=longest_word,
        bigram_log_likelihood=c.bigram.score(label) if c.bigram else 0.0,
        dga_likelihood_ratio=ngram - c.dga_ngram.score(label) if c.ngram and c.dga_ngram else 0.0,
        label_in_allowlist=int(label in c.allow_labels) if c.allow_labels is not None else 0,
    )


def extract_features(
    domain: str, context: FeatureContext | None = None, psl: PublicSuffixList | None = None
) -> DomainFeatures:
    """The features of a domain name, computed on its registrable label."""
    label, suffix = split_name(domain, psl)
    return label_features(label, suffix, context)
