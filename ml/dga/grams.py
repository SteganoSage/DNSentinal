"""Fitting and scoring n-gram models on a whole dataset at once.

features.NgramModel scores one label at a time; it is the reference the
C++ port follows. The pipeline refits n-gram models for every split
(benign 3-gram, benign 2-gram, DGA 3-gram: three per split, 40+ splits in
leave-family-out) and scores a million labels each time. Here every
label's n-grams become integer ids once, so fitting is a bincount and
scoring a weighted sum; the scores equal NgramModel's (tests/ml/test_grams.py).
"""

from __future__ import annotations

from array import array
from collections import Counter

import numpy as np

from .features import NgramModel


class GramIndex:
    """The n-grams of a fixed list of labels, as integer ids."""

    def __init__(self, labels, n: int) -> None:
        reference = NgramModel(n)
        gram_ids: dict[str, int] = {}
        char_ids: dict[str, int] = {}
        ids, rows, own, chars, char_rows = array("i"), array("i"), array("i"), array("i"), array("i")
        lengths = array("d")
        for row, label in enumerate(labels):
            grams = reference.grams(label)
            counts = Counter(grams)
            for gram in grams:
                ids.append(gram_ids.setdefault(gram, len(gram_ids)))
                own.append(counts[gram])  # how often this gram occurs in its own label
                rows.append(row)
            for char in set(label):
                chars.append(char_ids.setdefault(char, len(char_ids)))
                char_rows.append(row)
            lengths.append(len(label))
        self.n = n
        self.grams = list(gram_ids)  # id -> gram
        self.chars = list(char_ids)  # id -> character
        self.ids, self.rows, self.own = (np.frombuffer(a, dtype=np.int32) for a in (ids, rows, own))
        self.char_ids, self.char_rows = (np.frombuffer(a, dtype=np.int32) for a in (chars, char_rows))
        self.lengths = np.frombuffer(lengths, dtype=np.float64)
        self.size = len(self.lengths)
        self.per_row = np.bincount(self.rows, minlength=self.size)  # n-grams per label

    def fit(self, rows: np.ndarray, alpha: float = 1.0) -> "FittedGrams":
        """An n-gram model of the labels in `rows` (indices into the list)."""
        member = np.zeros(self.size, dtype=bool)
        member[rows] = True
        if not member.any():
            raise ValueError("cannot fit an n-gram model on no labels")
        counts = np.bincount(self.ids[member[self.rows]], minlength=len(self.grams))
        alphabet = np.unique(self.char_ids[member[self.char_rows]])
        return FittedGrams(self, counts, member, alphabet, alpha)


class FittedGrams:
    def __init__(self, index: GramIndex, counts: np.ndarray, member: np.ndarray, alphabet: np.ndarray,
                 alpha: float) -> None:
        self.index, self.counts, self.member, self.alphabet, self.alpha = index, counts, member, alphabet, alpha
        self.total = int(counts.sum())

    def score(self) -> np.ndarray:
        """NgramModel.score for every label; the ones it was fitted on are scored leave-one-out."""
        i = self.index
        vocabulary = max(len(self.alphabet) ** i.n, 1)
        mine = self.member[i.rows]
        counts = self.counts[i.ids] - np.where(mine, i.own, 0)
        denominator = self.total - np.where(self.member, i.per_row, 0) + self.alpha * vocabulary
        log_p = np.log((np.maximum(counts, 0) + self.alpha) / denominator[i.rows])
        return np.bincount(i.rows, weights=log_p, minlength=i.size) / np.maximum(i.lengths, 1)

    def model(self) -> NgramModel:
        """The same model as an NgramModel, to save with the classifier."""
        model = NgramModel(self.index.n, self.alpha)
        model._counts = Counter({self.index.grams[k]: int(v) for k in np.flatnonzero(self.counts)
                                 for v in [self.counts[k]]})
        model._total = self.total
        model._alphabet = {self.index.chars[k] for k in self.alphabet}
        return model
