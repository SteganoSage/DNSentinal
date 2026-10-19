"""A character-level CNN over the registrable domain: E7's learned-features model.

It reads the name itself rather than the hand-made features, which is the
comparison E7 asks for (T4): what it gains in detection, and what it costs
in size and latency. Needs PyTorch; quick on a Kaggle or Colab GPU (mixed
precision there), slow on a CPU.

Architecture: embedding (32) -> convolutions of width 2-5 (128 filters
each) -> max over positions -> dense (128) -> one logit.
"""

from __future__ import annotations

import numpy as np

from .models import Batch, Model

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_."
MAX_LENGTH = 64  # registrable domains longer than this are cut (labels are at most 63)
_INDEX = {c: i + 1 for i, c in enumerate(ALPHABET)}  # 0 pads, len + 1 is anything else
OPTIONS = {"epochs": 5, "batch_size": 1024}  # the pipeline's --epochs sets epochs


def encode(names) -> np.ndarray:
    out = np.zeros((len(names), MAX_LENGTH), dtype=np.uint8)
    for row, name in enumerate(names):
        codes = [_INDEX.get(c, len(ALPHABET) + 1) for c in name[:MAX_LENGTH]]
        out[row, : len(codes)] = codes
    return out


def _network(torch):
    nn = torch.nn

    class Net(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.embed = nn.Embedding(len(ALPHABET) + 2, 32, padding_idx=0)
            self.convs = nn.ModuleList(nn.Conv1d(32, 128, width, padding=width - 1) for width in (2, 3, 4, 5))
            self.head = nn.Sequential(nn.Dropout(0.3), nn.Linear(4 * 128, 128), nn.ReLU(), nn.Linear(128, 1))

        def forward(self, x):
            h = self.embed(x).transpose(1, 2)
            return self.head(torch.cat([conv(h).relu().amax(dim=2) for conv in self.convs], dim=1)).squeeze(1)

    return Net()


class CharCNN(Model):
    name, title = "cnn", "Character CNN"

    def __init__(self, seed: int, threads: int) -> None:
        import torch

        self.torch, self.seed = torch, seed
        self.epochs, self.batch_size = OPTIONS["epochs"], OPTIONS["batch_size"]
        self.learning_rate = 2e-3
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        torch.set_num_threads(max(1, threads))
        self.net = None

    def fit(self, batch: Batch) -> "DeepModel":
        torch = self.torch
        torch.manual_seed(self.seed)
        x = torch.from_numpy(encode(batch.names))
        y = torch.from_numpy(np.asarray(batch.y, dtype=np.float32))
        self.net = _network(torch).to(self.device)
        optimiser = torch.optim.AdamW(self.net.parameters(), lr=self.learning_rate, weight_decay=1e-4)
        loss_fn = torch.nn.BCEWithLogitsLoss()
        amp = self.device == "cuda"
        scaler = torch.amp.GradScaler("cuda", enabled=amp)
        generator = torch.Generator().manual_seed(self.seed)
        self.net.train()
        for _ in range(self.epochs):
            for rows in torch.randperm(len(x), generator=generator).split(self.batch_size):
                optimiser.zero_grad()
                with torch.autocast(self.device, dtype=torch.float16, enabled=amp):
                    logits = self.net(x[rows].long().to(self.device))
                    loss = loss_fn(logits.float(), y[rows].to(self.device))
                scaler.scale(loss).backward()
                scaler.unscale_(optimiser)
                torch.nn.utils.clip_grad_norm_(self.net.parameters(), 1.0)
                scaler.step(optimiser)
                scaler.update()
        self.net.eval()
        return self

    def score(self, batch: Batch) -> np.ndarray:
        torch = self.torch
        x = torch.from_numpy(encode(batch.names))
        out = []
        with torch.no_grad():
            for start in range(0, len(x), 8192):
                rows = slice(start, start + 8192)
                logits = self.net(x[rows].long().to(self.device))
                out.append(torch.sigmoid(logits.float()).cpu().numpy())
        return np.concatenate(out) if out else np.array([])

    def size(self) -> dict:
        parameters = sum(p.numel() for p in self.net.parameters())
        return {"bytes": 4 * parameters, "parameters": parameters}

    def single_thread(self) -> None:
        self.torch.set_num_threads(1)
        self.net.to("cpu")  # one name at a time: a GPU round trip costs more than it saves
        self.device = "cpu"
