"""Timestamped progress lines, on one clock for the whole run.

Its own module because `python -m ml.dga.pipeline` runs pipeline.py as
__main__ and tune.py imports it again as ml.dga.pipeline: a clock kept
there would restart halfway through a tuning run.
"""

import time

_START = time.monotonic()  # not time.time(): the wall clock can jump (WSL resyncs it)


def log(message: str) -> None:
    print(f"[{time.monotonic() - _START:7.1f}s] {message}", flush=True)
