#!/usr/bin/env python3
"""The exfiltrated data's destination, at the far end of a tunnel: count what arrives, every half second.

    python3 bench/drivers/sink.py --listen 172.30.0.1 --port 9000 --out sink.csv     # until SIGTERM

One CSV row every 0.5 s (and at the end): t (Unix seconds) and the total bytes received so far.
"""

import argparse
import signal
import socket
import sys
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument("--listen", required=True)
parser.add_argument("--port", type=int, default=9000)
parser.add_argument("--out", required=True)
args = parser.parse_args()
total = [0]
out = open(args.out, "w")
out.write("t,bytes\n")


def record():
    out.write(f"{time.time():.3f},{total[0]}\n")
    out.flush()


def stop(*_):
    record()
    out.close()
    sys.exit(0)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)


def clock():
    while True:
        record()
        time.sleep(0.5)


def serve(conn):
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                return
            total[0] += len(data)


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
for _ in range(60):  # the tunnel's address exists once iodined is up
    try:
        server.bind((args.listen, args.port))
        break
    except OSError:
        time.sleep(0.5)
server.listen(8)
threading.Thread(target=clock, daemon=True).start()
while True:
    conn, _ = server.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
