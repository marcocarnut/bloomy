#!/usr/bin/env python3
"""Standalone test client for the reseed39 bloom query server.

Streams hex programs (from argv, or stdin one-per-line) in one batch to the WS server, then
prints any HIT lines and the final ACK. This is what reseed39's browser side will do: derive
programs locally, send them, watch for HITs.

  ./client.py [ws://host:port] prog_hex [prog_hex ...]
  echo -e "<hex>\\n<hex>" | ./client.py ws://localhost:8080
"""
import sys, websocket

url   = "ws://localhost:8080"
progs = []
args  = sys.argv[1:]
if args and args[0].startswith("ws://"):
    url, args = args[0], args[1:]
progs = args if args else [l.strip() for l in sys.stdin if l.strip()]

ws = websocket.create_connection(url, timeout=15)
ws.send("\n".join(progs))
hits = []
while True:
    r = ws.recv()
    if r.startswith("ACK"):
        print(r); break
    if r.startswith("HIT"):
        h = r.split()[1]; hits.append(h); print(r)
ws.close()
print(f"# sent {len(progs)}, {len(hits)} hit(s)")
