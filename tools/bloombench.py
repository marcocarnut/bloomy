#!/usr/bin/env python3
"""bloombench -- baseline bloom-membership throughput over the reseed39 WebSocket API.

Streams UNIFORM-RANDOM programs (cheap to make locally) as fast as the server will take
them, so the number you get is the SERVER + NETWORK ceiling with the reseed39 app's
address derivation taken out of the loop. Random programs also means ~0 HITs, so no
extra HIT frames perturb the measurement. Pure Python 3 stdlib -- no pip installs.

  ./bloombench.py wss://oniric.postcogito.org/
  ./bloombench.py ws://192.0.0.7:8080/ --seconds 15 --batch 2000 --window 16

Reports:
  RTT        1-program round-trip (network + one server probe): min / median.
  Throughput programs/s ACKed over a fixed window, plus upstream KB/s.

Knobs that usually explain "wildly varying" app-side numbers:
  --batch   programs per WS frame   (bigger amorters per-frame overhead)
  --window  frames in flight        (hides network RTT; 1 = strict ping-pong)
Run it against oniric and redbox with the SAME knobs to compare apples to apples.
"""
import argparse, os, ssl, socket, struct, select, time, base64, statistics
from collections import deque
from urllib.parse import urlparse

class WS:
    """Minimal RFC6455 client: text frames, client-masked, stdlib only."""
    def __init__(self, url, timeout=30.0):
        u = urlparse(url)
        secure = (u.scheme == "wss")
        self.host = u.hostname
        self.port = u.port or (443 if secure else 80)
        path = u.path or "/"
        s = socket.create_connection((self.host, self.port), timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if secure:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=self.host)
        s.settimeout(timeout)
        self.s = s
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET {path} HTTP/1.1\r\nHost: {self.host}\r\n"
                        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.s.recv(4096)
            if not chunk: raise RuntimeError("server closed during handshake")
            resp += chunk
        if b" 101 " not in resp.split(b"\r\n", 1)[0]:
            raise RuntimeError("handshake failed: " + resp[:120].decode("latin1"))
        self.buf = resp.split(b"\r\n\r\n", 1)[1]

    def send_text(self, text):
        data = text.encode(); n = len(data)
        hdr = bytearray([0x81])
        if   n < 126:   hdr.append(0x80 | n)
        elif n < 65536: hdr.append(0x80 | 126); hdr += struct.pack("!H", n)
        else:           hdr.append(0x80 | 127); hdr += struct.pack("!Q", n)
        mask = os.urandom(4); hdr += mask
        if n:
            m = (mask * (n // 4 + 1))[:n]
            data = (int.from_bytes(data, "big") ^ int.from_bytes(m, "big")).to_bytes(n, "big")
        self.s.sendall(bytes(hdr) + data)

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk: raise ConnectionError("server closed")
            self.buf += chunk

    def recv_text(self):
        while True:
            self._need(2)
            b0, b1 = self.buf[0], self.buf[1]
            ln = b1 & 0x7f; off = 2
            if   ln == 126: self._need(4);  ln = struct.unpack("!H", self.buf[2:4])[0];  off = 4
            elif ln == 127: self._need(10); ln = struct.unpack("!Q", self.buf[2:10])[0]; off = 10
            self._need(off + ln)
            payload = self.buf[off:off+ln]; self.buf = self.buf[off+ln:]
            op = b0 & 0x0f
            if op == 0x8: raise ConnectionError("server sent close")
            if op in (0x1, 0x2): return payload.decode("latin1")
            # ignore ping/pong (0x9/0xA)

    def readable(self):
        return len(self.buf) > 0 or bool(select.select([self.s], [], [], 0)[0])

    def close(self):
        try: self.s.close()
        except Exception: pass


def rtt_probe(ws, samples):
    xs = []
    for _ in range(samples):
        prog = os.urandom(20).hex()
        t = time.perf_counter()
        ws.send_text(prog)
        while not ws.recv_text().startswith("ACK"):
            pass
        xs.append((time.perf_counter() - t) * 1000.0)
    return xs


def run_phase(ws, frames, batch, window, seconds):
    """Keep `window` frames in flight; return (programs_acked, elapsed_s)."""
    inflight = 0; acks = 0; idx = 0; nf = len(frames)
    t0 = time.perf_counter(); t_end = t0 + seconds
    last_t = t0; last_acks = 0
    while time.perf_counter() < t_end:
        while inflight < window:
            ws.send_text(frames[idx % nf]); idx += 1; inflight += 1
        if ws.recv_text().startswith("ACK"): acks += 1; inflight -= 1     # block for >=1
        while ws.readable():                                             # drain the rest
            if ws.recv_text().startswith("ACK"): acks += 1; inflight -= 1
        now = time.perf_counter()
        if now - last_t >= 2.0:
            print(f"    ... {acks*batch:>9,} programs   {(acks-last_acks)*batch/(now-last_t):>8,.0f} prog/s")
            last_t = now; last_acks = acks
    elapsed = time.perf_counter() - t0
    while inflight > 0:                                                  # drain tail
        if ws.recv_text().startswith("ACK"): acks += 1; inflight -= 1
    return acks * batch, elapsed


def main():
    ap = argparse.ArgumentParser(description="baseline bloom membership throughput over WS")
    ap.add_argument("url", help="ws://host:port/  or  wss://host/")
    ap.add_argument("--seconds", type=float, default=20.0, help="measurement window (default 20)")
    ap.add_argument("--warmup",  type=float, default=3.0,  help="discarded warmup (default 3)")
    ap.add_argument("--batch",   type=int,   default=1000, help="programs per frame (default 1000)")
    ap.add_argument("--window",  type=int,   default=8,    help="frames in flight (default 8; 1=ping-pong)")
    ap.add_argument("--pool",    type=int,   default=500_000, help="distinct random programs to pre-gen")
    ap.add_argument("--rtt-samples", type=int, default=15)
    ap.add_argument("--insecure", action="store_true", help="skip TLS cert verify (wss)")
    a = ap.parse_args()

    if a.insecure:
        ssl._create_default_https_context = ssl._create_unverified_context

    print(f"target {a.url}   batch={a.batch} window={a.window} pool={a.pool:,}")
    # Pre-build frame payloads once so the hot loop is pure network (no gen bottleneck).
    # pool >> programs-per-run, so on a disk-bound server the probes stay effectively random
    # (no page-cache warming from reuse) while a fast/cached server isn't client-limited.
    pool = a.pool - (a.pool % a.batch)
    progs = [os.urandom(20).hex() for _ in range(pool)]
    frames = ["\n".join(progs[i:i+a.batch]) for i in range(0, pool, a.batch)]
    print(f"  pre-generated {pool:,} random programs in {len(frames):,} frames")

    ws = WS(a.url)
    try:
        rtts = rtt_probe(ws, a.rtt_samples)
        print(f"  RTT (1-program round-trip): min {min(rtts):.1f} ms   "
              f"median {statistics.median(rtts):.1f} ms   (n={len(rtts)})")
        if a.warmup > 0:
            print(f"  warmup {a.warmup:.0f}s ...")
            run_phase(ws, frames, a.batch, a.window, a.warmup)
        print(f"  measuring {a.seconds:.0f}s ...")
        programs, elapsed = run_phase(ws, frames, a.batch, a.window, a.seconds)
    finally:
        ws.close()

    rate = programs / elapsed
    kbps = programs * 41 / 1024 / elapsed          # ~41 bytes/program on the wire (hex+nl)
    print("  " + "-"*52)
    print(f"  RESULT  {programs:,} programs in {elapsed:.1f}s = {rate:,.0f} prog/s "
          f"({kbps:,.0f} KB/s up)")


if __name__ == "__main__":
    main()
