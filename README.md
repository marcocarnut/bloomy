# bloomy

HTTP + WebSocket server that serves static files **and** answers Bloom-filter membership
queries over WebSocket — built for [reseed39](https://reseed39.postcogito.org) (BIP39/Electrum
seed recovery) and reusable for other crypto projects. Ships with `bloomtool`, a standalone,
CPU-only tool to build / append / query the dual Bloom filter.

## What it does

- Serves a web app bundle **and** a WebSocket API from one port (same-origin, so a browser
  page can query the filter with no CORS setup).
- **WS API:** the client streams newline-separated hex *programs* (the 20-byte hash160 /
  32-byte witness or taproot key it derives locally); the server replies `HIT <hex>` for each
  member and `ACK <n>` per frame. The seed never leaves the browser — only derived public
  programs do.
- The filter answers *"is this one of the ~1.5 billion Bitcoin addresses ever funded?"* so
  reseed39 can recover a seed **without the user knowing the target address**.

## Components

| file | role |
|---|---|
| `server.c` | HTTP + WS server (vendored `wsServer`). Serves `www/`, `/bloom-info`, and the bloom WS. |
| `tools/bloomtool.c` | CPU-only build / append / query / stat of the filter (`-j` parallel build). |
| `bloom_common.h`, `bloom_host.h` | filter format + probe/insert, kept **byte-compatible** with `bip39rxcrack-cli` (the CUDA cracker) via a parity gate. |
| `tools/bloombench.py`, `pfbench.c` | WS throughput / page-fault benchmarks. |
| `deploy/`, `DEPLOY.md` | production setup: stunnel + Let's Encrypt + systemd + ufw + tip-follower. |

## Bloom filter (BLF3 format)

Two **classic** Bloom filters whose false-positive rates multiply:
- **filter1** over the raw program (GPU-resident in the cracker; probed first here).
- **filter2** over `sha256(program)` (independent hash), probed only on a filter1 hit.

Sized by `--gib G1,G2` (byte sizes) and `--n N` (capacity → optimal `k`). Example in production:
6.5 GiB + 8 GiB, ~1.5 B addresses, measured combined FPR **~5×10⁻¹⁸** ("a HIT is always real").
`--resident=f1` pre-warms only filter1 into RAM and leaves filter2 cold on disk (paged in on the
rare hit) — saves ~8 GiB resident with no FPR loss, for hosting multiple coins' filters.

## Build

```sh
make            # builds server + tools/bloomtool
```
Needs a C compiler + pthreads. The server statically links the vendored `wsServer/`.

## bloomtool

```sh
bloomtool build IN OUT --gib G1,G2 --n N [--classic1] [--other FILE] [-j N]
bloomtool append IN BLF          # in-place insert (IN='-' reads stdin)
bloomtool query  BLF             # stdin: hex programs  -> "HIT <hex>" per member
bloomtool stat   BLF             # Monte-Carlo measured FPR
```
- `IN` is an address list, one per line (`1…`/`3…`/`bc1q…`/`bc1p…`); undecodable and
  non-seed-derivable lines (P2WSH/multisig) are skipped and counted.
- `-j N` parallelizes the build (atomic inserts; output is **byte-identical** regardless of N).
- **Build on ext4/tmpfs, never plain btrfs** — random mmap writes trigger COW write-amplification.

## server

```sh
[BIND=127.0.0.1] [PROXY_PROTOCOL=1] [ACCESS_LOG=path] [RESIDENT=f1] \
    server [--resident[=all|f1]] FILE.blf [port] [www_root] [allow_ip ...]
```
- `GET /` → `www_root/index.html`; `GET /bloom-info` → capability JSON; other GETs → static files.
- WS frames: hex programs → `HIT <hex>` + `ACK <n>`.
- `PROXY_PROTOCOL=1` — read the HAProxy PROXY v1 header (real client IP behind stunnel).
- `ACCESS_LOG=path` — Combined Log Format for static GETs (visitor stats; feed to GoAccess/AWStats).
- `--resident=f1` — pre-warm filter1 into RAM (recommended for the query server).
- Per-connection WS throughput is logged to stderr (`[open]`/`[rate]`/`[close]`).

## Deploy

See **DEPLOY.md**. TLS is terminated by stunnel (`protocol = proxy`); systemd runs the server on
localhost, plus a **tip-follower** that appends deep-confirmed blocks (`tip − 36`, ~6 h, well
beyond any reorg) from a pruned Bitcoin Core node via `getblock` → `bloomtool append`. The filter
itself is (re)built from an address snapshot (e.g. a ClickHouse export) with `bloomtool build`.

## www/

The static bundle under `www/` is **project-specific and deploy-populated** (git-ignored) — drop
your app's built bundle there at deploy time. bloomy is the server, not the app.

## License

Vendors [wsServer](https://github.com/Theldus/wsServer) (GPLv3, © Davidson Francis) under
`wsServer/`. Shares the Bloom filter format with `bip39rxcrack-cli`.
