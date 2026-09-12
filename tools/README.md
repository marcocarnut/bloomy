# tools

## bloomtool — standalone CPU-only bloom pipeline (no CUDA)

`bloomtool` builds, appends to, queries, and measures the reseed39 dual bloom filter
**without a GPU**, so the whole address-indexing pipeline can run on a GPU-less host
(e.g. hedonic, which has no CUDA libraries and cannot run the CUDA-linked `bip39rxcrack`
CLI). It shares `bloom_common.h` + `bloom_host.h` with the server and copies the
address-decode / sizing / build / append / stat logic verbatim from
`bip39rxcrack-cli/src/bip39rxcrack.c`, so its output is **byte-for-byte identical** to
the CLI's `--bloom-build --classic1` (proven by `make bloomtool-check`).

Build (static, no runtime deps):

    make bloomtool          # -> tools/bloomtool
    make bloomtool-check    # gate: bloomtool .blf == CLI .blf, byte for byte

Usage:

    # build the 1.7 B filter (6.5 GiB filter1 + 8 GiB filter2, classic1) from an address list
    zcat all_Bitcoin_addresses_ever_used_sorted.txt.gz \
      | bloomtool build - alladdrs.blf --gib 6.5,8 --n 1700000000 --classic1 --other skipped.txt

    # faster full rebuild: -j N parallel workers (needs a SEEKABLE file, not a pipe)
    bloomtool build all_addrs.txt alladdrs.blf --gib 6.5,8 --n 1700000000 --classic1 -j 8
    #   or with stdin redirected from a real file (still seekable):  bloomtool build - out.blf ... -j 8 < all_addrs.txt

    # daily tip-append (idempotent): decode block addresses -> insert in place
    getblock-addresses.sh | bloomtool append - alladdrs.blf

    # query: newline-separated hex programs (20B hash160 / 32B taproot) on stdin -> HIT lines
    printf '%s\n' <hexprog> | bloomtool query alladdrs.blf

    # measure the true FPR (Monte-Carlo over random programs)
    bloomtool stat alladdrs.blf

Notes:
- Only valid decodable addresses are inserted (P2PKH->44, P2SH->49, P2WPKH->84, P2TR->86);
  everything else is skipped and counted. `--other FILE` captures the **non-`bc1`** skips
  (junk / prefixed / ClickHouse noise); `bc1...` skips (P2WSH, other witness versions — not
  seed-derivable) are counted separately and not written to `--other`, matching the CLI.
- Filter format is BLF3 with classic filter1 (`--classic1`, `rsv=1`) + classic filter2 over
  sha256(program). `--gib G1,G2` sets the byte sizes; `--n N` sizes k for that design capacity.
- Build/append do random mmap writes: put the target file on **ext4/xfs or tmpfs**, never a
  plain btrfs file (copy-on-write turns random bit-writes into massive write amplification;
  use `chattr +C` if it must live on btrfs).
- `-j N` (build only): N worker threads mmap the input, split it into byte ranges, and insert
  concurrently with atomic bit-sets. Because bloom inserts only OR bits (order-independent),
  **the output is byte-for-byte identical regardless of N** (verified: `-j1`==`-j8` via cmp).
  The build is memory-latency-bound (~51 scattered cache-miss bit-sets/address), so threads
  overlap those stalls: ~3.7× at `-j8` on a small test, more on the full filter / more cores.
  Requires a **seekable regular file** input (filename, or `-` with stdin redirected from a
  file); a pipe (`zcat | … -j8`) prints a warning and falls back to `-j1`. Default is `-j1`
  (the exact serial path, unchanged). Appends stay single-threaded (they're already instant).
