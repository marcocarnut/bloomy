# reseed39 bloom query server.
#   make bloomq   # step 1: the mmap+probe core (reads hex programs from stdin)
#   make parity   # gate: bloomq's membership == the reference cracker's --bloom-check
#
# bloom_common.h + the COPIED functions in bloom_host.h come from the bip39rxcrack-cli repo
# (the correctness authority); the parity gate proves they stay in agreement.
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra
CLI    ?= /root/bip39rxcrack-cli/bip39rxcrack
RESEED39_DIR ?= /root/bip39rxcrack

WS_DIR ?= wsServer
.PHONY: all parity clean serve bloomtool bloomtool-check
all: bloomq server bloomtool

bloomq: bloomq.c bloom_host.h bloom_common.h
	$(CC) $(CFLAGS) -o bloomq bloomq.c

# Standalone CPU-only build/append/query/stat (no CUDA) -- runs the whole bloom pipeline
# on a GPU-less box (e.g. hedonic). Static so it needs no runtime libs. Output is
# byte-identical to the CLI's `--bloom-build --classic1` (proven by `make bloomtool-check`).
bloomtool: tools/bloomtool.c bloom_host.h bloom_common.h
	$(CC) $(CFLAGS) -static -I. -o tools/bloomtool tools/bloomtool.c -lm

# gate: a filter built by bloomtool is byte-for-byte identical to one built by the CLI
bloomtool-check: bloomtool
	@zcat $${LOYCE:-/vs1/claude/loyce/all_addrs_2026-09-08.txt.gz} 2>/dev/null | head -10000 > /tmp/bt_chk.txt; \
	tools/bloomtool build /tmp/bt_chk.txt /tmp/bt_a.blf --gib 0.03125,0.03125 --n 20000 --classic1 >/dev/null 2>&1; \
	$(CLI) --bloom-build /tmp/bt_chk.txt /tmp/bt_b.blf --bloom-gib 0.03125,0.03125 --bloom-n 20000 --classic1 >/dev/null 2>&1; \
	cmp /tmp/bt_a.blf /tmp/bt_b.blf && echo "bloomtool == CLI (byte-identical) OK" || echo "MISMATCH"; \
	rm -f /tmp/bt_chk.txt /tmp/bt_a.blf /tmp/bt_b.blf

$(WS_DIR)/libws.a:
	$(MAKE) -C $(WS_DIR) libws.a

server: server.c bloom_host.h bloom_common.h $(WS_DIR)/libws.a
	$(CC) $(CFLAGS) -I$(WS_DIR)/include -o server server.c $(WS_DIR)/libws.a -lpthread

# run the server on the real filter (foreground)
serve: server
	./server /root/data/alladdrs_classic.blf 8080

# prove the server's program-probe agrees with the CLI's address-probe, byte for byte
parity: bloomq
	@CLI=$(CLI) RESEED39_DIR=$(RESEED39_DIR) node gate/e2e_parity.js

clean:
	rm -f bloomq tools/bloomtool /tmp/bloomq_*.blf
