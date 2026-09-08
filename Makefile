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
.PHONY: all parity clean serve
all: bloomq server

bloomq: bloomq.c bloom_host.h bloom_common.h
	$(CC) $(CFLAGS) -o bloomq bloomq.c

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
	rm -f bloomq /tmp/bloomq_*.blf
