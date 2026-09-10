/* bloom_host.h -- host-side .blf load + full membership probe for the reseed39 bloom
 * query server. NO GPU: unlike the CLI (where filter1 is probed on the GPU and this host
 * code is only the filter2 cull), here we probe BOTH filters on the CPU, mmap-backed so the
 * 14.5 GiB filter is paged in on demand (works on a 400 MiB box).
 *
 * The functions marked COPIED are byte-copied from bip39rxcrack-cli/src/bip39rxcrack.c and
 * cuda/bloom_common.h -- the correctness authority. Keep them in sync; gate/e2e_parity.js
 * proves this server's membership answers match the CLI's `--bloom-check` exactly. */
#ifndef BLOOM_HOST_H
#define BLOOM_HOST_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include "bloom_common.h"   /* COPIED from cuda/: bloom_probe, bloom_probe_classic, BLOOM_K */

/* 0: MADV_RANDOM (RAM-starved / slow disk, e.g. oniric). 1: pre-warm + MADV_WILLNEED for a
   host whose RAM holds the whole filter (set before bloom_host_load; --resident / RESIDENT=1). */
static int bloom_resident_mode = 0;

/* ---- COPIED from bip39rxcrack.c: host SHA-256 (filter2 keys on sha256(program)) ---- */
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256_host(const uint8_t*msg,size_t len,uint8_t out[32]){
  static const uint32_t K[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
  uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  size_t padlen=((len+8)/64+1)*64; uint8_t*m=calloc(padlen,1); memcpy(m,msg,len); m[len]=0x80;
  uint64_t bits=(uint64_t)len*8; for(int i=0;i<8;i++) m[padlen-1-i]=(uint8_t)(bits>>(8*i));
  for(size_t off=0;off<padlen;off+=64){
    uint32_t w[64];
    for(int i=0;i<16;i++) w[i]=((uint32_t)m[off+i*4]<<24)|((uint32_t)m[off+i*4+1]<<16)|((uint32_t)m[off+i*4+2]<<8)|m[off+i*4+3];
    for(int i=16;i<64;i++){ uint32_t s0=ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3); uint32_t s1=ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<64;i++){ uint32_t S1=ROR32(e,6)^ROR32(e,11)^ROR32(e,25); uint32_t ch=(e&f)^((~e)&g); uint32_t t1=hh+S1+ch+K[i]+w[i];
      uint32_t S0=ROR32(a,2)^ROR32(a,13)^ROR32(a,22); uint32_t maj=(a&b)^(a&c)^(b&c); uint32_t t2=S0+maj;
      hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
  }
  free(m); for(int i=0;i<8;i++){ out[i*4]=h[i]>>24; out[i*4+1]=h[i]>>16; out[i*4+2]=h[i]>>8; out[i*4+3]=h[i]; }
}

/* ---- COPIED from bip39rxcrack.c: classic (non-blocked) filter2 probe over sha256(prog) ---- */
static void classic_bits(const uint8_t*prog,unsigned long long*a,unsigned long long*b){
  uint8_t h[32]; sha256_host(prog,32,h);
  unsigned long long x=0,y=0; for(int i=0;i<8;i++){ x|=(unsigned long long)h[i]<<(8*i); y|=(unsigned long long)h[8+i]<<(8*i); }
  *a=x; *b=y|1ULL; }
static int classic_probe(const uint8_t*f,const uint8_t*prog,int log2bytes,int k2){
  unsigned long long a,b; classic_bits(prog,&a,&b); unsigned long long mask=((unsigned long long)1<<(log2bytes+3))-1;
  for(int i=0;i<k2;i++){ unsigned long long p=(a+(unsigned long long)i*b)&mask; if(!((f[p>>3]>>(p&7))&1)) return 0; } return 1; }

/* ---- COPIED from bip39rxcrack.c: .blf on-disk headers ---- */
#define BLF_MAGIC  0x32464C42u   /* 'BLF2' legacy: filter2 is ALSO a blocked bloom */
#define BLF3_MAGIC 0x33464C42u   /* 'BLF3' current: filter2 is a CLASSIC bloom */
typedef struct { uint32_t magic,version,nblocks1,nblocks2,k,npurp; uint32_t purposes[8]; uint64_t n_addrs; } BlfHeader;
typedef struct { uint32_t magic,version,nblocks1,f2_log2bytes,k1,k2,npurp,rsv; uint32_t purposes[8]; uint64_t n_addrs; } Blf3Header;

/* server-local filter handle (a subset of the CLI's AddrSet; only the probe fields) */
typedef struct { const uint32_t *prefilter; uint32_t prefilter_nblocks; int f1_classic, f1_k;
                 const uint32_t *host_filter; uint32_t host_filter_nblocks; int f2_classic, f2_log2bytes, f2_k2;
                 uint64_t n_addrs; void *base; size_t sz; } BloomSet;

/* mmap a .blf read-only and set the filter pointers (mirrors load_bloom_file's pointer
   setup; drops the GPU-hive content hash + the FPR print). Returns 0 on success. */
static int bloom_host_load(const char*path, BloomSet*A){
  memset(A,0,sizeof *A);
  int fd=open(path,O_RDONLY); if(fd<0){ fprintf(stderr,"bloom: cannot open %s\n",path); return 1; }
  struct stat st; if(fstat(fd,&st)){ close(fd); return 1; } size_t sz=(size_t)st.st_size;
  void*base=mmap(0,sz,PROT_READ,MAP_SHARED,fd,0); close(fd);
  if(base==MAP_FAILED){ fprintf(stderr,"bloom: mmap %s failed\n",path); return 1; }
  A->base=base; A->sz=sz;
  if(bloom_resident_mode){
    /* Big-RAM host: the whole filter fits in memory. Ask for it, then pre-warm by touching
       every page so it is fully resident BEFORE the first query (no cold faults on early
       traffic). No MADV_RANDOM here -- we WANT it cached and readahead helps the bulk warm. */
    (void)madvise(base, sz, MADV_WILLNEED);
    struct timespec w0,w1; clock_gettime(CLOCK_MONOTONIC,&w0);
    volatile uint8_t acc=0; const uint8_t*b=(const uint8_t*)base;
    for(size_t off=0; off<sz; off+=4096) acc ^= b[off];
    (void)acc; clock_gettime(CLOCK_MONOTONIC,&w1);
    double dt=(w1.tv_sec-w0.tv_sec)+(w1.tv_nsec-w0.tv_nsec)/1e9;
    fprintf(stderr,"bloom: resident mode -- pre-warmed %.2f GiB into RAM in %.1fs (%.0f MiB/s)\n",
            sz/1073741824.0, dt, sz/1048576.0/(dt>0?dt:1));
  } else {
    /* RAM-starved / slow-disk host (e.g. oniric): queries are scattered random probes, so
       default readahead just faults neighbour pages we never read and evicts useful cache.
       MADV_RANDOM measurably cuts wasted I/O. Advisory: ignore errors. */
    (void)madvise(base, sz, MADV_RANDOM);
  }
  uint32_t magic=*(uint32_t*)base;
  if(magic==BLF3_MAGIC){
    Blf3Header*h=(Blf3Header*)base; int f1_classic=(h->rsv==1);
    if(!f1_classic && h->k1!=BLOOM_K){ fprintf(stderr,"bloom: k1=%u != %d (rebuild)\n",h->k1,BLOOM_K); return 1; }
    size_t f1b=(size_t)h->nblocks1*32u;
    A->prefilter=(const uint32_t*)((uint8_t*)base+sizeof(Blf3Header)); A->prefilter_nblocks=h->nblocks1;
    A->f1_classic=f1_classic; A->f1_k=(int)h->k1;
    A->host_filter=(const uint32_t*)((uint8_t*)base+sizeof(Blf3Header)+f1b);
    A->f2_classic=1; A->f2_log2bytes=(int)h->f2_log2bytes; A->f2_k2=(int)h->k2;
    A->n_addrs=h->n_addrs;
    fprintf(stderr,"bloom: loaded %s (BLF3) -- %llu addresses, filter1 %.2f GiB %s, filter2 %.2f GiB classic k=%u\n",
            path,(unsigned long long)h->n_addrs,(double)f1b/1073741824.0,f1_classic?"classic":"blocked",
            (double)((size_t)1<<h->f2_log2bytes)/1073741824.0,h->k2);
    return 0;
  }
  if(magic==BLF_MAGIC){
    BlfHeader*h=(BlfHeader*)base; if(h->k!=BLOOM_K){ fprintf(stderr,"bloom: k=%u != %d (rebuild)\n",h->k,BLOOM_K); return 1; }
    size_t f1b=(size_t)h->nblocks1*32u;
    A->prefilter=(const uint32_t*)((uint8_t*)base+sizeof(BlfHeader)); A->prefilter_nblocks=h->nblocks1;
    A->f1_classic=0; A->f1_k=BLOOM_K;
    A->host_filter=(const uint32_t*)((uint8_t*)base+sizeof(BlfHeader)+f1b); A->host_filter_nblocks=h->nblocks2; A->f2_classic=0;
    A->n_addrs=h->n_addrs;
    fprintf(stderr,"bloom: loaded %s (BLF2, legacy) -- %llu addresses\n",path,(unsigned long long)h->n_addrs);
    return 0;
  }
  fprintf(stderr,"bloom: %s not a .blf (bad magic)\n",path); return 1;
}

/* full membership: filter1 (blocked or classic) AND filter2 (classic or legacy blocked).
   `prog` is 32 bytes -- a 20-byte hash160 or 32-byte taproot key, ZERO-PADDED to 32. */
static int bloom_host_member(const BloomSet*A, const uint8_t prog[32]){
  int f1 = A->f1_classic
    ? bloom_probe_classic(A->prefilter, prog, (unsigned long long)A->prefilter_nblocks*256ull, A->f1_k)
    : bloom_probe(A->prefilter, prog, A->prefilter_nblocks-1);
  if(!f1) return 0;
  if(A->f2_classic) return classic_probe((const uint8_t*)A->host_filter, prog, A->f2_log2bytes, A->f2_k2);
  uint8_t h[32]; sha256_host(prog,32,h); return bloom_probe(A->host_filter,h,A->host_filter_nblocks-1);
}
#endif
