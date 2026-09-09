/* pfbench.c -- SSD/page-fault cost of the mmap'd bloom probe, no WS/network.
 *
 * Answers "what does a query cost on a box that can't cache the whole filter?":
 * mmaps the .blf, probes N pseudo-random programs (the realistic all-misses cracking
 * load -- a real run virtually never hits), and reports wall time + major/minor page
 * faults from getrusage. Run it cold (after drop_caches) and warm; run several copies
 * at once for the concurrent-client ceiling.
 *
 *   pfbench FILE.blf NQUERIES [random|normal] [seed]
 *
 * "random" -> madvise(MADV_RANDOM) (no readahead; each probe faults only what it reads).
 * "normal" -> default kernel readahead. seed defaults to 1 (deterministic set).
 */
#include "bloom_host.h"
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>

/* xorshift64* -- deterministic program stream, independent of the filter. */
static uint64_t xs; static uint64_t nextr(void){
  xs^=xs>>12; xs^=xs<<25; xs^=xs>>27; return xs*0x2545F4914F6CDD1DULL; }

static double now_s(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
  return t.tv_sec + t.tv_nsec/1e9; }
static long majflt(void){ struct rusage r; getrusage(RUSAGE_SELF,&r); return r.ru_majflt; }
static long minflt(void){ struct rusage r; getrusage(RUSAGE_SELF,&r); return r.ru_minflt; }

int main(int argc,char**argv){
  if(argc<3){ fprintf(stderr,"usage: %s FILE.blf NQUERIES [random|normal] [seed]\n",argv[0]); return 2; }
  long N=atol(argv[2]);
  int rnd = argc>3 ? strcmp(argv[3],"normal")!=0 : 1;   /* default: MADV_RANDOM */
  xs = argc>4 ? (uint64_t)strtoull(argv[4],0,10) : 1ULL; if(!xs) xs=1;

  BloomSet A; if(bloom_host_load(argv[1],&A)) return 2;
  if(madvise(A.base, A.sz, rnd?MADV_RANDOM:MADV_NORMAL))
    fprintf(stderr,"pfbench: madvise warning (continuing)\n");

  long hits=0, f1hits=0;
  long mj0=majflt(), mn0=minflt(); double t0=now_s();
  for(long q=0;q<N;q++){
    uint8_t prog[32]; memset(prog,0,32);
    for(int i=0;i<20;i++) prog[i]=(uint8_t)(nextr()>>17);   /* 20-byte hash160 */
    /* count filter1 hits separately so we can see if any query reached filter2 (8 GiB) */
    int f1 = A.f1_classic
      ? bloom_probe_classic(A.prefilter,prog,(unsigned long long)A.prefilter_nblocks*256ull,A.f1_k)
      : bloom_probe(A.prefilter,prog,A.prefilter_nblocks-1);
    if(f1){ f1hits++; if(bloom_host_member(&A,prog)) hits++; }
  }
  double dt=now_s()-t0; long mj=majflt()-mj0, mn=minflt()-mn0;

  fprintf(stderr,
    "pfbench: %s | %ld queries | %.3fs | %.0f q/s | %.2f us/q | hits=%ld f1hits=%ld\n"
    "         majflt=%ld (%.4f/q)  minflt=%ld (%.4f/q)\n",
    rnd?"MADV_RANDOM":"MADV_NORMAL", N, dt, N/dt, dt/N*1e6, hits, f1hits,
    mj, (double)mj/N, mn, (double)mn/N);
  return 0;
}
