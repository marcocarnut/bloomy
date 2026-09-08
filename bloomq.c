/* bloomq.c -- reseed39 bloom query, step 1 (the correctness core, no network yet).
 *
 * Loads a .blf (mmap), reads hex-encoded programs from stdin (one per line: a 20-byte
 * hash160 or 32-byte taproot key, i.e. 40 or 64 hex chars -- exactly what reseed39's
 * crackworker produces as `target.program`), and prints "HIT <hex>" for members. Silent on
 * misses (that's the wire protocol: respond only when found). The WS server (step 2) reuses
 * bloom_host_member() verbatim; this CLI exists so gate/e2e_parity.js can prove the probe
 * matches the reference cracker's `--bloom-check`.
 *
 *   usage: bloomq FILE.blf        # reads hex programs on stdin, HITs on stdout
 */
#include "bloom_host.h"
#include <ctype.h>

/* parse a hex line (leading/trailing space tolerated) into up to 32 bytes, zero-padded.
   returns the number of hex bytes decoded (20 or 32 expected), or -1 on a bad char. */
static int hex_to_prog(const char*line, uint8_t out[32]){
  memset(out,0,32);
  const char*s=line; while(*s && isspace((unsigned char)*s)) s++;
  int nib=0, val=0, nbytes=0;
  for(; *s && !isspace((unsigned char)*s); s++){
    int d; char c=*s;
    if(c>='0'&&c<='9') d=c-'0'; else if(c>='a'&&c<='f') d=c-'a'+10; else if(c>='A'&&c<='F') d=c-'A'+10;
    else return -1;
    val=(val<<4)|d; if(++nib==2){ if(nbytes>=32) return -1; out[nbytes++]=(uint8_t)val; nib=0; val=0; }
  }
  if(nib) return -1;               /* odd number of hex digits */
  return nbytes;
}

int main(int argc,char**argv){
  if(argc<2){ fprintf(stderr,"usage: %s FILE.blf   (reads hex programs from stdin)\n",argv[0]); return 2; }
  BloomSet A; if(bloom_host_load(argv[1],&A)) return 2;
  char line[256]; long q=0, hits=0, bad=0;
  while(fgets(line,sizeof line,stdin)){
    if(line[0]=='\n'||line[0]=='\0') continue;
    uint8_t prog[32]; int n=hex_to_prog(line,prog);
    if(n!=20 && n!=32){ bad++; continue; }              /* only h160(20) / taproot(32) */
    q++;
    if(bloom_host_member(&A,prog)){
      hits++;
      for(int i=0;i<n;i++) printf("%02x",prog[i]);       /* echo the program that hit */
      printf("\n"); fflush(stdout);
    }
  }
  fprintf(stderr,"bloomq: %ld queries, %ld hit(s), %ld skipped\n",q,hits,bad);
  return 0;
}
