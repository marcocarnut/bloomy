/* bloomtool.c -- standalone, CPU-only (NO CUDA) build/append/query/stat for the reseed39
 * dual bloom filter. Format-identical to bip39rxcrack-cli's `--bloom-build --classic1`:
 * it shares bloom_common.h (bloom_insert_classic/bloom_probe_classic) and bloom_host.h
 * (sha256_host, classic_bits, classic_probe, Blf3Header, BloomSet, bloom_host_load,
 * bloom_host_member) with the reseed39 server, and copies the address-decode + sizing +
 * build/append/stat logic verbatim from bip39rxcrack.c. This lets the whole hedonic
 * pipeline (rebuild + daily tip-append + query) run with no GPU.
 *
 *   bloomtool build IN OUT --gib G1,G2 --n N [--classic1] [--other FILE]
 *   bloomtool append IN BLF          (IN='-' = stdin)
 *   bloomtool query BLF              (stdin: newline hex programs -> "HIT <hex>")
 *   bloomtool stat BLF               (Monte-Carlo measured FPR)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "bloom_common.h"   /* bloom_insert_classic, bloom_probe_classic, bloom_insert, bloom_probe, BLOOM_K */
#include "bloom_host.h"     /* sha256_host, classic_bits, classic_probe, Blf3Header/BLF3_MAGIC, BloomSet, bloom_host_load, bloom_host_member */

static double now_s(void){ struct timeval tv; gettimeofday(&tv,0); return tv.tv_sec+tv.tv_usec/1e6; }

/* ============ base58 + bech32 + decode_address (verbatim from bip39rxcrack.c) ============ */
static const char*B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static int b58decode(const char*s,uint8_t*out,int outmax){
  uint8_t tmp[128]; int tn=0; memset(tmp,0,sizeof tmp);
  for(const char*c=s;*c;c++){ const char*p=strchr(B58,*c); if(!p) return -1; int carry=(int)(p-B58);
    for(int i=0;i<tn;i++){ carry+=tmp[i]*58; tmp[i]=carry&0xff; carry>>=8; }
    while(carry){ if(tn>=(int)sizeof tmp) return -1; tmp[tn++]=carry&0xff; carry>>=8; } }
  int zeros=0; for(const char*c=s;*c==B58[0];c++) zeros++;
  int total=zeros+tn; if(total>outmax) return -1;
  for(int i=0;i<zeros;i++) out[i]=0;
  for(int i=0;i<tn;i++) out[zeros+i]=tmp[tn-1-i];
  return total;
}
static const char*BECH="qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static uint32_t bech_polymod(const uint8_t*v,int n){
  static const uint32_t G[5]={0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3};
  uint32_t chk=1;
  for(int i=0;i<n;i++){ uint32_t b=chk>>25; chk=((chk&0x1ffffff)<<5)^v[i]; for(int k=0;k<5;k++) if((b>>k)&1) chk^=G[k]; }
  return chk;
}
static int bech32_decode(const char*addr,int*witver,uint8_t*prog,int*proglen,int*is_m){
  char s[130]; int L=strlen(addr); if(L<8||L>120) return -1;
  for(int i=0;i<L;i++){ char c=addr[i]; if(c>='A'&&c<='Z') c=c-'A'+'a'; s[i]=c; } s[L]=0;
  int pos=-1; for(int i=L-1;i>=0;i--) if(s[i]=='1'){ pos=i; break; }
  if(pos<1||pos+7>L) return -1;
  int hlen=pos; uint8_t values[130]; int vn=0;
  for(int i=0;i<hlen;i++) values[vn++]=s[i]>>5;
  values[vn++]=0;
  for(int i=0;i<hlen;i++) values[vn++]=s[i]&31;
  int dstart=vn;
  for(int i=pos+1;i<L;i++){ const char*p=strchr(BECH,s[i]); if(!p) return -1; values[vn++]=(uint8_t)(p-BECH); }
  int dlen=vn-dstart;
  if(dlen<7) return -1;
  uint32_t pm=bech_polymod(values,vn);
  if(pm==1) *is_m=0; else if(pm==0x2bc830a3) *is_m=1; else return -1;
  const uint8_t*data=values+dstart;
  *witver=data[0];
  int n5=dlen-6-1; const uint8_t*d5=data+1;
  uint32_t acc=0; int bits=0; *proglen=0;
  for(int i=0;i<n5;i++){ acc=(acc<<5)|d5[i]; bits+=5; while(bits>=8){ bits-=8; prog[(*proglen)++]=(uint8_t)((acc>>bits)&0xff); } }
  if(bits>=5 || ((acc<<(8-bits))&0xff)) return -1;
  return 0;
}
static int g_decode_quiet=0;
static int decode_address(const char*addr,uint8_t prog[32],int*proglen,int*purpose){
  if(!strncmp(addr,"bc1",3)||!strncmp(addr,"tb1",3)||!strncmp(addr,"bcrt1",5)){
    int wv,pl,ism; if(bech32_decode(addr,&wv,prog,&pl,&ism)){ if(!g_decode_quiet)fprintf(stderr,"bad bech32 address\n"); return -1; }
    if(wv==0&&pl==20&&ism==0){ *purpose=84; *proglen=20; return 0; }
    if(wv==1&&pl==32&&ism==1){ *purpose=86; *proglen=32; return 0; }
    if(!g_decode_quiet)fprintf(stderr,"unsupported witness v%d len %d\n",wv,pl);
    return -1;
  }
  uint8_t raw[64]; int n=b58decode(addr,raw,sizeof raw);
  if(n!=25){ if(!g_decode_quiet)fprintf(stderr,"address base58 decode length %d (want 25)\n",n); return -1; }
  int ver=raw[0]; memcpy(prog,raw+1,20); *proglen=20;
  if(ver==0x00) *purpose=44; else if(ver==0x05) *purpose=49;
  else { if(!g_decode_quiet)fprintf(stderr,"unsupported address version 0x%02x\n",ver); return -1; }
  return 0;
}

/* ============ filter2 classic insert (over sha256(program)); classic_bits from bloom_host.h ============ */
static void classic_insert(uint8_t*f,const uint8_t*prog,int log2bytes,int k2){
  unsigned long long a,b; classic_bits(prog,&a,&b); unsigned long long mask=((unsigned long long)1<<(log2bytes+3))-1;
  for(int i=0;i<k2;i++){ unsigned long long p=(a+(unsigned long long)i*b)&mask; f[p>>3]|=(uint8_t)(1u<<(p&7)); } }

/* ============ sizing / FPR (verbatim from bip39rxcrack.c) ============ */
static double classic_fpr(unsigned long long bits,unsigned long long n,int k){
  if(!bits||!k) return 1.0;
  return pow(1.0-exp(-(double)k*(double)n/(double)bits),(double)k); }
static int classic_optk(unsigned long long bits,unsigned long long n){
  if(!n) return 1;
  int k=(int)lround(0.6931471805599453*(double)bits/(double)n); if(k<1)k=1; if(k>64)k=64; return k; }
static double blf_fpr(unsigned long long nblocks,unsigned long long n){
  if(!nblocks) return 1.0;
  const double B=256.0, k=16.0; double lambda=(double)n/(double)nblocks;
  double p0=exp(-lambda);
  if(p0<=0.0){ double km=k*lambda, a=pow(1.0-1.0/B,km), mu=B*(1.0-a);
    if(mu<=0.0) return 1.0;
    double var=B*a+B*(B-1.0)*pow(1.0-2.0/B,km)-B*B*a*a; if(var<0)var=0;
    double f=pow(mu/B,k)*(1.0+0.5*k*(k-1.0)*var/(mu*mu)); return f>1.0?1.0:f; }
  double s=0.0, pm=p0;
  for(int m=0;m<=1000;m++){ double km=k*(double)m;
    if(km>0){ double a=pow(1.0-1.0/B,km), mu=B*(1.0-a);
      double var=B*a + B*(B-1.0)*pow(1.0-2.0/B,km) - B*B*a*a; if(var<0)var=0;
      double f=pow(mu/B,k)*(1.0+0.5*k*(k-1.0)*var/(mu*mu)); if(f>1.0)f=1.0; s+=pm*f; }
    pm*=lambda/(m+1); if(m>(int)lambda+80 && pm<1e-20) break; }
  return s; }
static int gib_to_log2bytes(double gib){ if(gib<=0) return 0; int e=(int)lround(log2(gib*1073741824.0)); if(e<3)e=3; if(e>40)e=40; return e; }
static uint32_t gib_to_nblocks(double gib){ if(gib<=0) return 0; double b=gib*33554432.0; int e=(int)lround(log2(b)); if(e<4)e=4; if(e>30)e=30; return 1u<<e; }

/* ============ build (verbatim classic1/blocked path from build_bloom_file) ============ */
static int cmd_build(const char*infile,const char*outfile,unsigned long long n_hint,double fpr,
                     double gib1,double gib2,const char*other_file,int classic1){
  uint32_t nb1; int log2b2,k2; (void)fpr;
  FILE*of=0; if(other_file){ of=fopen(other_file,"w"); if(!of) fprintf(stderr,"warning: cannot write --other %s (continuing)\n",other_file); }
  if(gib1>0 && gib2>0){
    nb1 = classic1 ? (uint32_t)(gib1*33554432.0) : gib_to_nblocks(gib1);
    log2b2=gib_to_log2bytes(gib2);
    k2=classic_optk((unsigned long long)1<<(log2b2+3), n_hint?n_hint:1500000000ULL); }
  else { if(!n_hint){ fprintf(stderr,"build needs --n N (or --gib G1,G2)\n"); if(of)fclose(of); return 2; }
    fprintf(stderr,"build: --gib G1,G2 is required in bloomtool (explicit sizes)\n"); if(of)fclose(of); return 2; }
  size_t f1b=(size_t)nb1*32u, f2b=(size_t)1<<log2b2;
  unsigned long long f1bits=(unsigned long long)f1b*8ull;
  int k1 = classic1 ? classic_optk(f1bits, n_hint?n_hint:1500000000ULL) : (int)BLOOM_K;
  const char*f1kind = classic1 ? "classic" : "blocked";
  size_t hdr=sizeof(Blf3Header), total=hdr+f1b+f2b;
  int ofd=open(outfile,O_RDWR|O_CREAT|O_TRUNC,0644);
  if(ofd<0){ fprintf(stderr,"cannot create %s\n",outfile); if(of)fclose(of); return 2; }
  if(ftruncate(ofd,(off_t)total)){ fprintf(stderr,"ftruncate %s to %.2f GiB failed\n",outfile,(double)total/1073741824.0); close(ofd); if(of)fclose(of); return 2; }
  void*obase=mmap(0,total,PROT_READ|PROT_WRITE,MAP_SHARED,ofd,0); close(ofd);
  if(obase==MAP_FAILED){ fprintf(stderr,"mmap %s (%.2f GiB) failed\n",outfile,(double)total/1073741824.0); if(of)fclose(of); return 2; }
  uint32_t *f1=(uint32_t*)((uint8_t*)obase+hdr);
  uint8_t  *f2=(uint8_t*)obase+hdr+f1b;
  if(n_hint){ double fpr1=classic1?classic_fpr(f1bits,n_hint,k1):blf_fpr(nb1,n_hint); double efpr0=fpr1*classic_fpr((unsigned long long)f2b*8,n_hint,k2);
    fprintf(stderr,"build: filter1 %.2f GiB %s k1=%d + filter2 %.2f GiB classic k=%d, est FPR ~%.1e (VERIFY with stat), streaming...\n",
            (double)f1b/1073741824.0,f1kind,k1,(double)f2b/1073741824.0,k2,efpr0); }
  FILE*f=(!strcmp(infile,"-"))?stdin:fopen(infile,"r"); if(!f){ fprintf(stderr,"cannot open %s\n",infile); munmap(obase,total); unlink(outfile); if(of)fclose(of); return 2; }
  long n=0,bad=0,skip_wsh=0,skip_other=0; uint32_t purposes[8]; int npurp=0; char line[256];
  double t0=now_s(),tlast=t0;
  g_decode_quiet=1;
  while(fgets(line,sizeof line,f)){ char*s=line; while(*s==' '||*s=='\t')s++;
    char*e=s+strlen(s); while(e>s&&(e[-1]=='\n'||e[-1]=='\r'||e[-1]==' '||e[-1]=='\t')) *--e=0; if(!*s) continue;
    uint8_t pr[32]; memset(pr,0,32); int pl,pu; if(decode_address(s,pr,&pl,&pu)){
      if(!strncmp(s,"bc1",3)) skip_wsh++; else { skip_other++; if(of) fprintf(of,"%s\n",s); }
      bad++; continue; }
    (void)pl;
    if(classic1) bloom_insert_classic(f1,pr,f1bits,k1); else bloom_insert(f1,pr,nb1-1);
    classic_insert(f2,pr,log2b2,k2);
    int seen=0; for(int k=0;k<npurp;k++) if(purposes[k]==(uint32_t)pu) seen=1;
    if(!seen && npurp<8) purposes[npurp++]=(uint32_t)pu;
    n++; if((n&0xFFFFF)==0){ double now=now_s(); if(now-tlast>=2.0){ fprintf(stderr,"  ... %ld addresses inserted (%.2fM/s, %.0fs elapsed)\r",n,n/(now-t0)/1e6,now-t0); fflush(stderr); tlast=now; } } }
  if(f!=stdin) fclose(f);
  g_decode_quiet=0;
  if(of){ fclose(of); if(skip_other) fprintf(stderr,"build: wrote %ld 'other' unparseable line(s) to %s\n",skip_other,other_file); }
  if(!n){ fprintf(stderr,"build: no valid addresses\n"); munmap(obase,total); unlink(outfile); return 2; }
  if(bad) fprintf(stderr,"build: skipped %ld (%ld native-segwit/other-witness; %ld other)\n",bad,skip_wsh,skip_other);
  if(n_hint && (unsigned long long)n>n_hint) fprintf(stderr,"build: WARNING -- %ld addresses exceeds --n %llu; FPR higher than target\n",n,n_hint);
  double fpr1f=classic1?classic_fpr(f1bits,(uint64_t)n,k1):blf_fpr(nb1,(uint64_t)n);
  double efpr=fpr1f*classic_fpr((unsigned long long)f2b*8,(uint64_t)n,k2);
  Blf3Header*h=(Blf3Header*)obase; memset(h,0,sizeof *h); h->magic=BLF3_MAGIC; h->version=3; h->nblocks1=nb1; h->f2_log2bytes=(uint32_t)log2b2;
  h->k1=(uint32_t)k1; h->k2=(uint32_t)k2; h->npurp=(uint32_t)npurp; h->rsv=classic1?1u:0u;
  for(int i=0;i<npurp;i++) h->purposes[i]=purposes[i];
  h->n_addrs=(uint64_t)n;
  if(msync(obase,total,MS_SYNC)) fprintf(stderr,"warning: msync %s failed\n",outfile);
  munmap(obase,total);
  fprintf(stderr,"build: %ld addresses (%ld skipped), filter1 %.2f GiB %s k1=%d + filter2 %.2f GiB classic k=%d = %.2f GiB, %d purpose(s), est combined FPR ~%.1e -> %s\n",
          n,bad,(double)f1b/1073741824.0,f1kind,k1,(double)f2b/1073741824.0,k2,(double)(f1b+f2b)/1073741824.0,npurp,efpr,outfile);
  fprintf(stderr,"build: run `bloomtool stat %s` to MEASURE the true FPR.\n",outfile);
  return 0;
}

/* ============ append (verbatim from build_bloom_append) ============ */
static int cmd_append(const char*listfile,const char*blffile){
  int fd=open(blffile,O_RDWR); if(fd<0){ fprintf(stderr,"cannot open %s (read-write)\n",blffile); return 2; }
  struct stat st; if(fstat(fd,&st)){ close(fd); return 2; } size_t sz=(size_t)st.st_size;
  void*base=mmap(0,sz,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); close(fd);
  if(base==MAP_FAILED){ fprintf(stderr,"mmap %s read-write failed\n",blffile); return 2; }
  if(*(uint32_t*)base!=BLF3_MAGIC){ fprintf(stderr,"%s: not a BLF3 filter (rebuild)\n",blffile); munmap(base,sz); return 2; }
  Blf3Header*h=(Blf3Header*)base; int f1_classic=(h->rsv==1);
  size_t f1b=(size_t)h->nblocks1*32u;
  uint32_t*f1=(uint32_t*)((uint8_t*)base+sizeof(Blf3Header));
  uint8_t *f2=(uint8_t*)base+sizeof(Blf3Header)+f1b;
  unsigned long long f1bits=(unsigned long long)f1b*8ull;
  int k1=(int)h->k1, k2=(int)h->k2;
  uint32_t purposes[8]; int npurp=(int)h->npurp; for(int i=0;i<npurp&&i<8;i++) purposes[i]=h->purposes[i];
  fprintf(stderr,"append: %s (filter1 %.2f GiB %s k1=%d + filter2 classic k=%d, %llu addresses) <- %s ...\n",
          blffile,(double)f1b/1073741824.0,f1_classic?"classic":"blocked",k1,k2,(unsigned long long)h->n_addrs,
          (!strcmp(listfile,"-"))?"stdin":listfile);
  FILE*f=(!strcmp(listfile,"-"))?stdin:fopen(listfile,"r"); if(!f){ fprintf(stderr,"cannot open %s\n",listfile); munmap(base,sz); return 2; }
  long n=0,bad=0; char line[256]; double t0=now_s(),tlast=t0; g_decode_quiet=1;
  while(fgets(line,sizeof line,f)){ char*s=line; while(*s==' '||*s=='\t')s++;
    char*e=s+strlen(s); while(e>s&&(e[-1]=='\n'||e[-1]=='\r'||e[-1]==' '||e[-1]=='\t')) *--e=0; if(!*s) continue;
    uint8_t pr[32]; memset(pr,0,32); int pl,pu; if(decode_address(s,pr,&pl,&pu)){ bad++; continue; } (void)pl;
    if(f1_classic) bloom_insert_classic(f1,pr,f1bits,k1); else bloom_insert(f1,pr,h->nblocks1-1);
    classic_insert(f2,pr,h->f2_log2bytes,k2);
    int seen=0; for(int k=0;k<npurp;k++) if(purposes[k]==(uint32_t)pu) seen=1;
    if(!seen && npurp<8) purposes[npurp++]=(uint32_t)pu;
    n++; if((n&0xFFFFF)==0){ double now=now_s(); if(now-tlast>=1.0){ fprintf(stderr,"  ... +%ld appended (%.0f/s)\r",n,n/(now-t0)); fflush(stderr); tlast=now; } } }
  if(f!=stdin) fclose(f);
  g_decode_quiet=0;
  if(!n){ fprintf(stderr,"\nappend: no new valid addresses (%ld skipped); filter unchanged\n",bad); munmap(base,sz); return 0; }
  h->n_addrs += (uint64_t)n; h->npurp=(uint32_t)npurp; for(int i=0;i<npurp;i++) h->purposes[i]=purposes[i];
  unsigned long long tot=(unsigned long long)h->n_addrs;
  if(msync(base,sz,MS_SYNC)) fprintf(stderr,"warning: msync %s failed\n",blffile);
  munmap(base,sz);
  fprintf(stderr,"\nappend: +%ld addresses (%ld skipped) in %.0fs -> %llu total in %s.\n",n,bad,now_s()-t0,tot,blffile);
  fprintf(stderr,"append: FPR rose (bits only turn on) -- re-measure with `bloomtool stat %s`.\n",blffile);
  return 0;
}

/* ============ query (bloom_host_load + bloom_host_member from bloom_host.h) ============ */
static int hex_to_prog(const char*s,size_t len,uint8_t out[32]){
  memset(out,0,32); size_t i=0; while(i<len && isspace((unsigned char)s[i])) i++;
  int nib=0,val=0,nb=0;
  for(; i<len && !isspace((unsigned char)s[i]); i++){ int d; char c=s[i];
    if(c>='0'&&c<='9')d=c-'0'; else if(c>='a'&&c<='f')d=c-'a'+10; else if(c>='A'&&c<='F')d=c-'A'+10; else return -1;
    val=(val<<4)|d; if(++nib==2){ if(nb>=32) return -1; out[nb++]=(uint8_t)val; nib=0; val=0; } }
  return nib?-1:nb;
}
static int cmd_query(const char*blf){
  BloomSet A; if(bloom_host_load(blf,&A)) return 2;
  char line[256];
  while(fgets(line,sizeof line,stdin)){
    size_t ll=strlen(line); while(ll&&(line[ll-1]=='\n'||line[ll-1]=='\r'||line[ll-1]==' '||line[ll-1]=='\t')) line[--ll]=0;
    if(!ll) continue;
    uint8_t prog[32]; int nb=hex_to_prog(line,ll,prog);
    if(nb!=20 && nb!=32) continue;
    if(bloom_host_member(&A,prog)){ char hx[66]; for(int i=0;i<nb;i++) snprintf(hx+i*2,3,"%02x",prog[i]); printf("HIT %s\n",hx); }
  }
  return 0;
}

/* ============ stat (verbatim Monte-Carlo from mode_bloom_stat, using BloomSet) ============ */
static double fill_classic(const uint8_t*fb,size_t bytes){
  const unsigned long long*p=(const unsigned long long*)fb; size_t nq=bytes/8; unsigned long long set=0;
  for(size_t i=0;i<nq;i++) set+=(unsigned long long)__builtin_popcountll(p[i]);
  return (double)set/((double)bytes*8.0);
}
static int cmd_stat(const char*file){
  BloomSet A; if(bloom_host_load(file,&A)) return 2;
  if(!A.f1_classic){ fprintf(stderr,"stat: this build only measures classic filter1 (blocked f1 unsupported here)\n"); }
  size_t f1b=(size_t)A.prefilter_nblocks*32u; unsigned long long f1bits=(unsigned long long)f1b*8ull;
  double fill1=fill_classic((const uint8_t*)A.prefilter,f1b);
  fprintf(stderr,"filter 1 (CLASSIC k=%d): %.2f GiB (%llu bits), fill %.4f (%.2f%% set)\n",
          A.f1_k,(double)f1b/1073741824.0,f1bits,fill1,100*fill1);
  size_t f2b=(size_t)1<<A.f2_log2bytes;
  double fill2=fill_classic((const uint8_t*)A.host_filter,f2b);
  fprintf(stderr,"filter 2 (CLASSIC k=%d): %.2f GiB, fill %.4f (%.2f%% set)\n",A.f2_k2,(double)f2b/1073741824.0,fill2,100*fill2);
  unsigned long long R1 = 200000000ULL;
  unsigned long long s=0x9e3779b97f4a7c15ULL; unsigned long long f1=0,f2only=0,both=0;
  fprintf(stderr,"monte-carlo: probing %llu random programs (TRUE combined FPR)...\n",R1);
  for(unsigned long long i=0;i<R1;i++){
    uint8_t pr[32]; memset(pr,0,32);
    for(int b=0;b<20;b+=8){ s+=0x9e3779b97f4a7c15ULL; unsigned long long z=s; z=(z^(z>>30))*0xbf58476d1ce4e5b9ULL; z=(z^(z>>27))*0x94d049bb133111ebULL; z^=z>>31;
      for(int q=0;q<8&&b+q<20;q++) pr[b+q]=(uint8_t)(z>>(8*q)); }
    int h1 = A.f1_classic ? bloom_probe_classic(A.prefilter,pr,f1bits,A.f1_k) : bloom_probe(A.prefilter,pr,A.prefilter_nblocks-1);
    int h2 = classic_probe((const uint8_t*)A.host_filter,pr,A.f2_log2bytes,A.f2_k2);
    if(h1) f1++;
    if(h2) f2only++;
    if(h1&&h2) both++;
    if((i&0x3FFFFFFF)==0x3FFFFFFF) fprintf(stderr,"  ... %llu probed (f1=%llu f2=%llu both=%llu)\r",i+1,f1,f2only,both);
  }
  fprintf(stderr,"\n");
  double p1=(double)f1/R1, p2meas=(double)f2only/R1;
  double p2=(f2only==0)?pow(fill2,(double)A.f2_k2):p2meas;
  double comb=p1*p2;
  fprintf(stderr,"MEASURED over %llu random programs:\n",R1);
  fprintf(stderr,"  filter 1 FPR = %llu/%llu = %.3e\n",f1,R1,p1);
  if(f2only==0) fprintf(stderr,"  filter 2 FPR = 0/%llu (too rare) -> from fill: %.4f^%d = %.2e\n",R1,fill2,A.f2_k2,p2);
  else          fprintf(stderr,"  filter 2 FPR = %llu/%llu = %.3e\n",f2only,R1,p2meas);
  fprintf(stderr,"  COMBINED FPR ~ %.2e%s\n",comb,(both>0)?"  (measured combined hits>0!)":"");
  fprintf(stderr,"  => ~%.2g false positive(s) over a 1e12 sweep.\n",comb*1e12);
  return 0;
}

int main(int argc,char**argv){
  if(argc<3){
    fprintf(stderr,"usage:\n"
      "  %s build IN OUT --gib G1,G2 --n N [--classic1] [--other FILE]\n"
      "  %s append IN BLF\n"
      "  %s query BLF        (stdin: hex programs -> HIT lines)\n"
      "  %s stat BLF\n",argv[0],argv[0],argv[0],argv[0]);
    return 2;
  }
  const char*cmd=argv[1];
  if(!strcmp(cmd,"query")) return cmd_query(argv[2]);
  if(!strcmp(cmd,"stat"))  return cmd_stat(argv[2]);
  if(!strcmp(cmd,"append")){ if(argc<4){ fprintf(stderr,"append IN BLF\n"); return 2; } return cmd_append(argv[2],argv[3]); }
  if(!strcmp(cmd,"build")){
    if(argc<4){ fprintf(stderr,"build IN OUT --gib G1,G2 --n N [--classic1] [--other FILE]\n"); return 2; }
    const char*in=argv[2],*out=argv[3]; double gib1=0,gib2=0; unsigned long long nn=0; int classic1=0; const char*other=0; double fpr=1e-12;
    for(int i=4;i<argc;i++){
      if(!strcmp(argv[i],"--gib")&&i+1<argc){ sscanf(argv[++i],"%lf,%lf",&gib1,&gib2); }
      else if(!strcmp(argv[i],"--n")&&i+1<argc) nn=strtoull(argv[++i],0,10);
      else if(!strcmp(argv[i],"--classic1")) classic1=1;
      else if(!strcmp(argv[i],"--other")&&i+1<argc) other=argv[++i];
      else { fprintf(stderr,"unknown build arg: %s\n",argv[i]); return 2; }
    }
    return cmd_build(in,out,nn,fpr,gib1,gib2,other,classic1);
  }
  fprintf(stderr,"unknown command: %s\n",cmd); return 2;
}
