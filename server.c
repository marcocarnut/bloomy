/* server.c -- reseed39 bloom query server (step 2).
 *
 * mmaps a .blf ONCE (shared, read-only) and answers WebSocket queries: a client streams
 * hex-encoded programs (the 20/32-byte hash160/taproot reseed39 derives); the server probes
 * full membership (filter1 AND filter2) and replies "HIT <hex>" only for members. Because the
 * probe is stateless and the filter is read-only, wsServer's per-connection threads give
 * multi-client for free. Each client message may batch many programs (newline-separated); the
 * server sends any HIT lines then one "ACK <n>" so the client has flow-control / knows a batch
 * was processed (a browser can send "DONE" and treat the final ACK as "finished, nothing else").
 *
 *   usage: server FILE.blf [port]        (default port 8080)
 *
 * NOTE: this serves ONLY the WebSocket API. The reseed39 HTML bundle is served separately (any
 * static file server) for now; folding static serving in is a later step.
 */
#include "bloom_host.h"
#include <ctype.h>
#include <time.h>
#include <ws.h>

static BloomSet g_bloom;   /* the mmap'd filter -- shared, read-only, across all connections */

static double now_mono(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
  return t.tv_sec + t.tv_nsec/1e9; }

/* Per-connection accounting so the server can report the throughput it actually served,
   independent of whatever the browser client claims. One thread per connection, so no locks.
   Rate is over the ACTIVE window (first program processed .. last), which excludes idle time
   before the client starts and after it stops -- i.e. the sustained programs/s (= addr/s). */
typedef struct { double t_open, t_first, t_last; unsigned long long progs, hits, next_tick; } ConnStat;
#define TICK_EVERY 200000ULL   /* running rate line every N programs (0 disables) */

/* hex (up to 32 bytes) -> program, zero-padded. returns byte count, or -1 on a bad char. */
static int hex_to_prog(const char*s, size_t len, uint8_t out[32]){
  memset(out,0,32);
  size_t i=0; while(i<len && isspace((unsigned char)s[i])) i++;
  int nib=0,val=0,nb=0;
  for(; i<len && !isspace((unsigned char)s[i]); i++){
    int d; char c=s[i];
    if(c>='0'&&c<='9')d=c-'0'; else if(c>='a'&&c<='f')d=c-'a'+10; else if(c>='A'&&c<='F')d=c-'A'+10; else return -1;
    val=(val<<4)|d; if(++nib==2){ if(nb>=32) return -1; out[nb++]=(uint8_t)val; nib=0; val=0; }
  }
  return nib?-1:nb;
}

static void onopen(ws_cli_conn_t c){
  ConnStat *s = calloc(1,sizeof *s);
  if(s){ s->t_open = now_mono(); s->t_first = -1.0; s->next_tick = TICK_EVERY; ws_set_connection_context(c,s); }
  fprintf(stderr,"[open]  %s\n", ws_getaddress(c));
}
static void onclose(ws_cli_conn_t c){
  ConnStat *s = ws_get_connection_context(c);
  if(s){
    double conn = now_mono() - s->t_open;
    double active = (s->t_first >= 0.0) ? (s->t_last - s->t_first) : 0.0;
    if(active > 0.0)
      fprintf(stderr,"[close] %s | %llu programs, %llu hit(s) | active %.2fs = %.0f addr/s | conn %.1fs\n",
              ws_getaddress(c), s->progs, s->hits, active, (double)s->progs/active, conn);
    else
      fprintf(stderr,"[close] %s | %llu programs, %llu hit(s) | single burst (no rate) | conn %.1fs\n",
              ws_getaddress(c), s->progs, s->hits, conn);
    free(s); ws_set_connection_context(c,0);
  } else fprintf(stderr,"[close] %s\n", ws_getaddress(c));
}

static void onmessage(ws_cli_conn_t c, const unsigned char *msg, uint64_t size, int type){
  (void)type;
  ConnStat *s = ws_get_connection_context(c);
  double t0 = now_mono(); if(s && s->t_first < 0.0) s->t_first = t0;
  const char *p=(const char*)msg, *end=p+size;
  long processed=0, hitcount=0;
  while(p<end){
    const char *nl=memchr(p,'\n',(size_t)(end-p));
    size_t ll = nl ? (size_t)(nl-p) : (size_t)(end-p);
    uint8_t prog[32]; int n=hex_to_prog(p,ll,prog);
    if(n==20||n==32){
      processed++;
      if(bloom_host_member(&g_bloom,prog)){
        hitcount++;
        char reply[72]="HIT "; for(int i=0;i<n;i++) snprintf(reply+4+i*2,3,"%02x",prog[i]);
        ws_sendframe_txt(c,reply);
      }
    }
    if(!nl) break;
    p=nl+1;
  }
  char ack[32]; snprintf(ack,sizeof ack,"ACK %ld",processed); ws_sendframe_txt(c,ack);
  if(s){
    s->t_last = now_mono(); s->progs += (unsigned long long)processed; s->hits += (unsigned long long)hitcount;
    if(TICK_EVERY && s->progs >= s->next_tick){
      double active = s->t_last - s->t_first;
      if(active > 0.0)
        fprintf(stderr,"[rate]  %s | %llu programs so far | %.0f addr/s (active %.1fs)\n",
                ws_getaddress(c), s->progs, (double)s->progs/active, active);
      s->next_tick += TICK_EVERY;
    }
  }
}

int main(int argc,char**argv){
  if(argc<2){ fprintf(stderr,"usage: %s FILE.blf [port] [www_root] [allow_ip ...]\n",argv[0]); return 2; }
  uint16_t port = argc>2 ? (uint16_t)atoi(argv[2]) : 8080;
  const char *www = argc>3 ? argv[3] : "./www";   /* GET / on the WS port serves this dir */
  /* Bind address: default localhost (behind stunnel, all real traffic is from 127.0.0.1;
     never needs a public interface). Set BIND=0.0.0.0 for direct LAN testing. */
  const char *bind_host = getenv("BIND"); if(!bind_host||!bind_host[0]) bind_host="127.0.0.1";
  if(bloom_host_load(argv[1],&g_bloom)) return 2;
  ws_set_www(www);
  char info[200]; snprintf(info,sizeof info,
    "{\"service\":\"reseed39-bloom\",\"version\":1,\"addresses\":%llu}", (unsigned long long)g_bloom.n_addrs);
  ws_set_bloom_info(info);   /* GET /bloom-info -> this JSON (the browser's feature-detect) */
  /* peer allowlist: localhost always; each extra arg is an allowed IP. No extra args = allow all. */
  ws_allow_ip("127.0.0.1");
  for(int i=4;i<argc;i++) ws_allow_ip(argv[i]);
  fprintf(stderr,"reseed39 bloom server: %llu addresses; WS + static (%s) on %s:%u",
          (unsigned long long)g_bloom.n_addrs, www, bind_host, port);
  fprintf(stderr,"; allow 127.0.0.1"); for(int i=4;i<argc;i++) fprintf(stderr,",%s",argv[i]);
  fprintf(stderr,"\n");
  struct ws_server srv = {
    .host=bind_host, .port=port, .thread_loop=0, .timeout_ms=0,
    .evs = { .onopen=onopen, .onclose=onclose, .onmessage=onmessage },
  };
  ws_socket(&srv);   /* blocks, one thread per client internally */
  return 0;
}
