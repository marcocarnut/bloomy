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
#include <ws.h>

static BloomSet g_bloom;   /* the mmap'd filter -- shared, read-only, across all connections */

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

static void onopen(ws_cli_conn_t c){ fprintf(stderr,"[open]  %s\n", ws_getaddress(c)); }
static void onclose(ws_cli_conn_t c){ fprintf(stderr,"[close] %s\n", ws_getaddress(c)); }

static void onmessage(ws_cli_conn_t c, const unsigned char *msg, uint64_t size, int type){
  (void)type;
  const char *p=(const char*)msg, *end=p+size;
  long processed=0;
  while(p<end){
    const char *nl=memchr(p,'\n',(size_t)(end-p));
    size_t ll = nl ? (size_t)(nl-p) : (size_t)(end-p);
    uint8_t prog[32]; int n=hex_to_prog(p,ll,prog);
    if(n==20||n==32){
      processed++;
      if(bloom_host_member(&g_bloom,prog)){
        char reply[72]="HIT "; for(int i=0;i<n;i++) snprintf(reply+4+i*2,3,"%02x",prog[i]);
        ws_sendframe_txt(c,reply);
      }
    }
    if(!nl) break;
    p=nl+1;
  }
  char ack[32]; snprintf(ack,sizeof ack,"ACK %ld",processed); ws_sendframe_txt(c,ack);
}

int main(int argc,char**argv){
  if(argc<2){ fprintf(stderr,"usage: %s FILE.blf [port] [www_root] [allow_ip ...]\n",argv[0]); return 2; }
  uint16_t port = argc>2 ? (uint16_t)atoi(argv[2]) : 8080;
  const char *www = argc>3 ? argv[3] : "./www";   /* GET / on the WS port serves this dir */
  if(bloom_host_load(argv[1],&g_bloom)) return 2;
  ws_set_www(www);
  char info[200]; snprintf(info,sizeof info,
    "{\"service\":\"reseed39-bloom\",\"version\":1,\"addresses\":%llu}", (unsigned long long)g_bloom.n_addrs);
  ws_set_bloom_info(info);   /* GET /bloom-info -> this JSON (the browser's feature-detect) */
  /* peer allowlist: localhost always; each extra arg is an allowed IP. No extra args = allow all. */
  ws_allow_ip("127.0.0.1");
  for(int i=4;i<argc;i++) ws_allow_ip(argv[i]);
  fprintf(stderr,"reseed39 bloom server: %llu addresses; WS + static (%s) on 0.0.0.0:%u",
          (unsigned long long)g_bloom.n_addrs, www, port);
  if(argc>4){ fprintf(stderr,"; allow 127.0.0.1"); for(int i=4;i<argc;i++) fprintf(stderr,",%s",argv[i]); }
  else fprintf(stderr,"; WARNING: no IP allowlist (accepting ALL)");
  fprintf(stderr,"\n");
  struct ws_server srv = {
    .host="0.0.0.0", .port=port, .thread_loop=0, .timeout_ms=0,
    .evs = { .onopen=onopen, .onclose=onclose, .onmessage=onmessage },
  };
  ws_socket(&srv);   /* blocks, one thread per client internally */
  return 0;
}
