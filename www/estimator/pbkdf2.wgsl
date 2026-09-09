// pbkdf2.wgsl -- PBKDF2-HMAC-SHA512(2048) BIP39 seed, one lane per candidate.
// The HMAC key is the FIXED mnemonic, so the host precomputes the ipad/opad
// SHA-512 midstates; every per-lane HMAC is then a single from-state block.
// Mirrors bip39crypto.pbkdf2ViaMid EXACTLY (node-gated). v1 constraint:
// salt+4 <= 111 bytes (one block for the U_1 inner) -- host validates.
//
// Gated byte-exact vs JS mnemonicToSeed on the Arc before being trusted.

fn add64(a:vec2<u32>,b:vec2<u32>)->vec2<u32>{ let lo=a.y+b.y; let c=select(0u,1u,lo<a.y); return vec2<u32>(a.x+b.x+c,lo); }
fn rotr64(x:vec2<u32>,r:u32)->vec2<u32>{
  if (r<32u){ return vec2<u32>((x.x>>r)|(x.y<<(32u-r)),(x.y>>r)|(x.x<<(32u-r))); }
  else if (r==32u){ return vec2<u32>(x.y,x.x); }
  else { let s=r-32u; return vec2<u32>((x.y>>s)|(x.x<<(32u-s)),(x.x>>s)|(x.y<<(32u-s))); }
}
fn shr64(x:vec2<u32>,s:u32)->vec2<u32>{
  if (s<32u){ return vec2<u32>(x.x>>s,(x.y>>s)|(x.x<<(32u-s))); }
  else { return vec2<u32>(0u,x.x>>(s-32u)); }
}

@group(0) @binding(0) var<storage,read> K: array<vec2<u32>,80>;
@group(0) @binding(1) var<storage,read> ipad: array<vec2<u32>,8>;   // midstate after ipad block
@group(0) @binding(2) var<storage,read> opad: array<vec2<u32>,8>;   // midstate after opad block
@group(0) @binding(3) var<storage,read> saltLen: array<u32>;        // per-lane salt byte length
@group(0) @binding(4) var<storage,read> saltData: array<u32>;       // stride u32/lane, big-endian packed
@group(0) @binding(5) var<storage,read_write> outSeed: array<u32>;  // 16 u32 (64 bytes) / lane
@group(0) @binding(6) var<uniform> params: vec4<u32>;               // x=count, y=stride, z=iters, w=0

// compress ONE 128-byte block (w = 32 u32 = 16 64-bit words) into `st`, return new state
fn compress(st: array<vec2<u32>,8>, w: array<u32,32>) -> array<vec2<u32>,8> {
  var W: array<vec2<u32>,80>;
  for (var i=0u;i<16u;i=i+1u){ W[i]=vec2<u32>(w[i*2u], w[i*2u+1u]); }
  for (var i=16u;i<80u;i=i+1u){
    let s0=(rotr64(W[i-15u],1u) ^ rotr64(W[i-15u],8u)) ^ shr64(W[i-15u],7u);
    let s1=(rotr64(W[i-2u],19u) ^ rotr64(W[i-2u],61u)) ^ shr64(W[i-2u],6u);
    W[i]=add64(add64(W[i-16u],s0), add64(W[i-7u],s1));
  }
  var a=st[0]; var b=st[1]; var c=st[2]; var d=st[3]; var e=st[4]; var f=st[5]; var g=st[6]; var h=st[7];
  for (var i=0u;i<80u;i=i+1u){
    let S1=(rotr64(e,14u) ^ rotr64(e,18u)) ^ rotr64(e,41u);
    let ch=(e & f) ^ (~e & g);
    let t1=add64(add64(add64(h,S1), add64(ch,K[i])), W[i]);
    let S0=(rotr64(a,28u) ^ rotr64(a,34u)) ^ rotr64(a,39u);
    let maj=(a & b) ^ (a & c) ^ (b & c);
    let t2=add64(S0,maj);
    h=g; g=f; f=e; e=add64(d,t1); d=c; c=b; b=a; a=add64(t1,t2);
  }
  var r: array<vec2<u32>,8>;
  r[0]=add64(st[0],a); r[1]=add64(st[1],b); r[2]=add64(st[2],c); r[3]=add64(st[3],d);
  r[4]=add64(st[4],e); r[5]=add64(st[5],f); r[6]=add64(st[6],g); r[7]=add64(st[7],h);
  return r;
}

// Continue from `state`, absorbing ONE more block: msg[0..msgLen) (msgLen<=111),
// with `prior` bytes already hashed. Returns the digest state (8 x vec2).
fn fromState1(state: array<vec2<u32>,8>, msg: array<u32,28>, msgLen: u32, prior: u32) -> array<vec2<u32>,8> {
  var w: array<u32,32>;
  for (var i=0u;i<32u;i=i+1u){ w[i]=0u; }
  let fw = msgLen / 4u;
  for (var i=0u;i<fw;i=i+1u){ w[i]=msg[i]; }
  let rem = msgLen % 4u;
  if (rem==0u){ w[fw]=0x80000000u; }
  else { let sh=(3u-rem)*8u; w[fw]=msg[fw] | (0x80u<<sh); }
  w[31]=(prior+msgLen)*8u;   // 128-bit length: low 32 bits (value < 2^32 here)
  return compress(state, w);
}

// pack a 64-byte digest state into the array<u32,28> message layout (first 16 words)
fn stateToMsg(s: array<vec2<u32>,8>) -> array<u32,28> {
  var m: array<u32,28>;
  for (var i=0u;i<28u;i=i+1u){ m[i]=0u; }
  for (var i=0u;i<8u;i=i+1u){ m[i*2u]=s[i].x; m[i*2u+1u]=s[i].y; }
  return m;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let lane = gid.x;
  if (lane >= params.x) { return; }
  let sl = saltLen[lane];
  let base = lane * params.y;
  var ip: array<vec2<u32>,8>; var op: array<vec2<u32>,8>;
  for (var i=0u;i<8u;i=i+1u){ ip[i]=ipad[i]; op[i]=opad[i]; }

  // U_1: inner over salt||INT(1); msg = salt bytes with a 0x01 at byte (sl+3)
  var msg: array<u32,28>;
  for (var i=0u;i<28u;i=i+1u){ msg[i]=0u; }
  let sw = (sl + 3u) / 4u;                 // ceil(sl/4) salt words
  for (var i=0u;i<sw;i=i+1u){ msg[i]=saltData[base+i]; }
  let ipos = sl + 3u;                      // the '1' byte of INT(1) big-endian
  let iw = ipos / 4u; let ish = (3u - (ipos % 4u)) * 8u;
  msg[iw] = msg[iw] | (1u << ish);

  var inner = fromState1(ip, msg, sl + 4u, 128u);
  var U = fromState1(op, stateToMsg(inner), 64u, 128u);
  var T: array<vec2<u32>,8>;
  for (var i=0u;i<8u;i=i+1u){ T[i]=U[i]; }

  let iters = params.z;
  for (var it=1u; it<iters; it=it+1u){
    inner = fromState1(ip, stateToMsg(U), 64u, 128u);
    U = fromState1(op, stateToMsg(inner), 64u, 128u);
    for (var i=0u;i<8u;i=i+1u){ T[i]=T[i]^U[i]; }
  }
  let o = lane * 16u;
  for (var i=0u;i<8u;i=i+1u){ outSeed[o+i*2u]=T[i].x; outSeed[o+i*2u+1u]=T[i].y; }
}
