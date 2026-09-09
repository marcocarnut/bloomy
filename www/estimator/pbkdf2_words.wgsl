// pbkdf2_words.wgsl -- PBKDF2-HMAC-SHA512(2048) BIP39 seed for WORDS mode.
// Unlike pbkdf2.wgsl (fixed mnemonic -> host precomputes ipad/opad midstates),
// here the MNEMONIC varies per lane (it's the HMAC key), so each lane builds its
// own ipad/opad midstates on the GPU from the mnemonic bytes, then runs the same
// 2048-iteration PBKDF2 against the FIXED salt ("mnemonic"+passphrase). The
// passphrase is fixed in words mode, so the salt is shared across lanes.
//
// Gated byte-exact vs bip39crypto.mnemonicToSeed on the Arc (12- and 24-word
// mnemonics, including keys >128 bytes that trigger the SHA-512 key pre-hash).
// v1 constraint: salt+4 <= 111 (one block for U_1 inner) -- host validates.

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
@group(0) @binding(1) var<storage,read> saltData: array<u32>;       // shared salt, big-endian packed
@group(0) @binding(2) var<storage,read> mnLen: array<u32>;          // per-lane mnemonic byte length
@group(0) @binding(3) var<storage,read> mnData: array<u32>;         // stride u32/lane, big-endian packed
@group(0) @binding(4) var<storage,read_write> outSeed: array<u32>;  // 16 u32 (64 bytes) / lane
@group(0) @binding(5) var<uniform> params: vec4<u32>;               // x=count, y=stride, z=iters, w=saltLen

// SHA-512 initial state (H0), hi/lo.
const H0: array<vec2<u32>,8> = array<vec2<u32>,8>(
  vec2<u32>(0x6a09e667u,0xf3bcc908u), vec2<u32>(0xbb67ae85u,0x84caa73bu),
  vec2<u32>(0x3c6ef372u,0xfe94f82bu), vec2<u32>(0xa54ff53au,0x5f1d36f1u),
  vec2<u32>(0x510e527fu,0xade682d1u), vec2<u32>(0x9b05688cu,0x2b3e6c1fu),
  vec2<u32>(0x1f83d9abu,0xfb41bd6bu), vec2<u32>(0x5be0cd19u,0x137e2179u));

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

fn fromState1(state: array<vec2<u32>,8>, msg: array<u32,28>, msgLen: u32, prior: u32) -> array<vec2<u32>,8> {
  var w: array<u32,32>;
  for (var i=0u;i<32u;i=i+1u){ w[i]=0u; }
  let fw = msgLen / 4u;
  for (var i=0u;i<fw;i=i+1u){ w[i]=msg[i]; }
  let rem = msgLen % 4u;
  if (rem==0u){ w[fw]=0x80000000u; }
  else { let sh=(3u-rem)*8u; w[fw]=msg[fw] | (0x80u<<sh); }
  w[31]=(prior+msgLen)*8u;
  return compress(state, w);
}

fn stateToMsg(s: array<vec2<u32>,8>) -> array<u32,28> {
  var m: array<u32,28>;
  for (var i=0u;i<28u;i=i+1u){ m[i]=0u; }
  for (var i=0u;i<8u;i=i+1u){ m[i*2u]=s[i].x; m[i*2u+1u]=s[i].y; }
  return m;
}

// key words (32 u32 = 128 bytes) for the HMAC, from the lane's mnemonic:
//  - len<=128: the mnemonic bytes, zero-padded to 128
//  - len >128: SHA-512(mnemonic) (64 bytes) then zero-padded to 128 (always 2 blocks here)
fn keyWords(base: u32, len: u32) -> array<u32,32> {
  var k: array<u32,32>;
  for (var i=0u;i<32u;i=i+1u){ k[i]=0u; }
  if (len <= 128u) {
    let nw = (len + 3u) / 4u;
    for (var i=0u;i<nw;i=i+1u){ k[i]=mnData[base+i]; }
    return k;
  }
  // key pre-hash: SHA-512 over `len` bytes (129..~215 -> exactly 2 blocks)
  var b0: array<u32,32>;
  for (var i=0u;i<32u;i=i+1u){ b0[i]=mnData[base+i]; }          // first 128 bytes
  var st = compress(H0, b0);
  var b1: array<u32,32>;
  for (var i=0u;i<32u;i=i+1u){ b1[i]=0u; }
  let rem = len - 128u;                                          // bytes into block 1 (1..~87)
  let fw = rem / 4u;
  for (var i=0u;i<fw;i=i+1u){ b1[i]=mnData[base+32u+i]; }
  let r = rem % 4u;
  if (r==0u){ b1[fw]=0x80000000u; } else { let sh=(3u-r)*8u; b1[fw]=mnData[base+32u+fw] | (0x80u<<sh); }
  b1[31]=len*8u;                                                 // 128-bit length low word
  st = compress(st, b1);
  for (var i=0u;i<8u;i=i+1u){ k[i*2u]=st[i].x; k[i*2u+1u]=st[i].y; }
  return k;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let lane = gid.x;
  if (lane >= params.x) { return; }
  let base = lane * params.y;
  let kw = keyWords(base, mnLen[lane]);

  // ipad/opad midstates from this lane's key
  var ib: array<u32,32>; var ob: array<u32,32>;
  for (var i=0u;i<32u;i=i+1u){ ib[i]=kw[i]^0x36363636u; ob[i]=kw[i]^0x5c5c5c5cu; }
  let ip = compress(H0, ib);
  let op = compress(H0, ob);

  // PBKDF2: U_1 over the FIXED salt||INT(1); salt is shared (params.w = saltLen).
  let sl = params.w;
  var msg: array<u32,28>;
  for (var i=0u;i<28u;i=i+1u){ msg[i]=0u; }
  let sw = (sl + 3u) / 4u;
  for (var i=0u;i<sw;i=i+1u){ msg[i]=saltData[i]; }
  let ipos = sl + 3u;
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
