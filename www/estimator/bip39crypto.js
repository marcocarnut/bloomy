// bip39crypto.js -- BIP39 seed + BIP32 hardened derivation + xpub chain-code
// compare, pure JS (browser + node). This is the correctness reference for the
// in-browser cracker (Batch 2): the xpub-target path is secp256k1-FREE --
// hardened derivation uses the parent PRIVATE key, so the account node's chain
// code is reached with only SHA-512/HMAC + a mod-n add. Compare that 32-byte
// chain code to the target xpub's and you've cracked it with zero elliptic curve.
//
// SHA-512 here is a clear BigInt implementation -- the CORRECTNESS reference,
// gated against the official BIP39/BIP32 vectors. The fast paths (Uint32-pair JS
// for the CPU cracker, WGSL for the GPU) will be gated byte-exact against THIS.
'use strict';

/* ------------------------------- SHA-512 -------------------------------- */
const M64 = (1n << 64n) - 1n;
const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M64;
const shr  = (x, n) => x >> n;
const K512 = [
  0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n,0x59f111f1b605d019n,0x923f82a4af194f9bn,0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n,0x12835b0145706fben,0x243185be4ee4b28cn,0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn,0x80deb1fe3b1696b1n,0x9bdc06a725c71235n,0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n,0xefbe4786384f25e3n,0x0fc19dc68b8cd5b5n,0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n,0x4a7484aa6ea6e483n,0x5cb0a9dcbd41fbd4n,0x76f988da831153b5n,
  0x983e5152ee66dfabn,0xa831c66d2db43210n,0xb00327c898fb213fn,0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n,0xd5a79147930aa725n,0x06ca6351e003826fn,0x142929670a0e6e70n,
  0x27b70a8546d22ffcn,0x2e1b21385c26c926n,0x4d2c6dfc5ac42aedn,0x53380d139d95b3dfn,
  0x650a73548baf63den,0x766a0abb3c77b2a8n,0x81c2c92e47edaee6n,0x92722c851482353bn,
  0xa2bfe8a14cf10364n,0xa81a664bbc423001n,0xc24b8b70d0f89791n,0xc76c51a30654be30n,
  0xd192e819d6ef5218n,0xd69906245565a910n,0xf40e35855771202an,0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n,0x1e376c085141ab53n,0x2748774cdf8eeb99n,0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n,0x4ed8aa4ae3418acbn,0x5b9cca4f7763e373n,0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn,0x78a5636f43172f60n,0x84c87814a1f0ab72n,0x8cc702081a6439ecn,
  0x90befffa23631e28n,0xa4506cebde82bde9n,0xbef9a3f7b2c67915n,0xc67178f2e372532bn,
  0xca273eceea26619cn,0xd186b8c721c0c207n,0xeada7dd6cde0eb1en,0xf57d4f7fee6ed178n,
  0x06f067aa72176fban,0x0a637dc5a2c898a6n,0x113f9804bef90daen,0x1b710b35131c471bn,
  0x28db77f523047d84n,0x32caab7b40c72493n,0x3c9ebe0a15c9bebcn,0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n,0x597f299cfc657e2an,0x5fcb6fab3ad6faecn,0x6c44198c4a475817n];
const H512_0 = [
  0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n];

// SHA-512 of a Uint8Array -> Uint8Array(64). BigInt REFERENCE (slow, gated-against).
function _sha512Big(bytes) {
  const l = bytes.length;
  const bitLen = BigInt(l) * 8n;
  // pad: 0x80, zeros to 112 mod 128, then 16-byte big-endian length
  const padLen = ((112 - (l + 1) % 128) + 128) % 128;
  const total = l + 1 + padLen + 16;
  const m = new Uint8Array(total);
  m.set(bytes); m[l] = 0x80;
  for (let i = 0; i < 16; i++) m[total - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
  const H = H512_0.slice();
  const W = new Array(80);
  for (let off = 0; off < total; off += 128) {
    for (let i = 0; i < 16; i++) {
      let w = 0n;
      for (let j = 0; j < 8; j++) w = (w << 8n) | BigInt(m[off + i * 8 + j]);
      W[i] = w;
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr(W[i-15],1n) ^ rotr(W[i-15],8n) ^ shr(W[i-15],7n);
      const s1 = rotr(W[i-2],19n) ^ rotr(W[i-2],61n) ^ shr(W[i-2],6n);
      W[i] = (W[i-16] + s0 + W[i-7] + s1) & M64;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr(e,14n) ^ rotr(e,18n) ^ rotr(e,41n);
      const ch = (e & f) ^ ((e ^ M64) & g);
      const t1 = (h + S1 + ch + K512[i] + W[i]) & M64;
      const S0 = rotr(a,28n) ^ rotr(a,34n) ^ rotr(a,39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) & M64;
      h=g; g=f; f=e; e=(d + t1) & M64; d=c; c=b; b=a; a=(t1 + t2) & M64;
    }
    H[0]=(H[0]+a)&M64; H[1]=(H[1]+b)&M64; H[2]=(H[2]+c)&M64; H[3]=(H[3]+d)&M64;
    H[4]=(H[4]+e)&M64; H[5]=(H[5]+f)&M64; H[6]=(H[6]+g)&M64; H[7]=(H[7]+h)&M64;
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) for (let j = 0; j < 8; j++)
    out[i*8 + j] = Number((H[i] >> BigInt(8 * (7 - j))) & 0xffn);
  return out;
}

/* --------------- fast SHA-512 (Uint32 hi/lo; gated vs BigInt) ------------ *
 * Constants are DERIVED from the gated BigInt K512/H512_0 above (no retyping).
 * ~1-2 orders of magnitude faster than the BigInt reference; byte-exact to it.  */
const _KH = Uint32Array.from(K512, k => Number((k >> 32n) & 0xffffffffn));
const _KL = Uint32Array.from(K512, k => Number(k & 0xffffffffn));
const _IH = Uint32Array.from(H512_0, k => Number((k >> 32n) & 0xffffffffn));
const _ILo = Uint32Array.from(H512_0, k => Number(k & 0xffffffffn));
const _WH = new Uint32Array(80), _WL = new Uint32Array(80);

function sha512(bytes) {
  const l = bytes.length;
  const padLen = ((112 - (l + 1) % 128) + 128) % 128;
  const total = l + 1 + padLen + 16;
  const m = new Uint8Array(total);
  m.set(bytes); m[l] = 0x80;
  const bl = BigInt(l) * 8n;
  for (let i = 0; i < 16; i++) m[total - 1 - i] = Number((bl >> BigInt(8 * i)) & 0xffn);
  let h0h=_IH[0],h0l=_ILo[0], h1h=_IH[1],h1l=_ILo[1], h2h=_IH[2],h2l=_ILo[2], h3h=_IH[3],h3l=_ILo[3],
      h4h=_IH[4],h4l=_ILo[4], h5h=_IH[5],h5l=_ILo[5], h6h=_IH[6],h6l=_ILo[6], h7h=_IH[7],h7l=_ILo[7];
  const WH=_WH, WL=_WL;
  for (let off = 0; off < total; off += 128) {
    for (let i = 0; i < 16; i++) {
      const j = off + i*8;
      WH[i] = (m[j]<<24)|(m[j+1]<<16)|(m[j+2]<<8)|m[j+3];
      WL[i] = (m[j+4]<<24)|(m[j+5]<<16)|(m[j+6]<<8)|m[j+7];
    }
    for (let i = 16; i < 80; i++) {
      const x1h=WH[i-15], x1l=WL[i-15];
      // sigma0 = rotr(1)^rotr(8)^shr(7)
      const s0h = ((x1h>>>1)|(x1l<<31)) ^ ((x1h>>>8)|(x1l<<24)) ^ (x1h>>>7);
      const s0l = ((x1l>>>1)|(x1h<<31)) ^ ((x1l>>>8)|(x1h<<24)) ^ ((x1l>>>7)|(x1h<<25));
      const x2h=WH[i-2], x2l=WL[i-2];
      // sigma1 = rotr(19)^rotr(61)^shr(6)   (61 -> m=29 cross form)
      const s1h = ((x2h>>>19)|(x2l<<13)) ^ ((x2l>>>29)|(x2h<<3)) ^ (x2h>>>6);
      const s1l = ((x2l>>>19)|(x2h<<13)) ^ ((x2h>>>29)|(x2l<<3)) ^ ((x2l>>>6)|(x2h<<26));
      // W[i] = W[i-16] + s0 + W[i-7] + s1   (64-bit add via lo carry)
      const a16h=WH[i-16],a16l=WL[i-16], a7h=WH[i-7],a7l=WL[i-7];
      let lo = (a16l>>>0)+(s0l>>>0); let hi = (a16h+s0h+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      let lo2 = lo+(a7l>>>0); hi = (hi+a7h+(lo2>=0x100000000?1:0))>>>0; lo2>>>=0;
      let lo3 = lo2+(s1l>>>0); hi = (hi+s1h+(lo3>=0x100000000?1:0))>>>0; lo3>>>=0;
      WH[i]=hi; WL[i]=lo3>>>0;
    }
    let ah=h0h,al=h0l, bh=h1h,bl=h1l, ch=h2h,cl=h2l, dh=h3h,dl=h3l,
        eh=h4h,el=h4l, fh=h5h,fl=h5l, gh=h6h,gl=h6l, hh=h7h,hl=h7l;
    for (let i = 0; i < 80; i++) {
      // S1 = rotr(e,14)^rotr(e,18)^rotr(e,41)   (41 -> m=9)
      const S1h = ((eh>>>14)|(el<<18)) ^ ((eh>>>18)|(el<<14)) ^ ((el>>>9)|(eh<<23));
      const S1l = ((el>>>14)|(eh<<18)) ^ ((el>>>18)|(eh<<14)) ^ ((eh>>>9)|(el<<23));
      const chh = (eh & fh) ^ (~eh & gh);
      const chl = (el & fl) ^ (~el & gl);
      // S0 = rotr(a,28)^rotr(a,34)^rotr(a,39)   (34 -> m=2, 39 -> m=7)
      const S0h = ((ah>>>28)|(al<<4)) ^ ((al>>>2)|(ah<<30)) ^ ((al>>>7)|(ah<<25));
      const S0l = ((al>>>28)|(ah<<4)) ^ ((ah>>>2)|(al<<30)) ^ ((ah>>>7)|(al<<25));
      const majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
      const majl = (al & bl) ^ (al & cl) ^ (bl & cl);
      // t1 = h + S1 + ch + K[i] + W[i]
      let lo=(hl>>>0)+(S1l>>>0); let hi=(hh+S1h+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      lo=lo+(chl>>>0); hi=(hi+chh+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      lo=lo+(_KL[i]>>>0); hi=(hi+_KH[i]+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      lo=lo+(WL[i]>>>0); hi=(hi+WH[i]+(lo>=0x100000000?1:0))>>>0; lo>>>=0;
      const t1h=hi, t1l=lo>>>0;
      // t2 = S0 + maj
      let lo2=(S0l>>>0)+(majl>>>0); let hi2=(S0h+majh+(lo2>=0x100000000?1:0))>>>0; lo2>>>=0;
      const t2h=hi2, t2l=lo2>>>0;
      hh=gh;hl=gl; gh=fh;gl=fl; fh=eh;fl=el;
      // e = d + t1
      let elo=(dl>>>0)+(t1l>>>0); eh=(dh+t1h+(elo>=0x100000000?1:0))>>>0; el=elo>>>0;
      dh=ch;dl=cl; ch=bh;cl=bl; bh=ah;bl=al;
      // a = t1 + t2
      let alo=(t1l>>>0)+(t2l>>>0); ah=(t1h+t2h+(alo>=0x100000000?1:0))>>>0; al=alo>>>0;
    }
    let lo;
    lo=(h0l>>>0)+(al>>>0); h0h=(h0h+ah+(lo>=0x100000000?1:0))>>>0; h0l=lo>>>0;
    lo=(h1l>>>0)+(bl>>>0); h1h=(h1h+bh+(lo>=0x100000000?1:0))>>>0; h1l=lo>>>0;
    lo=(h2l>>>0)+(cl>>>0); h2h=(h2h+ch+(lo>=0x100000000?1:0))>>>0; h2l=lo>>>0;
    lo=(h3l>>>0)+(dl>>>0); h3h=(h3h+dh+(lo>=0x100000000?1:0))>>>0; h3l=lo>>>0;
    lo=(h4l>>>0)+(el>>>0); h4h=(h4h+eh+(lo>=0x100000000?1:0))>>>0; h4l=lo>>>0;
    lo=(h5l>>>0)+(fl>>>0); h5h=(h5h+fh+(lo>=0x100000000?1:0))>>>0; h5l=lo>>>0;
    lo=(h6l>>>0)+(gl>>>0); h6h=(h6h+gh+(lo>=0x100000000?1:0))>>>0; h6l=lo>>>0;
    lo=(h7l>>>0)+(hl>>>0); h7h=(h7h+hh+(lo>=0x100000000?1:0))>>>0; h7l=lo>>>0;
  }
  const out = new Uint8Array(64);
  const put = (h,l,o)=>{ out[o]=(h>>>24)&255;out[o+1]=(h>>>16)&255;out[o+2]=(h>>>8)&255;out[o+3]=h&255;
                         out[o+4]=(l>>>24)&255;out[o+5]=(l>>>16)&255;out[o+6]=(l>>>8)&255;out[o+7]=l&255; };
  put(h0h,h0l,0);put(h1h,h1l,8);put(h2h,h2l,16);put(h3h,h3l,24);
  put(h4h,h4l,32);put(h5h,h5l,40);put(h6h,h6l,48);put(h7h,h7l,56);
  return out;
}
// The BigInt reference is kept (renamed) so the fast one can be gated against it.
function sha512Big(bytes) { return _sha512Big(bytes); }

/* --------- HMAC midstates (for the GPU: fixed key -> precompute ipad/opad) --- *
 * Compress ONE 128-byte block into a SHA-512 state (BigInt; host-side, run twice
 * per crack -- perf irrelevant). hmacMidstates(key) returns the SHA-512 state
 * after absorbing the ipad/opad blocks, as hi/lo u32 tables for the WGSL kernel,
 * so each per-lane HMAC is a single from-state block. Gated: GPU HMAC using these
 * must equal hmacSha512 (the full, already-gated reference).                     */
function _sha512CompressBig(H, block /* Uint8Array(128) */) {
  const W = new Array(80);
  for (let i = 0; i < 16; i++) { let w = 0n; for (let j = 0; j < 8; j++) w = (w << 8n) | BigInt(block[i*8+j]); W[i] = w; }
  for (let i = 16; i < 80; i++) {
    const s0 = rotr(W[i-15],1n) ^ rotr(W[i-15],8n) ^ shr(W[i-15],7n);
    const s1 = rotr(W[i-2],19n) ^ rotr(W[i-2],61n) ^ shr(W[i-2],6n);
    W[i] = (W[i-16] + s0 + W[i-7] + s1) & M64;
  }
  let [a,b,c,d,e,f,g,h] = H;
  for (let i = 0; i < 80; i++) {
    const S1 = rotr(e,14n)^rotr(e,18n)^rotr(e,41n);
    const ch = (e & f) ^ ((e ^ M64) & g);
    const t1 = (h + S1 + ch + K512[i] + W[i]) & M64;
    const S0 = rotr(a,28n)^rotr(a,34n)^rotr(a,39n);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) & M64;
    h=g; g=f; f=e; e=(d+t1)&M64; d=c; c=b; b=a; a=(t1+t2)&M64;
  }
  return [(H[0]+a)&M64,(H[1]+b)&M64,(H[2]+c)&M64,(H[3]+d)&M64,(H[4]+e)&M64,(H[5]+f)&M64,(H[6]+g)&M64,(H[7]+h)&M64];
}
function _stateToU32(state8) {   // -> Uint32Array(16), hi,lo interleaved
  const o = new Uint32Array(16);
  for (let i = 0; i < 8; i++) { o[i*2] = Number((state8[i] >> 32n) & 0xffffffffn); o[i*2+1] = Number(state8[i] & 0xffffffffn); }
  return o;
}
function hmacMidstates(key /* Uint8Array */) {
  let k = key; if (k.length > 128) k = sha512(k);
  const kp = new Uint8Array(128); kp.set(k);
  const ip = new Uint8Array(128), op = new Uint8Array(128);
  for (let i = 0; i < 128; i++) { ip[i] = kp[i] ^ 0x36; op[i] = kp[i] ^ 0x5c; }
  return { ipad: _stateToU32(_sha512CompressBig(H512_0, ip)),
           opad: _stateToU32(_sha512CompressBig(H512_0, op)) };
}
function _u32ToState(u32){ const s=[]; for(let i=0;i<8;i++) s.push((BigInt(u32[i*2])<<32n)|BigInt(u32[i*2+1])); return s; }
// Continue SHA-512 from `stateU32` (hi/lo) absorbing ONE more block whose data is
// `msg[0..msgLen)` (msgLen<=111), given `prior` bytes already hashed. Returns the
// 64-byte digest. This is exactly what the WGSL kernel does per HMAC half.
function sha512FromState1blk(stateU32, msg, msgLen, prior){
  const blk=new Uint8Array(128);
  for(let i=0;i<msgLen;i++) blk[i]=msg[i];
  blk[msgLen]=0x80;
  const bl=BigInt(prior+msgLen)*8n;
  for(let i=0;i<16;i++) blk[127-i]=Number((bl>>BigInt(8*i))&0xffn);
  const st=_sha512CompressBig(_u32ToState(stateU32), blk);
  const out=new Uint8Array(64);
  for(let i=0;i<8;i++) for(let j=0;j<8;j++) out[i*8+j]=Number((st[i]>>BigInt(8*(7-j)))&0xffn);
  return out;
}
// HMAC + PBKDF2 via precomputed midstates (the GPU decomposition; salt+4<=111).
function hmacViaMid(mid, msg){ return sha512FromState1blk(mid.opad, sha512FromState1blk(mid.ipad, msg, msg.length, 128), 64, 128); }
function pbkdf2ViaMid(mid, salt){
  let u = sha512FromState1blk(mid.ipad, concat(salt, Uint8Array.of(0,0,0,1)), salt.length+4, 128);
  u = sha512FromState1blk(mid.opad, u, 64, 128);
  const t = u.slice();
  for (let i=1;i<2048;i++){ u=sha512FromState1blk(mid.ipad,u,64,128); u=sha512FromState1blk(mid.opad,u,64,128); for(let j=0;j<64;j++) t[j]^=u[j]; }
  return t;
}

/* ------------------------------- HMAC/PBKDF2 ---------------------------- */
function hmacSha512(key, msg) {           // key,msg: Uint8Array -> Uint8Array(64)
  const B = 128;
  let k = key;
  if (k.length > B) k = sha512(k);
  const kpad = new Uint8Array(B); kpad.set(k);
  const ipad = new Uint8Array(B), opad = new Uint8Array(B);
  for (let i = 0; i < B; i++) { ipad[i] = kpad[i] ^ 0x36; opad[i] = kpad[i] ^ 0x5c; }
  const inner = sha512(concat(ipad, msg));
  return sha512(concat(opad, inner));
}
// PBKDF2-HMAC-SHA512, dkLen a multiple handled generally; BIP39 uses dkLen=64 (1 block).
function pbkdf2Sha512(password, salt, iterations, dkLen) {
  const hLen = 64, blocks = Math.ceil(dkLen / hLen);
  const out = new Uint8Array(blocks * hLen);
  for (let b = 1; b <= blocks; b++) {
    const bi = new Uint8Array(4); bi[0]=(b>>>24)&255; bi[1]=(b>>>16)&255; bi[2]=(b>>>8)&255; bi[3]=b&255;
    let u = hmacSha512(password, concat(salt, bi));
    const t = u.slice();
    for (let i = 1; i < iterations; i++) { u = hmacSha512(password, u); for (let j=0;j<hLen;j++) t[j] ^= u[j]; }
    out.set(t, (b-1)*hLen);
  }
  return out.slice(0, dkLen);
}

/* ------------------------------- BIP39 seed ----------------------------- */
const _enc = (typeof TextEncoder !== 'undefined') ? new TextEncoder() : null;
function utf8(s){ return _enc ? _enc.encode(s) : Uint8Array.from(Buffer.from(s,'utf8')); }
function nfkd(s){ return s.normalize('NFKD'); }
// BIP39: seed = PBKDF2(NFKD(mnemonic), "mnemonic"+NFKD(passphrase), 2048, 64).
function mnemonicToSeed(mnemonic, passphrase='') {
  return pbkdf2Sha512(utf8(nfkd(mnemonic)), utf8('mnemonic' + nfkd(passphrase)), 2048, 64);
}

/* ------------------------------- BIP32 ---------------------------------- */
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
function bytesToBig(b){ let x=0n; for (let i=0;i<b.length;i++) x=(x<<8n)|BigInt(b[i]); return x; }
function ser256(x){ const o=new Uint8Array(32); for(let i=31;i>=0;i--){o[i]=Number(x&0xffn);x>>=8n;} return o; }
function ser32(i){ return Uint8Array.of((i>>>24)&255,(i>>>16)&255,(i>>>8)&255,i&255); }
const HARD = 0x80000000;

// master node from seed: {k: BigInt priv, c: Uint8Array(32) chaincode}
function seedToMaster(seed){
  const I = hmacSha512(utf8('Bitcoin seed'), seed);
  return { k: bytesToBig(I.slice(0,32)), c: I.slice(32,64) };
}
// hardened CKDpriv (index already includes the 0x80000000 bit). No EC.
function ckdHardened(par, index){
  const data = concat(Uint8Array.of(0x00), ser256(par.k), ser32(index >>> 0));
  const I = hmacSha512(par.c, data);
  const IL = bytesToBig(I.slice(0,32));
  const k = (IL + par.k) % SECP_N;       // parse256(IL) < n assumed (holds w/ prob ~1)
  return { k, c: I.slice(32,64) };
}
// derive m / a' / b' / c' ... (all hardened) from seed; returns the final node.
function deriveHardenedPath(seed, hardIndices){
  let node = seedToMaster(seed);
  for (const i of hardIndices) node = ckdHardened(node, (i + HARD) >>> 0);
  return node;
}
// The account node m/purpose'/coin'/account' -- its chain code is what an account
// xpub carries, reachable with NO elliptic curve. purpose: 44|49|84|86, coin 0.
function accountNode(seed, purpose, account=0, coin=0){
  return deriveHardenedPath(seed, [purpose, coin, account]);
}

/* ------------------------------- base58check ---------------------------- */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const _sha256 = (typeof BIP39 !== 'undefined') ? BIP39.sha256
              : (typeof require === 'function') ? require('./bip39.js').sha256 : null;
function sha256d(b){ return _sha256(_sha256(b)); }
function b58decode(str){
  let x = 0n; for (const ch of str){ const v = B58.indexOf(ch); if (v<0) throw new Error('bad base58'); x = x*58n + BigInt(v); }
  const bytes=[]; while (x>0n){ bytes.unshift(Number(x & 0xffn)); x >>= 8n; }
  for (let i=0;i<str.length && str[i]==='1';i++) bytes.unshift(0);
  return Uint8Array.from(bytes);
}
function b58encode(bytes){
  let x = bytesToBig(bytes); let s='';
  while (x>0n){ const r=Number(x%58n); s=B58[r]+s; x/=58n; }
  for (let i=0;i<bytes.length && bytes[i]===0;i++) s='1'+s;
  return s;
}
function b58checkDecode(str){
  const raw=b58decode(str); const payload=raw.slice(0,-4), chk=raw.slice(-4);
  const h=sha256d(payload); for(let i=0;i<4;i++) if(h[i]!==chk[i]) throw new Error('bad base58check checksum');
  return payload;
}
function b58checkEncode(payload){
  const h=sha256d(payload); return b58encode(concat(payload, h.slice(0,4)));
}
// Decode an xpub/ypub/zpub -> {version, depth, fingerprint, childNumber, chainCode(32), key(33)}.
function decodeXpub(str){
  const p=b58checkDecode(str);
  if (p.length!==78) throw new Error('extended key must be 78 bytes, got '+p.length);
  return { version: bytesToBig(p.slice(0,4)), depth: p[4], fingerprint: p.slice(5,9),
           childNumber: bytesToBig(p.slice(9,13)), chainCode: p.slice(13,45), key: p.slice(45,78) };
}

/* ============================ secp256k1 (JS) ============================= *
 * Needed for the ADDRESS-target crack (the xpub path is EC-free; addresses
 * aren't). Field arithmetic mod P; Jacobian point ops (one modular inverse per
 * scalar mult, at the end); compressed 33-byte pubkey. Pure BigInt -- perf is a
 * few thousand mults/s, fine for the browser "small problems" the tool targets.
 * Gated: privToPub(vector priv) == the BIP32 vector-1 master pubkey.           */
const SECP_P  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const SECP_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const SECP_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const _P = SECP_P;
function _mod(a,m){ const r=a%m; return r<0n?r+m:r; }
function _modinv(a,m){                          // extended Euclid, a^-1 mod m
  a=_mod(a,m); let [old_r,r]=[a,m], [old_s,s]=[1n,0n];
  while (r!==0n){ const q=old_r/r; [old_r,r]=[r,old_r-q*r]; [old_s,s]=[s,old_s-q*s]; }
  return _mod(old_s,m);
}
// Jacobian point {X,Y,Z}; the point at infinity is Z==0.
const _INF = { X:0n, Y:1n, Z:0n };
function _jDouble(p){
  if (p.Z===0n || p.Y===0n) return _INF;
  const Y2=_mod(p.Y*p.Y,_P);
  const S=_mod(4n*p.X*Y2,_P);
  const M=_mod(3n*p.X*p.X,_P);              // a==0 for secp256k1
  const X3=_mod(M*M-2n*S,_P);
  const Y3=_mod(M*(S-X3)-8n*Y2*Y2,_P);
  const Z3=_mod(2n*p.Y*p.Z,_P);
  return {X:X3,Y:Y3,Z:Z3};
}
function _jAdd(p,q){
  if (p.Z===0n) return q; if (q.Z===0n) return p;
  const Z1Z1=_mod(p.Z*p.Z,_P), Z2Z2=_mod(q.Z*q.Z,_P);
  const U1=_mod(p.X*Z2Z2,_P), U2=_mod(q.X*Z1Z1,_P);
  const S1=_mod(p.Y*q.Z*Z2Z2,_P), S2=_mod(q.Y*p.Z*Z1Z1,_P);
  if (U1===U2){ return (S1===S2) ? _jDouble(p) : _INF; }
  const H=_mod(U2-U1,_P), R=_mod(S2-S1,_P);
  const HH=_mod(H*H,_P), HHH=_mod(H*HH,_P), V=_mod(U1*HH,_P);
  const X3=_mod(R*R-HHH-2n*V,_P);
  const Y3=_mod(R*(V-X3)-S1*HHH,_P);
  const Z3=_mod(p.Z*q.Z*H,_P);
  return {X:X3,Y:Y3,Z:Z3};
}
function _jToAffine(p){
  if (p.Z===0n) return null;                // infinity
  const zi=_modinv(p.Z,_P), zi2=_mod(zi*zi,_P), zi3=_mod(zi2*zi,_P);
  return { x:_mod(p.X*zi2,_P), y:_mod(p.Y*zi3,_P) };
}
function _scalarMult(k, ax, ay){             // k * (ax,ay) affine -> affine {x,y} or null
  k=_mod(k,SECP_N); if (k===0n) return null;
  let R=_INF; let Q={X:ax,Y:ay,Z:1n};
  while (k>0n){ if (k&1n) R=_jAdd(R,Q); Q=_jDouble(Q); k>>=1n; }
  return _jToAffine(R);
}
// Fixed-base comb table for G: table[i][j] = (j << 4i)*G, i=0..63, j=1..15.
// Every EC op in the address path is k*G (privToPub, ckdNormal's parent pubkey,
// the taproot tweak), so this replaces ~256 doublings + 128 adds with ~64 adds
// and no doublings -> the address crack's host EC gets several x faster. Built
// lazily once. pointFromPriv stays byte-exact (gated 25/25 in test_crypto.js).
let _combG = null;
const _COMB_W = 8, _COMB_NW = 32;               // 8-bit window: 32 point-adds / mult
function _buildCombG(){
  const WIN=1<<_COMB_W;                          // 256
  const tbl=new Array(_COMB_NW); for (let i=0;i<_COMB_NW;i++){ tbl[i]=new Array(WIN); tbl[i][0]=null; }
  // Build every table point in Jacobian, then ONE batch inversion to affine
  // (else 32*255 per-point inverses make the lazy init slow).
  const jp=[], meta=[];
  let base={X:SECP_GX,Y:SECP_GY,Z:1n};          // 256^i * G (i=0 -> G)
  for (let i=0;i<_COMB_NW;i++){
    let acc=_INF;
    for (let j=1;j<WIN;j++){ acc=_jAdd(acc, base); jp.push(acc); meta.push([i,j]); }
    for (let d=0;d<_COMB_W;d++) base=_jDouble(base);   // base *= 256
  }
  const zinv=_batchInv(jp.map(p=>p.Z));
  for (let t=0;t<jp.length;t++){ const p=jp[t], zi=zinv[t], zi2=_mod(zi*zi,_P), zi3=_mod(zi2*zi,_P);
    const m=meta[t]; tbl[m[0]][m[1]]={ x:_mod(p.X*zi2,_P), y:_mod(p.Y*zi3,_P) }; }
  return tbl;
}
function _combMulJ(k){                          // k*G via the comb -> Jacobian point (no inverse)
  k=_mod(k,SECP_N); if (k===0n) return _INF;
  if (!_combG) _combG=_buildCombG();
  let R=_INF;
  for (let i=0;i<_COMB_NW;i++){
    const byte=Number((k>>BigInt(i*_COMB_W))&255n);
    if (byte){ const a=_combG[i][byte]; R=_jAdd(R,{X:a.x,Y:a.y,Z:1n}); }
  }
  return R;
}
function pointFromPriv(k){                     // k*G -> affine {x,y} or null (one inverse)
  const R=_combMulJ(k); return (R.Z===0n)?null:_jToAffine(R);
}
// Montgomery batch inversion: N inverses in ONE modinv + ~3N muls.
function _batchInv(zs){
  const n=zs.length; if (!n) return [];
  const pref=new Array(n); pref[0]=_mod(zs[0],_P);
  for (let i=1;i<n;i++) pref[i]=_mod(pref[i-1]*zs[i],_P);
  let inv=_modinv(pref[n-1],_P);
  const out=new Array(n);
  for (let i=n-1;i>0;i--){ out[i]=_mod(inv*pref[i-1],_P); inv=_mod(inv*_mod(zs[i],_P),_P); }
  out[0]=inv; return out;
}
// Compressed pubkeys for a batch of privkeys with ONE modular inversion for the
// whole batch (the inverse is ~1/3 of a single privToPub, so this is the address
// crack's EC lever). Returns Uint8Array(33)[] (null entries for k==0).
function privToPubBatch(ks){
  const n=ks.length, pts=new Array(n);
  for (let i=0;i<n;i++){ const k=_mod(ks[i],SECP_N); pts[i]=(k===0n)?null:_combMulJ(k); }
  const idx=[], zs=[];
  for (let i=0;i<n;i++){ if (pts[i] && pts[i].Z!==0n){ idx.push(i); zs.push(pts[i].Z); } }
  const zinv=_batchInv(zs);
  const out=new Array(n).fill(null);
  for (let j=0;j<idx.length;j++){ const i=idx[j], p=pts[i], zi=zinv[j];
    const zi2=_mod(zi*zi,_P), zi3=_mod(zi2*zi,_P);
    out[i]=serPoint({ x:_mod(p.X*zi2,_P), y:_mod(p.Y*zi3,_P) });
  }
  return out;
}
function serPoint(pt){                       // affine -> 33-byte compressed
  const o=new Uint8Array(33); o[0]=(pt.y&1n)===0n?0x02:0x03;
  const xb=ser256(pt.x); o.set(xb,1); return o;
}
function privToPub(k){ return serPoint(pointFromPriv(k)); }            // 33-byte compressed
// lift_x per BIP340: x -> the even-y point on the curve (or null if not on curve).
function liftX(x){
  x=_mod(x,_P);
  const c=_mod(x*x%_P*x + 7n,_P);
  const y=_modpow(c,(_P+1n)/4n,_P);
  if (_mod(y*y,_P)!==c) return null;
  return { x, y: (y&1n)===0n ? y : _P-y };
}
function _modpow(b,e,m){ b=_mod(b,m); let r=1n; while(e>0n){ if(e&1n) r=_mod(r*b,m); b=_mod(b*b,m); e>>=1n; } return r; }

/* ---- non-hardened CKDpriv (needs the parent PUBKEY = one scalar mult) ---- */
// Variant taking the parent pubkey precomputed -- lets the address crack batch
// the scalar mults (privToPubBatch) across a candidate batch instead of one per
// derivation. ckdNormal is this with pub computed inline.
function ckdNormalPub(par, pub, index){
  if ((index>>>0) >= HARD) throw new Error('ckdNormal: index must be non-hardened (<2^31)');
  const I = hmacSha512(par.c, concat(pub, ser32(index>>>0)));
  const IL = bytesToBig(I.slice(0,32));
  return { k:(IL + par.k) % SECP_N, c:I.slice(32,64) };
}
function ckdNormal(par, index){
  if ((index>>>0) >= HARD) throw new Error('ckdNormal: index must be non-hardened (<2^31)');
  const pub = privToPub(par.k);
  const I = hmacSha512(par.c, concat(pub, ser32(index>>>0)));
  const IL = bytesToBig(I.slice(0,32));
  const k = (IL + par.k) % SECP_N;
  return { k, c: I.slice(32,64) };
}
// Derive to a receiving/change address key: m/purpose'/coin'/account'/change/index.
function addressNode(seed, purpose, account=0, coin=0, change=0, index=0){
  let node = deriveHardenedPath(seed, [purpose, coin, account]);
  node = ckdNormal(node, change);
  node = ckdNormal(node, index);
  return node;
}

/* ------------------------------- RIPEMD-160 ----------------------------- */
function ripemd160(msg){
  const rol=(x,n)=>((x<<n)|(x>>>(32-n)))>>>0;
  const rl=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
            3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
            4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
  const rr=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
            15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
            12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
  const sl=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
            11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
            9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
  const sr=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
            9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
            8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
  const KL=[0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e];
  const KR=[0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000];
  const f=(j,x,y,z)=> j<16?(x^y^z): j<32?((x&y)|(~x&z)): j<48?((x|~y)^z): j<64?((x&z)|(y&~z)):(x^(y|~z));
  const l=msg.length;
  const withOne=l+1; const k=(56-(withOne%64)+64)%64;
  const total=l+1+k+8; const m=new Uint8Array(total); m.set(msg); m[l]=0x80;
  const bl=l*8; m[total-8]=bl&255; m[total-7]=(bl>>>8)&255; m[total-6]=(bl>>>16)&255; m[total-5]=(bl>>>24)&255;
  let h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
  const X=new Int32Array(16);
  for (let off=0; off<total; off+=64){
    for (let i=0;i<16;i++){ const j=off+i*4; X[i]=(m[j]|(m[j+1]<<8)|(m[j+2]<<16)|(m[j+3]<<24)); }
    let al=h0,bl2=h1,cl=h2,dl=h3,el=h4, ar=h0,br=h1,cr=h2,dr=h3,er=h4;
    for (let j=0;j<80;j++){
      const rnd=j>>4;
      let t=(al + f(j,bl2,cl,dl) + X[rl[j]] + KL[rnd])|0; t=(rol(t>>>0, sl[j]) + el)|0;
      al=el; el=dl; dl=rol(cl>>>0,10); cl=bl2; bl2=t;
      let u=(ar + f(79-j,br,cr,dr) + X[rr[j]] + KR[rnd])|0; u=(rol(u>>>0, sr[j]) + er)|0;
      ar=er; er=dr; dr=rol(cr>>>0,10); cr=br; br=u;
    }
    const t=(h1+cl+dr)|0; h1=(h2+dl+er)|0; h2=(h3+el+ar)|0; h3=(h4+al+br)|0; h4=(h0+bl2+cr)|0; h0=t;
  }
  const o=new Uint8Array(20); const put=(h,p)=>{ o[p]=h&255;o[p+1]=(h>>>8)&255;o[p+2]=(h>>>16)&255;o[p+3]=(h>>>24)&255; };
  put(h0,0);put(h1,4);put(h2,8);put(h3,12);put(h4,16); return o;
}
function hash160(b){ return ripemd160(_sha256(b)); }

/* ---------------------------- bech32 / bech32m -------------------------- */
const _BECH='qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function _polymod(values){
  const GEN=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];
  let chk=1;
  for (const v of values){ const b=chk>>>25; chk=((chk&0x1ffffff)<<5)^v; for(let i=0;i<5;i++) if((b>>i)&1) chk^=GEN[i]; }
  return chk>>>0;
}
function _hrpExpand(hrp){ const o=[]; for(let i=0;i<hrp.length;i++) o.push(hrp.charCodeAt(i)>>5); o.push(0); for(let i=0;i<hrp.length;i++) o.push(hrp.charCodeAt(i)&31); return o; }
function _convertBits(data, from, to, pad){
  let acc=0,bits=0; const out=[]; const maxv=(1<<to)-1;
  for (const value of data){ acc=(acc<<from)|value; bits+=from; while(bits>=to){ bits-=to; out.push((acc>>bits)&maxv); } }
  if (pad){ if (bits) out.push((acc<<(to-bits))&maxv); }
  else if (bits>=from || ((acc<<(to-bits))&maxv)) return null;
  return out;
}
function bech32Encode(hrp, data, spec){                 // spec: 'bech32'|'bech32m'
  const CONST = spec==='bech32m' ? 0x2bc830a3 : 1;
  const values=_hrpExpand(hrp).concat(data);
  const polymod=_polymod(values.concat([0,0,0,0,0,0]))^CONST;
  const chk=[]; for(let i=0;i<6;i++) chk.push((polymod>>(5*(5-i)))&31);
  let s=hrp+'1'; for (const d of data.concat(chk)) s+=_BECH[d]; return s;
}
function bech32Decode(str){                              // -> {hrp, data(5-bit[]), spec} or null
  const lower=str.toLowerCase();
  if (str!==lower && str!==str.toUpperCase()) return null;
  const s=lower; const pos=s.lastIndexOf('1');
  if (pos<1 || pos+7>s.length) return null;
  const hrp=s.slice(0,pos); const data=[];
  for (let i=pos+1;i<s.length;i++){ const d=_BECH.indexOf(s[i]); if(d<0) return null; data.push(d); }
  const values=_hrpExpand(hrp).concat(data);
  const pm=_polymod(values);
  const spec = pm===1 ? 'bech32' : pm===0x2bc830a3 ? 'bech32m' : null;
  if (!spec) return null;
  return { hrp, data: data.slice(0,-6), spec };
}
// Encode a segwit address (witver 0 -> bech32, >=1 -> bech32m).
function segwitEncode(hrp, witver, program){
  const spec = witver===0 ? 'bech32':'bech32m';
  return bech32Encode(hrp, [witver].concat(_convertBits(Array.from(program),8,5,true)), spec);
}

/* --------------- address decode + per-purpose program build ------------- *
 * A "target" is {type, program}: p2pkh/p2sh -> 20-byte HASH160; p2wpkh ->
 * 20-byte HASH160 (witv0); p2tr -> 32-byte x-only tweaked key (witv1).       */
function decodeAddress(str){
  const low=str.toLowerCase();
  if (low.startsWith('bc1') || low.startsWith('tb1') || low.startsWith('bcrt1')){
    const d=bech32Decode(str); if(!d) throw new Error('bad bech32 address');
    const witver=d.data[0]; const prog=_convertBits(d.data.slice(1),5,8,false);
    if (!prog) throw new Error('bad witness program');
    const program=Uint8Array.from(prog);
    if (witver===0 && program.length===20){ if(d.spec!=='bech32') throw new Error('v0 must be bech32'); return {type:'p2wpkh', program, hrp:d.hrp}; }
    if (witver===1 && program.length===32){ if(d.spec!=='bech32m') throw new Error('v1 must be bech32m'); return {type:'p2tr', program, hrp:d.hrp}; }
    throw new Error('unsupported witness v'+witver+' len '+program.length);
  }
  const p=b58checkDecode(str);
  if (p.length!==21) throw new Error('bad base58 address length');
  if (p[0]===0x00) return {type:'p2pkh', program:p.slice(1)};
  if (p[0]===0x05) return {type:'p2sh',  program:p.slice(1)};
  throw new Error('unknown base58 address version 0x'+p[0].toString(16));
}
const _TAP_TAG = null;   // computed lazily
let _tapTweakMid=null;
function _taggedHash(tag, msg){ const th=_sha256(utf8(tag)); return _sha256(concat(th, th, msg)); }
// The script type a BIP purpose produces (for matching against a decoded target).
function purposeType(purpose){ return purpose===44?'p2pkh':purpose===49?'p2sh':purpose===84?'p2wpkh':purpose===86?'p2tr':null; }
// Build the {type,program} for a derived 33-byte compressed pubkey under a purpose.
function pubToTarget(pub33, purpose){
  if (purpose===44) return {type:'p2pkh',  program:hash160(pub33)};
  if (purpose===84) return {type:'p2wpkh', program:hash160(pub33)};
  if (purpose===49){ const redeem=concat(Uint8Array.of(0x00,0x14), hash160(pub33)); return {type:'p2sh', program:hash160(redeem)}; }
  if (purpose===86){                                   // BIP86 taproot
    const P=liftX(bytesToBig(pub33.slice(1)));
    const t=_mod(bytesToBig(_taggedHash('TapTweak', pub33.slice(1))), SECP_N);
    const tG=pointFromPriv(t);
    const Q=_jToAffine(_jAdd({X:P.x,Y:P.y,Z:1n}, {X:tG.x,Y:tG.y,Z:1n}));
    return {type:'p2tr', program:ser256(Q.x)};
  }
  throw new Error('unsupported purpose '+purpose);
}
// Encode a {type, program} target back to an address string -- the inverse of
// decodeAddress (mainnet hrp 'bc' by default). Handy for planting test targets.
function encodeAddress(target, hrp){
  const t=target.type, prog=target.program;
  hrp = hrp || 'bc';
  if (t==='p2pkh')  return b58checkEncode(concat(Uint8Array.of(0x00), prog));
  if (t==='p2sh')   return b58checkEncode(concat(Uint8Array.of(0x05), prog));
  if (t==='p2wpkh'){ if(prog.length!==20) throw new Error('p2wpkh program must be 20 bytes'); return segwitEncode(hrp, 0, prog); }
  if (t==='p2tr'){   if(prog.length!==32) throw new Error('p2tr program must be 32 bytes'); return segwitEncode(hrp, 1, prog); }
  throw new Error('unsupported address type '+t);
}
// Full: seed + path -> {type, program} for comparison to a decoded address.
function addressTarget(seed, purpose, account, coin, change, index){
  const node=addressNode(seed, purpose, account, coin, change, index);
  return pubToTarget(privToPub(node.k), purpose);
}

/* ------------- custom derivation-path templates (oddball wallets) --------- *
 * Many wallets predate/ignore BIP44's m/purpose'/coin'/account'/change/index:
 * Breadwallet/MultiBit HD use m/0'/0/i, Electrum-legacy m/0/i, etc. A template
 * is a BIP32 path with hardened markers (' or h) and the placeholders
 * {account}/{change}/{index} filled per candidate. The SEED is still BIP39
 * (salt "mnemonic") -- only the BIP32 path differs -- and the script type comes
 * from the pasted target (programForType), so the user specifies only the path. */
function parsePathTemplate(template){                 // -> array of {v|placeholder, hardened} (validates once)
  const parts = String(template).trim().split('/');
  if (parts[0] !== 'm' && parts[0] !== 'M') throw new Error("path must start with m/");
  const out = [];
  for (let i=1;i<parts.length;i++){
    let s = parts[i].trim(); if (s==='') continue;
    let hardened=false;
    if (/['h]$/.test(s)){ hardened=true; s=s.slice(0,-1); }
    if (s==='{account}'||s==='{change}'||s==='{index}') out.push({ ph:s, hardened });
    else { const n=parseInt(s,10); if(!Number.isInteger(n)||n<0||String(n)!==s) throw new Error('bad path segment "'+parts[i]+'"'); out.push({ v:n, hardened }); }
  }
  if (!out.length) throw new Error('empty path');
  return out;
}
function deriveTemplate(seed, template, vars){        // template: string OR parsed array
  const parsed = Array.isArray(template) ? template : parsePathTemplate(template);
  vars = vars || {};
  let node = seedToMaster(seed);
  for (const seg of parsed){
    const n = ('ph' in seg) ? (seg.ph==='{account}'?(vars.account|0):seg.ph==='{change}'?(vars.change|0):(vars.index|0)) : seg.v;
    node = seg.hardened ? ckdHardened(node, (n + HARD) >>> 0) : ckdNormal(node, n);
  }
  return node;
}
// Build the {type,program} for a pubkey given a target script TYPE (not a BIP
// purpose) -- used with custom paths, where the type comes from the target.
const _TYPE_PURPOSE = { p2pkh:44, p2sh:49, p2wpkh:84, p2tr:86 };
function programForType(pub33, type){
  const p=_TYPE_PURPOSE[type]; if(p===undefined) throw new Error('unsupported target type '+type);
  return pubToTarget(pub33, p);
}
// Which placeholders a parsed template uses (drives the estimator multiplier + loops).
function templatePlaceholders(parsed){
  const s={ account:false, change:false, index:false };
  for(const seg of parsed) if('ph' in seg) s[seg.ph.slice(1,-1)]=true;
  return s;
}
// Custom-path address match: sweep {account}x{change}x{index} of the template
// against a decoded target; returns {account,change,index} of a hit, else null.
// The single crack-side derivation site for custom paths (used on every backend).
function customMatch(seed, parsedTmpl, taddr, opts){
  opts = opts || {};
  const ph = opts.ph || templatePlaceholders(parsedTmpl);
  const changes = ph.change ? (opts.changes && opts.changes.length ? opts.changes : [0]) : [0];
  const gap = ph.index ? Math.max(1, opts.gap||1) : 1;
  const accounts = ph.account ? Math.max(1, opts.accounts||1) : 1;
  for (let a=0;a<accounts;a++) for (const ch of changes) for (let ix=0;ix<gap;ix++){
    const node = deriveTemplate(seed, parsedTmpl, {account:a, change:ch, index:ix});
    const tg = programForType(privToPub(node.k), taddr.type);
    if (tg.type===taddr.type && eq(tg.program, taddr.program)) return { account:a, change:ch, index:ix };
  }
  return null;
}

/* ------------------------------- helpers -------------------------------- */
function concat(...arrs){ let n=0; for(const a of arrs) n+=a.length; const o=new Uint8Array(n); let k=0; for(const a of arrs){o.set(a,k);k+=a.length;} return o; }
function toHex(b){ let s=''; for(let i=0;i<b.length;i++) s+=b[i].toString(16).padStart(2,'0'); return s; }
function fromHex(h){ const o=new Uint8Array(h.length/2); for(let i=0;i<o.length;i++) o[i]=parseInt(h.substr(i*2,2),16); return o; }
function eq(a,b){ if(a.length!==b.length) return false; for(let i=0;i<a.length;i++) if(a[i]!==b[i]) return false; return true; }

const _exports = {
  sha512, sha512Big, hmacSha512, pbkdf2Sha512, mnemonicToSeed,
  seedToMaster, ckdHardened, deriveHardenedPath, accountNode, SECP_N, ser256,
  b58decode, b58encode, b58checkDecode, b58checkEncode, decodeXpub,
  toHex, fromHex, concat, eq, utf8, nfkd,
  // SHA-512 K/H0 as hi/lo u32 tables (for the WGSL kernel; same gated constants).
  gpuK: { hi: _KH, lo: _KL }, gpuH0: { hi: _IH, lo: _ILo },
  // GPU HMAC midstate decomposition (host precompute + node gate).
  hmacMidstates, sha512FromState1blk, hmacViaMid, pbkdf2ViaMid,
  // secp256k1 + address-target crack (the EC path).
  SECP_P, pointFromPriv, privToPub, privToPubBatch, serPoint, liftX,
  ckdNormal, ckdNormalPub, addressNode,
  ripemd160, hash160,
  bech32Encode, bech32Decode, segwitEncode,
  decodeAddress, encodeAddress, purposeType, pubToTarget, addressTarget,
  parsePathTemplate, deriveTemplate, programForType, templatePlaceholders, customMatch,
};
if (typeof module !== 'undefined' && module.exports) module.exports = _exports;
if (typeof globalThis !== 'undefined') globalThis.BIP39Crypto = _exports; // window OR worker(self)
