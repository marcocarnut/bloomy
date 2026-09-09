// bip39.js -- BIP39 mnemonic checksum validation, pure JS (browser + node).
//
// This is NEW estimator code (not librxe): it lets the model measure the
// checksum-survival fraction of a mnemonic pattern -- exact by enumeration
// when the set is small, sampled otherwise. Only ENGLISH is wired here; the
// other nine official lists slot in the same way (word->index map + this same
// checksum math) when words/joint mode needs them.
//
// A BIP39 mnemonic of W words carries ENT = W*11*32/33 entropy bits and
// CS = W/3 checksum bits (12w->4, 24w->8). The checksum bits are the top CS
// bits of SHA256(entropy). Only 1 in 2^CS random word tuples is valid.

'use strict';

/* ---- compact SHA-256 (works identically in node and the browser) -------- */
function sha256(bytes) {
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
      h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const l = bytes.length;
  const withOne = l + 1;
  const k = (56 - (withOne % 64) + 64) % 64;
  const total = withOne + k + 8;
  const m = new Uint8Array(total);
  m.set(bytes);
  m[l] = 0x80;
  const bitLenHi = Math.floor((l * 8) / 0x100000000);
  const bitLenLo = (l * 8) >>> 0;
  m[total-8]=(bitLenHi>>>24)&0xff; m[total-7]=(bitLenHi>>>16)&0xff;
  m[total-6]=(bitLenHi>>>8)&0xff;  m[total-5]=bitLenHi&0xff;
  m[total-4]=(bitLenLo>>>24)&0xff; m[total-3]=(bitLenLo>>>16)&0xff;
  m[total-2]=(bitLenLo>>>8)&0xff;  m[total-1]=bitLenLo&0xff;
  const w = new Uint32Array(64);
  const rotr=(x,n)=>(x>>>n)|(x<<(32-n));
  for (let off=0; off<total; off+=64) {
    for (let i=0;i<16;i++)
      w[i]=(m[off+4*i]<<24)|(m[off+4*i+1]<<16)|(m[off+4*i+2]<<8)|(m[off+4*i+3]);
    for (let i=16;i<64;i++){
      const s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);
      const s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i=0;i<64;i++){
      const S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
      const ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+K[i]+w[i])|0;
      const S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
      const maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)|0;
      h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
    }
    h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;
    h4=(h4+e)|0;h5=(h5+f)|0;h6=(h6+g)|0;h7=(h7+h)|0;
  }
  const out=new Uint8Array(32);
  const hs=[h0,h1,h2,h3,h4,h5,h6,h7];
  for (let i=0;i<8;i++){ out[4*i]=(hs[i]>>>24)&0xff; out[4*i+1]=(hs[i]>>>16)&0xff;
    out[4*i+2]=(hs[i]>>>8)&0xff; out[4*i+3]=hs[i]&0xff; }
  return out;
}

/* ---- fast single-block SHA-256 for the CHECKSUM early-reject ------------- *
 * The BIP39 checksum hashes only the entropy (16..32 bytes -> always ONE
 * 64-byte block) and needs only the top CS<=8 bits, which live in the first
 * output word (h0). This specialization hoists K to module scope, reuses the
 * block/schedule buffers (no per-call allocation), computes a single block, and
 * returns h0 alone -- ~3.4x the compact sha256 (measured, spike/sha256-bench.js)
 * so one core clears the ~2.8M/s needed to keep the GPU seed kernel fed.
 * Byte-exact with the top word of sha256() -- gated in test/test_crypto.js.
 * Requires bytes.length <= 55 (true for every BIP39 entropy size). */
const _K32 = new Int32Array([
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
const _blk1 = new Uint8Array(64);
const _w64  = new Int32Array(64);
function sha256_1blk_h0(bytes) {           // bytes.length must be <= 55
  const l = bytes.length;
  _blk1.fill(0);
  _blk1.set(bytes);
  _blk1[l] = 0x80;
  const bits = l * 8;                       // < 2^32 for l<=55 -> hi length words 0
  _blk1[60] = (bits>>>24)&0xff; _blk1[61] = (bits>>>16)&0xff;
  _blk1[62] = (bits>>>8)&0xff;  _blk1[63] =  bits&0xff;
  const w = _w64;
  for (let i=0;i<16;i++)
    w[i]=(_blk1[4*i]<<24)|(_blk1[4*i+1]<<16)|(_blk1[4*i+2]<<8)|_blk1[4*i+3];
  for (let i=16;i<64;i++){
    const x=w[i-15], y=w[i-2];
    const s0=((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3);
    const s1=((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10);
    w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
  }
  let a=0x6a09e667|0,b=0xbb67ae85|0,c=0x3c6ef372|0,d=0xa54ff53a|0,
      e=0x510e527f|0,f=0x9b05688c|0,g=0x1f83d9ab|0,h=0x5be0cd19|0;
  for (let i=0;i<64;i++){
    const S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
    const ch=(e&f)^(~e&g);
    const t1=(h+S1+ch+_K32[i]+w[i])|0;
    const S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
    const maj=(a&b)^(a&c)^(b&c);
    const t2=(S0+maj)|0;
    h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
  }
  return (0x6a09e667 + a)|0;                // h0 (== big-endian bytes [0..3] of the digest)
}

/* ---- BIP39 wordlist -> checksum validator ------------------------------- */
// Valid BIP39 mnemonic word counts and their (ENT bytes, checksum bits).
const VALID_WORD_COUNTS = new Set([12,15,18,21,24]);

// Build a validator bound to one wordlist (array of 2048 words, index order).
function makeValidator(words) {
  if (words.length !== 2048) throw new Error(`wordlist must be 2048 words, got ${words.length}`);
  const index = new Map();
  for (let i=0;i<2048;i++) index.set(words[i], i);

  // Is this space/whitespace-joined mnemonic checksum-valid?
  function isValid(mnemonic) {
    const toks = mnemonic.trim().split(/\s+/);
    const W = toks.length;
    if (!VALID_WORD_COUNTS.has(W)) return false;
    // pack W*11 bits
    const totalBits = W * 11;
    const entBits = (totalBits * 32) / 33;   // integer for valid W
    const csBits = totalBits - entBits;       // = W/3
    const bits = new Uint8Array(totalBits);
    for (let i=0;i<W;i++){
      const idx = index.get(toks[i]);
      if (idx === undefined) return false;    // not a wordlist word
      for (let b=0;b<11;b++) bits[i*11+b] = (idx >>> (10-b)) & 1;
    }
    const entBytesLen = entBits/8;
    const ent = new Uint8Array(entBytesLen);
    for (let i=0;i<entBits;i++) if (bits[i]) ent[i>>3] |= (0x80 >> (i&7));
    // Checksum = top csBits (<=8) of SHA256(ent), which live in the digest's
    // first byte == top byte of h0. Use the no-alloc single-block hasher.
    const hb0 = (sha256_1blk_h0(ent) >>> 24) & 0xff;
    for (let i=0;i<csBits;i++){
      const hb = (hb0 >> (7-i)) & 1;
      if (hb !== bits[entBits+i]) return false;
    }
    return true;
  }

  // "Generate valid" mode: given a mnemonic whose LAST word is a scaffold
  // placeholder (or any word), recompute the correct final word so the whole
  // mnemonic is checksum-valid, and return it. Only the last word's HIGH
  // (11-CS) bits are entropy; we recompute the LOW CS checksum bits from the
  // full entropy and overwrite them: corrected = (freeBits<<CS) | checksum.
  // Idempotent on an already-valid mnemonic (returns the same last word).
  // Returns null on a bad word count or an unknown word. `toks` = word array.
  function completeLastWord(toks) {
    const W = toks.length;
    if (!VALID_WORD_COUNTS.has(W)) return null;
    const totalBits = W * 11;
    const entBits = (totalBits * 32) / 33;
    const csBits = totalBits - entBits;                 // = W/3
    const bits = new Uint8Array(totalBits);
    for (let i=0;i<W;i++){
      const idx = index.get(toks[i]);
      if (idx === undefined) return null;
      for (let b=0;b<11;b++) bits[i*11+b] = (idx >>> (10-b)) & 1;
    }
    const ent = new Uint8Array(entBits/8);
    for (let i=0;i<entBits;i++) if (bits[i]) ent[i>>3] |= (0x80 >> (i&7));
    const hb0 = (sha256_1blk_h0(ent) >>> 24) & 0xff;    // top byte of SHA256(entropy)
    const checksum = hb0 >>> (8 - csBits);              // top CS bits
    const lastIdx = index.get(toks[W-1]);
    const free = lastIdx >>> csBits;                    // this word's high (11-CS) entropy bits
    return words[(free << csBits) | checksum];
  }
  // Convenience over a whitespace-joined string: returns the corrected mnemonic
  // string (last word swapped to the checksum-valid one), or null if malformed.
  function complete(mnemonic) {
    const toks = mnemonic.trim().split(/\s+/);
    const last = completeLastWord(toks);
    if (last === null) return null;
    toks[toks.length-1] = last;
    return toks.join(' ');
  }

  return { isValid, complete, completeLastWord, words, index,
    // theoretical survival fraction for a full-entropy pattern of W words
    theoreticalFraction: (W) => VALID_WORD_COUNTS.has(W) ? Math.pow(2, -(W/3)) : null };
}

/* ---- [:Nth:] last-word scaffolds (cardinality devices for generate mode) --- *
 * The final word of a W-word mnemonic carries CS=W/3 checksum bits in its LOW
 * bits and 11-CS free entropy bits in its HIGH bits. A scaffold dictionary of
 * exactly 2^(11-CS) words -- one per free-bit value, at wordlist indices
 * {e * 2^CS} -- gives librxe the exact valid cardinality; the completeLastWord
 * substitution then fixes the checksum per candidate. MUST be the stride
 * representatives (NOT the first N words, which share high-bits 0 and collapse
 * to a single valid word). */
const NTH_TOKENS = { 12:'12th', 15:'15th', 18:'18th', 21:'21st', 24:'24th' };
function csBitsFor(W){ return VALID_WORD_COUNTS.has(W) ? (W/3) : null; }
function scaffoldWords(words, W) {
  const csBits = csBitsFor(W);
  if (csBits === null) return null;
  const stride = 1 << csBits, n = 1 << (11 - csBits), out = new Array(n);
  for (let e=0;e<n;e++) out[e] = words[e*stride];
  return out;
}

const _bip39Exports = { sha256, sha256_1blk_h0, makeValidator, VALID_WORD_COUNTS,
  NTH_TOKENS, csBitsFor, scaffoldWords };
if (typeof module !== 'undefined' && module.exports) module.exports = _bip39Exports;
if (typeof globalThis !== 'undefined') globalThis.BIP39 = _bip39Exports; // window OR worker(self)
