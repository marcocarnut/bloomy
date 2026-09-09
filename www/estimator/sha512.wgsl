// sha512.wgsl -- SHA-512 in WGSL (32-bit ISA: each 64-bit word is a vec2<u32>
// = (hi, lo)). This is the GPU building block for PBKDF2-HMAC-SHA512(2048) +
// BIP32 hardened derivation. It is gated BYTE-EXACT against the JS reference
// (estimator/bip39crypto.js) before anything is trusted.
//
// This first module is a SELF-TEST harness kernel: it hashes N independent
// messages (each <= 128 bytes, one block after padding is applied host-side is
// avoided -- we pad in-shader up to 2 blocks) and writes the 64-byte digests.
// Layout is deliberately simple for the gate; the cracker kernel will inline
// SHA-512 into the PBKDF2/HMAC loops rather than round-trip through buffers.

// ---- 64-bit helpers on vec2<u32> = (hi, lo) --------------------------------
fn add64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
  let lo = a.y + b.y;
  let carry = select(0u, 1u, lo < a.y);   // unsigned overflow of lo
  return vec2<u32>(a.x + b.x + carry, lo);
}
fn xor64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> { return a ^ b; }
fn and64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> { return a & b; }
fn not64(a: vec2<u32>) -> vec2<u32> { return ~a; }

// rotate right by r (1..63). Split at 32.
fn rotr64(x: vec2<u32>, r: u32) -> vec2<u32> {
  if (r == 0u) { return x; }
  if (r < 32u) {
    let hi = (x.x >> r) | (x.y << (32u - r));
    let lo = (x.y >> r) | (x.x << (32u - r));
    return vec2<u32>(hi, lo);
  } else if (r == 32u) {
    return vec2<u32>(x.y, x.x);
  } else {
    let s = r - 32u;
    let hi = (x.y >> s) | (x.x << (32u - s));
    let lo = (x.x >> s) | (x.y << (32u - s));
    return vec2<u32>(hi, lo);
  }
}
// shift right by s (1..63).
fn shr64(x: vec2<u32>, s: u32) -> vec2<u32> {
  if (s < 32u) {
    let hi = x.x >> s;
    let lo = (x.y >> s) | (x.x << (32u - s));
    return vec2<u32>(hi, lo);
  } else {
    return vec2<u32>(0u, x.x >> (s - 32u));
  }
}

// SHA-512 constants (round + init). Filled from a host-provided storage buffer
// to avoid a 640-line literal and any transcription risk (host derives them from
// the gated BigInt tables, exactly like the fast JS path).
@group(0) @binding(0) var<storage, read> K: array<vec2<u32>, 80>;   // round constants
@group(0) @binding(1) var<storage, read> H0: array<vec2<u32>, 8>;   // init state
// input: msgs[i] = MSGWORDS u32 words (big-endian bytes already packed), preceded
// by a u32 byte-length. Simplicity for the gate: fixed stride, <=128 data bytes.
@group(0) @binding(2) var<storage, read> inLen: array<u32>;         // per-message byte length
@group(0) @binding(3) var<storage, read> inData: array<u32>;        // stride INSTRIDE u32/message (big-endian packed)
@group(0) @binding(4) var<storage, read_write> outDigest: array<u32>; // 16 u32 (64 bytes) per message
@group(0) @binding(5) var<uniform> params: vec4<u32>;               // x=count, y=INSTRIDE(u32), (z,w reserved)

// process one message (<= 128 data bytes -> up to 2 blocks after padding)
fn sha512_one(mi: u32) {
  let n = inLen[mi];                    // byte length (<=128)
  let base = mi * params.y;             // u32 offset into inData
  // Build the padded message in a local word array of up to 32 u32 (=2 blocks).
  var w32: array<u32, 64>;              // up to 2 blocks (256 bytes)
  // number of 128-byte blocks after padding = ceil((n + 1 + 16) / 128)
  let nblk = (n + 17u + 127u) / 128u;
  let totalWords = nblk * 32u;
  for (var i = 0u; i < totalWords; i = i + 1u) { w32[i] = 0u; }
  // copy data words (big-endian packed); copy ceil(n/4) words then fix the 0x80
  let fullWords = n / 4u;
  for (var i = 0u; i < fullWords; i = i + 1u) { w32[i] = inData[base + i]; }
  // place the 0x80 pad byte at byte position n (host zero-fills beyond n in the
  // partial word, so a plain OR suffices -- and we avoid any shift-by-32).
  let rem = n % 4u;                     // trailing partial-word bytes, 0..3
  if (rem == 0u) {
    w32[fullWords] = 0x80000000u;       // 0x80 in the top byte of a fresh word
  } else {
    let shift = (3u - rem) * 8u;        // rem 1..3 -> shift 16/8/0 (always < 32)
    w32[fullWords] = inData[base + fullWords] | (0x80u << shift);
  }
  // length in bits at the very end (low 64 bits; n<=128 so hi=0)
  let bits = n * 8u;
  w32[totalWords - 1u] = bits;          // low 32 bits of bit-length
  // (w32[totalWords-2] stays 0 -> high 32 bits of the 64-bit length; 128-bit field's upper 64 already 0)

  var h0=H0[0]; var h1=H0[1]; var h2=H0[2]; var h3=H0[3];
  var h4=H0[4]; var h5=H0[5]; var h6=H0[6]; var h7=H0[7];
  var W: array<vec2<u32>, 80>;
  for (var blk = 0u; blk < nblk; blk = blk + 1u) {
    let bo = blk * 32u;
    for (var i = 0u; i < 16u; i = i + 1u) {
      W[i] = vec2<u32>(w32[bo + i*2u], w32[bo + i*2u + 1u]);
    }
    for (var i = 16u; i < 80u; i = i + 1u) {
      let s0 = xor64(xor64(rotr64(W[i-15u],1u), rotr64(W[i-15u],8u)), shr64(W[i-15u],7u));
      let s1 = xor64(xor64(rotr64(W[i-2u],19u), rotr64(W[i-2u],61u)), shr64(W[i-2u],6u));
      W[i] = add64(add64(W[i-16u], s0), add64(W[i-7u], s1));
    }
    var a=h0; var b=h1; var c=h2; var d=h3; var e=h4; var f=h5; var g=h6; var h=h7;
    for (var i = 0u; i < 80u; i = i + 1u) {
      let S1 = xor64(xor64(rotr64(e,14u), rotr64(e,18u)), rotr64(e,41u));
      let ch = xor64(and64(e,f), and64(not64(e), g));
      let t1 = add64(add64(add64(h, S1), add64(ch, K[i])), W[i]);
      let S0 = xor64(xor64(rotr64(a,28u), rotr64(a,34u)), rotr64(a,39u));
      let maj = xor64(xor64(and64(a,b), and64(a,c)), and64(b,c));
      let t2 = add64(S0, maj);
      h=g; g=f; f=e; e=add64(d,t1); d=c; c=b; b=a; a=add64(t1,t2);
    }
    h0=add64(h0,a); h1=add64(h1,b); h2=add64(h2,c); h3=add64(h3,d);
    h4=add64(h4,e); h5=add64(h5,f); h6=add64(h6,g); h7=add64(h7,h);
  }
  let o = mi * 16u;
  outDigest[o+0u]=h0.x; outDigest[o+1u]=h0.y; outDigest[o+2u]=h1.x; outDigest[o+3u]=h1.y;
  outDigest[o+4u]=h2.x; outDigest[o+5u]=h2.y; outDigest[o+6u]=h3.x; outDigest[o+7u]=h3.y;
  outDigest[o+8u]=h4.x; outDigest[o+9u]=h4.y; outDigest[o+10u]=h5.x; outDigest[o+11u]=h5.y;
  outDigest[o+12u]=h6.x; outDigest[o+13u]=h6.y; outDigest[o+14u]=h7.x; outDigest[o+15u]=h7.y;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let mi = gid.x;
  if (mi >= params.x) { return; }
  sha512_one(mi);
}
