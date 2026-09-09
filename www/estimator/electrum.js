// electrum.js -- Electrum v2 seed scheme. It is NOT BIP39; the differences that
// matter to a cracker/estimator:
//   * KDF salt is "electrum"+passphrase (BIP39 uses "mnemonic"+passphrase),
//     otherwise identical PBKDF2-HMAC-SHA512 x2048 -> 64-byte seed.
//   * NO wordlist checksum. A phrase is a valid Electrum seed iff
//     HMAC-SHA512(key="Seed version", msg=normalize(phrase)).hex() starts with a
//     version prefix: '01' standard(p2pkh), '100' segwit(p2wpkh), '101'/'102' 2fa.
//     That prefix probability (1/256, 1/4096) is Electrum's analogue of BIP39's
//     checksum survival, and is the pre-filter that skips PBKDF2 on non-seeds.
//   * Root-based derivation, no BIP44: standard uses m (addresses m/0/i, m/1/i,
//     p2pkh); segwit uses m/0' (addresses m/0'/0/i, m/0'/1/i, p2wpkh).
//   * normalize_text: NFKD + lowercase + strip combining marks + collapse
//     whitespace (English scope; Electrum also strips spaces between CJK chars,
//     omitted -- we support English seeds, whose wordlist == BIP39's).
// The English wordlist is byte-identical to BIP39's, so [:electrum-en:] aliases
// the BIP39 list. Gated byte-exact vs Electrum's own vectors (test_electrum.js).
'use strict';
(function(root){
  const C = (typeof globalThis!=='undefined' && globalThis.BIP39Crypto)
         || (typeof require==='function' ? require('./bip39crypto.js') : null);
  const utf8 = C.utf8;
  const HARD = 0x80000000;
  const PREFIX = { standard:'01', segwit:'100', '2fa':'101', '2fa_segwit':'102' };

  // Electrum normalize_text (English scope).
  function normalize(s){
    s = (s==null?'':String(s)).normalize('NFKD').toLowerCase();
    s = Array.from(s).filter(ch=>{ const c=ch.codePointAt(0);   // strip combining marks
      return !((c>=0x0300&&c<=0x036F)||(c>=0x1AB0&&c<=0x1AFF)||(c>=0x1DC0&&c<=0x1DFF)||(c>=0x20D0&&c<=0x20FF)||(c>=0xFE20&&c<=0xFE2F)); }).join('');
    return s.split(/\s+/).filter(Boolean).join(' ');   // collapse whitespace
  }
  function seedVersionHex(m){ return C.toHex(C.hmacSha512(utf8('Seed version'), utf8(normalize(m)))); }
  function isNewSeed(m, prefix){ return seedVersionHex(m).startsWith(prefix); }
  // 'standard' | 'segwit' | '2fa' | '2fa_segwit' | null (old/invalid). Prefixes
  // are mutually exclusive ('01' vs '10...'), so first match wins unambiguously.
  function seedType(m){
    const hx=seedVersionHex(m);
    for(const t of ['standard','segwit','2fa','2fa_segwit']) if(hx.startsWith(PREFIX[t])) return t;
    return null;
  }
  // 64-byte seed. Salt = "electrum" + normalized passphrase.
  function toSeed(m, passphrase=''){
    return C.pbkdf2Sha512(utf8(normalize(m)), utf8('electrum'+normalize(passphrase)), 2048, 64);
  }
  const isSegwit = t => (t==='segwit'||t==='2fa_segwit');
  // The node whose chain code an Electrum account xpub carries: standard=m, segwit=m/0'.
  function accountNode(seed64, type){
    const m = C.seedToMaster(seed64);
    return isSegwit(type) ? C.ckdHardened(m, (0+HARD)>>>0) : m;
  }
  function purposeType(type){ return isSegwit(type) ? 'p2wpkh' : 'p2pkh'; }
  // {type, program} for the leaf at change/index (mirrors BIP39Crypto.pubToTarget).
  function addressTarget(seed64, type, change, index){
    const leaf = C.ckdNormal(C.ckdNormal(accountNode(seed64, type), change), index);
    const pub = C.privToPub(leaf.k);
    return { type:purposeType(type), program:C.hash160(pub) };
  }
  // Human address string for the leaf (used by tests / display).
  function address(seed64, type, change, index){
    const tg = addressTarget(seed64, type, change, index);
    return tg.type==='p2wpkh' ? C.segwitEncode('bc',0,tg.program)
                              : C.b58checkEncode(C.concat(Uint8Array.of(0x00), tg.program));
  }

  const E = { normalize, seedVersionHex, isNewSeed, seedType, toSeed, accountNode, purposeType, addressTarget, address, PREFIX };
  if (typeof module!=='undefined' && module.exports) module.exports = E;
  if (root) root.Electrum = E;
})(typeof globalThis!=='undefined'?globalThis:this);
