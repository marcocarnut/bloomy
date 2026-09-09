// crackworker.js -- one shard of a CPU crack, off the main thread.
// Each worker loads its OWN rxe wasm core (so it can unrank its slice of the
// keyspace) plus the shared BIP39 crypto, then sweeps [start,end): for words
// mode it enumerates candidate MNEMONICS x a fixed passphrase (optionally
// checksum-filtered); for passphrase mode a fixed mnemonic x candidate
// PASSPHRASES. On a hit it posts it and stops; the main thread terminate()s the
// pool. This is what makes words-mode multicore (the unrank sweep AND the
// PBKDF2 both parallelize) -- the GPU can't help there (varying HMAC key).
//
// Correctness note: the seed/derive/compare here is the SAME bip39crypto used
// (and gated 25/25) on the main thread -- workers are a scheduling change only.
'use strict';
// Propagate the ?v= cache-bust from the Worker URL to our importScripts, so a
// plain reload picks up edited modules here too (http.server sends no cache
// headers). The main thread spawns us as new Worker('crackworker.js?v=bN').
const _v = self.location.search || '';
importScripts('../wasm/rxecore.js'+_v, '../wasm/rxecore_api.js'+_v, 'bip39.js'+_v, 'bip39crypto.js'+_v, 'electrum.js'+_v);

let core = null, C = null, V = null;
let _runSet = null, _runPat = null;   // parsed-set cache across same-pattern chunks
async function ensureCore(wordlist){
  if (core) return;
  C = globalThis.BIP39Crypto;
  core = await globalThis.RxeCoreAPI.loadRxeCore({ moduleArgs:{ locateFile: p => '../wasm/'+p+_v } });
  core.registerDict('bip39', wordlist);
  ['bip39-en','bip39en','en','english','electrum-en','electrumen','electrum'].forEach(a=>{ try{ core.registerDict(a, wordlist); }catch(e){} });
  Object.entries(globalThis.BIP39.NTH_TOKENS).forEach(([W,tok])=>{ try{ core.registerDict(tok, globalThis.BIP39.scaffoldWords(wordlist, +W)); }catch(e){} });
  V = globalThis.BIP39.makeValidator(wordlist);
}
function hexToBytes(h){ const o=new Uint8Array(h.length/2); for(let i=0;i<o.length;i++) o[i]=parseInt(h.substr(i*2,2),16); return o; }

onmessage = async (e) => {
  const d = e.data;
  if (!d) return;

  // DERIVE mode: parallel secp256k1 derive+compare on GPU-produced seeds (the
  // address crack's EC, moved off the main thread). No rxe core needed here.
  if (d.type === 'derive') {
    C = C || globalThis.BIP39Crypto;
    const seeds = new Uint8Array(d.seedsBuf);
    let hit = null;
    // XPUB target: EC-FREE chain-code compare (accountNode). Parallelizing this
    // off the main thread keeps the hybrid pipeline smooth (was inline before).
    if (d.targetKind === 'xpub') {
      const tcc = hexToBytes(d.chainCodeHex);
      for (let i=0; i<d.n && !hit; i++) { const seed = seeds.subarray(i*64, i*64+64);
        for (const pp of d.plan) {
          if (C.eq(C.accountNode(seed, pp.purpose, pp.account, pp.coin).c, tcc)) { hit = { index:d.startIndex+i, path:pp }; break; } }
      }
      postMessage(hit ? { type:'derivehit', id:d.id, batchId:d.batchId, index:hit.index, path:hit.path }
                      : { type:'derivedone', id:d.id, batchId:d.batchId });
      return;
    }
    const taddr = { type:d.addrType, program:hexToBytes(d.programHex) };
    const plan = d.plan.filter(pp => C.purposeType(pp.purpose) === taddr.type);
    const changes = (d.changes && d.changes.length) ? d.changes : [0];
    const gap = Math.max(1, d.gap || 1);
    // CUSTOM derivation path: a single template, script type from the target.
    if (d.pathTemplate) {
      const tmpl = C.parsePathTemplate(d.pathTemplate), ph = C.templatePlaceholders(tmpl);
      for (let i=0; i<d.n && !hit; i++) {
        const h = C.customMatch(seeds.subarray(i*64, i*64+64), tmpl, taddr, { ph, changes, gap, accounts:d.accounts||1 });
        if (h) hit = { index:d.startIndex+i, path:{ custom:true, template:d.pathTemplate, ...h } };
      }
      postMessage(hit ? { type:'derivehit', id:d.id, batchId:d.batchId, index:hit.index, path:hit.path }
                      : { type:'derivedone', id:d.id, batchId:d.batchId });
      return;
    }
    // BATCH EC: for the common simple derivation (1 purpose, change 0, index 0)
    // amortize the modular inverse across the whole task via Montgomery batch
    // inversion (privToPubBatch) -- ~1.7x the per-candidate privToPub.
    const simple = plan.length===1 && changes.length===1 && changes[0]===0 && gap===1
                   && typeof C.privToPubBatch==='function' && typeof C.ckdNormalPub==='function';
    if (simple) {
      const pp = plan[0], n = d.n;
      const accts = new Array(n);
      for (let i=0;i<n;i++) accts[i]=C.deriveHardenedPath(seeds.subarray(i*64,i*64+64),[pp.purpose,pp.coin||0,pp.account||0]);
      const pubA = C.privToPubBatch(accts.map(a=>a.k));
      const chs = new Array(n); for (let i=0;i<n;i++) chs[i]=C.ckdNormalPub(accts[i], pubA[i], 0);
      const pubC = C.privToPubBatch(chs.map(c=>c.k));
      const nodes = new Array(n); for (let i=0;i<n;i++) nodes[i]=C.ckdNormalPub(chs[i], pubC[i], 0);
      const pubN = C.privToPubBatch(nodes.map(nd=>nd.k));
      for (let i=0;i<n;i++){ const tg=C.pubToTarget(pubN[i], pp.purpose);
        if (tg.type===taddr.type && C.eq(tg.program, taddr.program)){ hit={ index:d.startIndex+i, path:{...pp, change:0, index:0} }; break; } }
    } else {
      for (let i=0; i<d.n && !hit; i++) {
        const seed = seeds.subarray(i*64, i*64+64);
        for (const pp of plan) {
          const acct = C.deriveHardenedPath(seed, [pp.purpose, pp.coin||0, pp.account||0]);
          for (const ch of changes) { const chNode = C.ckdNormal(acct, ch);
            for (let idx=0; idx<gap; idx++) { const node = C.ckdNormal(chNode, idx);
              const tg = C.pubToTarget(C.privToPub(node.k), pp.purpose);
              if (tg.type===taddr.type && C.eq(tg.program, taddr.program)) { hit = { index:d.startIndex+i, path:{...pp, change:ch, index:idx} }; break; } }
            if (hit) break; }
          if (hit) break; }
      }
    }
    postMessage(hit ? { type:'derivehit', id:d.id, batchId:d.batchId, index:hit.index, path:hit.path }
                    : { type:'derivedone', id:d.id, batchId:d.batchId });
    return;
  }

  // BLOOM DERIVE: no target — derive EVERY purpose's program for each seed and
  // return the flat hex (batched EC), so the main thread can stream them to the
  // bloom server. Order is purpose -> change -> idx -> seed i; the main thread
  // replays the SAME nested order to map each hex back to its candidate.
  if (d.type === 'bloomderive') {
    C = C || globalThis.BIP39Crypto;
    const seeds = new Uint8Array(d.seedsBuf), n = d.n;
    const PURPOSES = d.purposes, changes = (d.changes&&d.changes.length)?d.changes:[0], gap = Math.max(1, d.gap||1);
    const hexes = [];
    for (const purpose of PURPOSES) {
      const accts = new Array(n); for (let i=0;i<n;i++) accts[i]=C.deriveHardenedPath(seeds.subarray(i*64,i*64+64),[purpose,0,0]);
      const pubA = C.privToPubBatch(accts.map(a=>a.k));
      for (const ch of changes) {
        const chN = new Array(n); for (let i=0;i<n;i++) chN[i]=C.ckdNormalPub(accts[i],pubA[i],ch);
        const pubC = C.privToPubBatch(chN.map(c=>c.k));
        for (let idx=0; idx<gap; idx++) {
          const ixN = new Array(n); for (let i=0;i<n;i++) ixN[i]=C.ckdNormalPub(chN[i],pubC[i],idx);
          const pubN = C.privToPubBatch(ixN.map(nd=>nd.k));
          for (let i=0;i<n;i++) hexes.push(C.toHex(C.pubToTarget(pubN[i],purpose).program));
        }
      }
    }
    postMessage({ type:'bloomderived', batchId:d.batchId, hexes });
    return;
  }

  // BLOOM SWEEP: unrank this worker's raw range + checksum-filter, return the
  // surviving candidates (mnemonics in words mode / passphrases otherwise). Moves
  // the sweep OFF the main thread so it stops stalling the GPU-seed pipeline; the
  // main thread then seeds (GPU) and hands the seeds back for the bloomderive EC.
  if (d.type === 'bloomsweep') {
    try {
      await ensureCore(d.wordlist);
      if (!(_runSet && _runPat === d.pattern)) { if (_runSet) { try{ _runSet.free(); }catch(e){} } _runSet = core.parse(d.pattern); _runPat = d.pattern; }
      const set = _runSet;
      const reqCsum = d.requireChecksum !== false, isWords = d.mode === 'words';
      const end = Math.min(d.start + d.n, d.total);
      const items = [];
      const UB = 4096; let base=-1, cb=null, useBatch=true;
      const at = (i) => { if (useBatch) {
          if (!(cb && i >= base && i < base + cb.length)) { const r = set.unrankBatch ? set.unrankBatch(i, Math.min(UB, end - i)) : null;
            if (r === null) { useBatch=false; return set.unrank(BigInt(i)); } base=i; cb=r; }
          return cb[i - base]; }
        return set.unrank(BigInt(i)); };
      for (let i = d.start; i < end; i++) { const c = at(i); if (c == null) continue;
        if (isWords && reqCsum && !V.isValid(c)) continue;
        items.push(c); }
      postMessage({ type:'bloomswept', id:d.id, n:(end - d.start), items });
    } catch (err) { postMessage({ type:'error', id:d.id, message: String(err && err.message || err) }); }
    return;
  }

  if (d.type !== 'run') return;
  try {
    await ensureCore(d.wordlist);
    // Cache the parsed set across chunks of the SAME pattern (the monotonic-cursor
    // driver re-issues 'run' with successive ranges) so we parse once, not per chunk.
    if (!(_runSet && _runPat === d.pattern)) {
      if (_runSet) { try{ _runSet.free(); }catch(e){} }
      _runSet = core.parse(d.pattern); _runPat = d.pattern;
    }
    const set = _runSet;
    const isWords = d.mode === 'words';
    const isAddr  = d.target.kind === 'address';
    const tcc   = isAddr ? null : hexToBytes(d.target.chainCodeHex);
    const taddr = isAddr ? { type:d.target.addrType, program:hexToBytes(d.target.programHex) } : null;
    const plan  = isAddr ? d.plan.filter(pp => C.purposeType(pp.purpose) === taddr.type) : d.plan;
    const changes = (d.changes && d.changes.length) ? d.changes : [0];
    const gap = Math.max(1, d.gap || 1);
    const customTmpl = (isAddr && d.pathTemplate) ? C.parsePathTemplate(d.pathTemplate) : null;   // custom derivation path
    const customPh = customTmpl ? C.templatePlaceholders(customTmpl) : null;
    const reqCsum = d.requireChecksum !== false;
    const generate = !!d.generate;   // [:Nth:] scaffold: overwrite the last word's checksum
    const pass = d.passphrase || '';
    // sweepOnly: this worker only unranks + checksum-filters and streams the
    // surviving mnemonics back; the MAIN thread GPU-seeds them. That parallelizes
    // the sweep (the real bottleneck for a multi-unknown-word checksum-on crack)
    // while the GPU does the KDF -- neither alone was enough.
    const sweepOnly = !!d.sweepOnly;
    const maxlen = d.maxlen || 0;   // EXPERIMENTAL: skip candidates longer than this (saves the KDF/EC)
    let swept = 0, seeded = 0, lastPost = performance.now();
    let candBuf = [];
    const flushCand = (force) => { if (candBuf.length && (force || candBuf.length>=512)) { postMessage({ type:'cand', id:d.id, items:candBuf, swept }); candBuf=[]; } };
    // Report on a wall-clock cadence, not every N candidates -- in passphrase
    // mode (or checksum-off) a small shard may never reach a swept-count
    // threshold, so the UI would sit blank until 'done'.
    const maybePost = () => { const now = performance.now(); if (now - lastPost >= 250) { lastPost = now; if(sweepOnly) flushCand(true); postMessage({ type:'progress', id:d.id, swept, seeded }); } };

    // Candidate fetch backed by the batched sequential unrank (one seek + N
    // odometer-steps, ~5x the per-index unrank). Falls back to unrank on an
    // older core lacking the export.
    const UB = 4096; let _cbBase = -1, _cb = null, _useBatch = true;
    const candAt = (i) => {
      if (_useBatch) {
        if (!(_cb && i >= _cbBase && i < _cbBase + _cb.length)) {
          const r = set.unrankBatch ? set.unrankBatch(i, Math.min(UB, d.end - i)) : null;
          if (r === null) { _useBatch = false; return set.unrank(BigInt(i)); }
          _cbBase = i; _cb = r;
        }
        return _cb[i - _cbBase];
      }
      return set.unrank(BigInt(i));
    };

    for (let i = d.start; i < d.end; i++) {
      let mn, pw;
      if (isWords) {
        mn = candAt(i); pw = pass;
        if (generate) {
          // GENERATE mode: rewrite the last word so the checksum is valid. One
          // SHA per candidate (same as the reject filter), but NOTHING is
          // rejected -- every scaffold candidate becomes a valid mnemonic.
          mn = (mn !== null) ? V.complete(mn) : null;
          if (mn === null) { swept++; maybePost(); continue; }
        } else if (reqCsum && !(mn !== null && V.isValid(mn))) { swept++; maybePost(); continue; }
      } else {
        pw = candAt(i); mn = d.mnemonic;
      }
      // maxlen: skip this candidate (the mnemonic in words mode, the passphrase
      // otherwise) before any hashing -- swept over, never seeded.
      if (maxlen){ const _c = isWords ? mn : pw; if (_c != null && _c.length > maxlen){ swept++; maybePost(); continue; } }
      if (sweepOnly) { swept++; seeded++; candBuf.push({ mn, index:i }); flushCand(false); maybePost(); continue; }
      seeded++;
      const seed = C.mnemonicToSeed(mn, pw);
      let hit = null;
      if (isAddr) {
        if (customTmpl) {
          const h = C.customMatch(seed, customTmpl, taddr, { ph:customPh, changes, gap, accounts:d.accounts||1 });
          if (h) hit = { custom:true, template:d.pathTemplate, ...h };
        } else
        for (const pp of plan) {
          const acct = C.deriveHardenedPath(seed, [pp.purpose, pp.coin||0, pp.account||0]);
          for (const ch of changes) {
            const chNode = C.ckdNormal(acct, ch);
            for (let idx = 0; idx < gap; idx++) {
              const node = C.ckdNormal(chNode, idx);
              const tg = C.pubToTarget(C.privToPub(node.k), pp.purpose);
              if (tg.type === taddr.type && C.eq(tg.program, taddr.program)) { hit = { ...pp, change:ch, index:idx }; break; }
            }
            if (hit) break;
          }
          if (hit) break;
        }
      } else {
        for (const pp of d.plan) {
          if (C.eq(C.accountNode(seed, pp.purpose, pp.account, pp.coin).c, tcc)) { hit = pp; break; }
        }
      }
      swept++;
      if (hit) { postMessage({ type:'hit', id:d.id, index:i, candidate:(isWords?mn:pw), path:hit, swept, seeded }); return; }  // set is cached (freed on pattern change)
      maybePost();
    }
    if (sweepOnly) flushCand(true);
    postMessage({ type:'done', id:d.id, swept, seeded });
  } catch (err) {
    postMessage({ type:'error', id:d.id, message: String(err && err.message || err) });
  }
};
