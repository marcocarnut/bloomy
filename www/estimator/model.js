// model.js -- the BIP39 keyspace / effort ESTIMATOR model.
//
// This is the ONE place the *new* estimator logic lives (PLAN §9/§14). Every
// enumeration count and every sample string comes from librxe via the wasm core
// (THE DRIFT RULE) -- this file never re-implements counting or the bijection.
// What is genuinely new here (and nowhere else):
//   * checksum-survival  (exact by enumeration when small, else sampled)
//   * path-plan multiplier (paths x accounts x change x gap)
//   * joint-mode product   (checksum-valid words-set  x  passphrase-set)
//   * ETA from PLAN §9 rate constants  (LABELLED "assumed, pre-calibration")
//   * green/yellow/red verdict + narrowing-levers text
//
// The model is dependency-injected with a loaded rxe core and a BIP39 validator
// so it is trivially unit-testable in node and identical in the browser.
//
//   const rxe = await loadRxeCore();
//   const validator = makeValidator(englishWords);
//   const report = estimate({ ... }, { rxe, validator });

'use strict';

/* ======================================================================== *
 *  PLAN §9 performance constants -- ASSUMED, PRE-CALIBRATION PLACEHOLDERS.  *
 *  There is no browser/CPU benchmarked here yet; real calibration (browser  *
 *  JS-CPU + WebGPU, and native `--calibrate`) is a later step with Kiko.    *
 *  Override the whole block via input.calibration to feed measured rates.   *
 * ======================================================================== */
const DEFAULT_RATES = {
  calibrated: false,           // flips true once a real measurement is supplied
  source: 'assumed (PLAN §9), pre-calibration',
  cpu: {
    kdfPerCore: 3000,          // PBKDF2-HMAC-SHA512(2048) cand/s/core (range ~1-5K)
    ecMultPerCore: 50000,      // fixed-base k*G mults/s/core (libsecp ~50-70K)
    sweepPerCore: 30000,       // unrank + checksum-test cand/s/core (fallback if uncalibrated)
    sweepAggregate: null,      // MEASURED multicore aggregate sweep cand/s (preferred)
    sweepCores: null,          // core count sweepAggregate was measured at
  },
  gpu: {
    kdf: 300000,               // device KDF cand/s (PLAN range 1e5-1e6)
    ecMult: 100000,            // HOST secp256k1 ceiling for address targets (1e4-1e5)
  },
};

// Verdict thresholds on time-to-exhaust (the planning number). PLAN §14:
// green = minutes/hours, yellow = days/weeks, red = years+.
const GREEN_MAX_SEC = 24 * 3600;             // <= 1 day  -> green
const YELLOW_MAX_SEC = 365 * 24 * 3600;      // <= 1 year -> yellow, else red

// 9-tier feasibility scale on time-to-exhaust. Returns { key, color } where
// color (green/yellow/red) still drives styling + which narrowing levers show.
function verdictTier(sec) {
  const H = 3600, D = 86400, Y = 365 * D;
  if (!isFinite(sec))    return { key:'hopeless', color:'red' };
  if (sec < 60)          return { key:'trivial',  color:'green' };
  if (sec < H)           return { key:'veryEasy', color:'green' };
  if (sec < D)           return { key:'easy',     color:'green' };
  if (sec < 7 * D)       return { key:'days',     color:'yellow' };
  if (sec < 30 * D)      return { key:'weeks',    color:'yellow' };
  if (sec < Y)           return { key:'months',   color:'yellow' };
  if (sec < 10 * Y)      return { key:'years',    color:'red' };
  if (sec < 100 * Y)     return { key:'decades',  color:'red' };
  return { key:'hopeless', color:'red' };
}

// EC mults per address derivation for an *address* target (PLAN §2.4:
// change + index + address = 3 fixed-base mults; taproot's +1 is ignored here).
const MULTS_PER_ADDRESS = 3;

/* ----------------------------- formatting ------------------------------- */

// Human-readable count for a (possibly huge) BigInt or number.
function humanCount(n) {
  const b = typeof n === 'bigint' ? n : BigInt(Math.round(Number(n)));
  if (b < 0n) return String(b);
  const s = b.toString();
  if (s.length <= 6) return s.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  // scientific-ish: d.ddde+NN
  const exp = s.length - 1;
  const mant = s[0] + '.' + s.slice(1, 4);
  return `${mant}e${exp}`;
}

function humanTime(sec) {
  if (!isFinite(sec)) return 'unbounded';
  if (sec < 1) return '<1 s';
  const units = [
    ['year', 365 * 24 * 3600],
    ['day', 24 * 3600],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1],
  ];
  for (const [name, span] of units) {
    if (sec >= span) {
      const v = sec / span;
      const val = v >= 100 ? Math.round(v) : Math.round(v * 10) / 10;
      return `${val} ${name}${val === 1 ? '' : 's'}`;
    }
  }
  return `${Math.round(sec)} seconds`;
}
// Pessimistic display for sub-year ETAs: round the value in its unit UP by
// ceil(v + 0.5) and phrase it as an upper bound ("less than N units"). An
// over-estimate is forgiven; an under-estimate annoys -- and real cracks can run
// a bit over the estimate. >= 1 year falls back to the plain humanTime.
function humanTimeUpper(sec) {
  if (!isFinite(sec)) return 'unbounded';
  const YEAR = 365 * 24 * 3600;
  if (sec >= YEAR) return humanTime(sec);
  if (sec < 60) return 'less than a minute';
  for (const [name, span] of [['day', 86400], ['hour', 3600], ['minute', 60]]) {
    if (sec >= span) { const v = Math.ceil(sec / span + 0.5); return `less than ${v} ${name}${v === 1 ? '' : 's'}`; }
  }
  return 'less than a minute';
}

/* --------------------------- checksum survival -------------------------- */
// How many members of a mnemonic pattern are checksum-valid BIP39 mnemonics.
// Exact when the raw set is small enough to walk; sampled otherwise. The result
// always says WHICH method and the fraction it found (BRIEF P2 requirement).
//
//   set        : a parsed RxeSet (from rxe.parse) for the mnemonic pattern
//   validator  : { isValid(mnemonicString), theoreticalFraction(W) }
//   opts.exactThreshold : walk-and-count if raw cardinality <= this (default 2e5)
//   opts.sampleSize     : random samples when not exact (default 20000)
// Deterministic PRNG so the SAME pattern always yields the SAME sampled survival
// count -- otherwise checking then un-checking a box would jitter the total and
// confuse the user. Seeded from the pattern's own shape (first member + raw size).
function _hashStr(s){ let h=2166136261>>>0; for(let i=0;i<s.length;i++){ h^=s.charCodeAt(i); h=Math.imul(h,16777619); } return h>>>0; }
function _mulberry32(a){ return function(){ a|=0; a=(a+0x6D2B79F5)|0; let t=Math.imul(a^(a>>>15), 1|a); t=(t+Math.imul(t^(t>>>7), 61|t))^t; return ((t^(t>>>14))>>>0)/4294967296; }; }

function checksumSurvival(set, validator, opts = {}) {
  const exactThreshold = BigInt(opts.exactThreshold != null ? opts.exactThreshold : 200000);
  const sampleSize = opts.sampleSize != null ? opts.sampleSize : 20000;

  const raw = set.cardinality(); // BigInt, or null if infinite
  if (raw === null) {
    return { infinite: true, method: 'none', raw: null, validCount: null,
             fraction: null, wordCount: null, theoreticalFraction: null };
  }

  // Word count (for the theoretical 2^-(W/3) cross-check) from the first member.
  let wordCount = null;
  const first = set.unrank(0n);
  if (first !== null) wordCount = first.trim().split(/\s+/).length;
  const theoreticalFraction =
    wordCount != null ? validator.theoreticalFraction(wordCount) : null;

  if (raw <= exactThreshold) {
    // EXACT: enumerate every member, count survivors.
    let valid = 0n;
    for (let i = 0n; i < raw; i++) {
      const m = set.unrank(i);
      if (m !== null && validator.isValid(m)) valid++;
    }
    const fraction = raw === 0n ? 0 : Number(valid) / Number(raw);
    return { infinite: false, method: 'exact', raw, validCount: valid,
             fraction, wordCount, theoreticalFraction };
  }

  // SAMPLED: draw random indices, validate, extrapolate. Deterministic RNG seeded
  // from the pattern shape so the count is stable across recomputes.
  const rng = _mulberry32((_hashStr(String(first||'')) ^ (Number(raw & 0xffffffffn)>>>0)) >>> 0);
  const rawNum = Number(raw);
  let survivors = 0;
  const seen = new Set();
  let draws = 0;
  const target = Math.min(sampleSize, rawNum);
  // guard against pathological dup-heavy draws on tiny-but-over-threshold sets
  let guard = target * 20;
  while (seen.size < target && guard-- > 0) {
    const i = BigInt(Math.floor(rng() * rawNum));
    if (seen.has(i.toString())) continue;
    seen.add(i.toString());
    draws++;
    const m = set.unrank(i);
    if (m !== null && validator.isValid(m)) survivors++;
  }
  // Sampling can't resolve a rare survivor: e.g. [a-z]{4} for one missing word
  // is 456,976 candidates but only ~1 is a valid mnemonic (most [a-z]{4} aren't
  // even wordlist words), so a 5k sample sees 0 and reports "0 candidates" -- yet
  // the cracker enumerates all and finds it. When the sample finds <=2 survivors
  // and the raw set is small enough to walk, recount EXACTLY so the estimate
  // agrees with the cracker instead of misleading with a hard zero.
  const exactFallbackCap = BigInt(opts.exactFallbackCap != null ? opts.exactFallbackCap : 1000000);
  if (survivors <= 2 && raw <= exactFallbackCap) {
    let valid = 0n;
    for (let i = 0n; i < raw; i++) {
      const m = set.unrank(i);
      if (m !== null && validator.isValid(m)) valid++;
    }
    const fr = raw === 0n ? 0 : Number(valid) / Number(raw);
    return { infinite: false, method: 'exact', raw, validCount: valid, fraction: fr,
             wordCount, theoreticalFraction, exactFallback: true };
  }
  const fraction = draws === 0 ? 0 : survivors / draws;
  // extrapolated valid count, kept exact-ratio in BigInt for magnitude
  const validCount = draws === 0 ? 0n : (raw * BigInt(survivors)) / BigInt(draws);
  return { infinite: false, method: 'sampled', raw, validCount, fraction,
           sampleSize: draws, survivors, wordCount, theoreticalFraction,
           // sample saw nothing but the set is too big to walk -> not a true zero
           belowSampleResolution: survivors === 0 };
}

/* --------------------------- path multiplier ---------------------------- */
// paths x accounts x change x gap. For an xpub target the fan-out collapses:
// you compare the account node's chain code directly (PLAN §3/§6), so change
// and gap do NOT multiply -- only purposes x accounts.
function pathMultiplier(path = {}, targetType = 'address') {
  const purposes = Array.isArray(path.purposes) ? path.purposes.length
                 : (path.purposes != null ? Number(path.purposes) : 1);
  const accounts = path.accounts != null ? Number(path.accounts) : 1;
  const change = path.change != null ? Number(path.change) : 1;
  const gap = path.gap != null ? Number(path.gap) : 1;

  const p = Math.max(1, purposes);
  const a = Math.max(1, accounts);
  if (targetType === 'xpub') {
    return { value: p * a, purposes: p, accounts: a, change: 1, gap: 1,
             collapsed: true };
  }
  const c = Math.max(1, change);
  const g = Math.max(1, gap);
  return { value: p * a * c * g, purposes: p, accounts: a, change: c, gap: g,
           collapsed: false };
}

/* ------------------------------ the model ------------------------------- */
// input:
//   passphrasePattern : string | null      (the positional passphrase regex)
//   mnemonicKnown     : bool               (true => passphrase mode; mnemonic fixed)
//   mnemonicPattern   : string | null      (a SHAPE over [:bip39-*:]/{{ }}/alts)
//   targetType        : 'address' | 'xpub'
//   path              : { purposes:[...]|n, accounts, change, gap }
//   backend           : 'cpu' | 'gpu'
//   cores             : int (cpu only, default 1)
//   calibration       : optional full/partial RATES override (sets calibrated)
//   exactThreshold, sampleSize : checksum-survival knobs
// deps: { rxe (loaded core), validator (BIP39) }
function estimate(input, deps) {
  const { rxe, validator } = deps;
  const rates = mergeRates(input.calibration);
  const targetType = input.targetType === 'xpub' ? 'xpub' : 'address';
  const backend = input.backend === 'gpu' ? 'gpu' : 'cpu';
  const cores = Math.max(1, Number(input.cores || 1));

  const notes = [];
  const warnings = [];
  const requireChecksum = input.requireChecksum !== false;

  // ---- parse BOTH axes up front so the mode follows from CARDINALITY, not a UI
  //      toggle: whichever side has >1 candidate is the axis being searched. A
  //      fixed non-empty passphrase is card 1 -> words mode (not joint). ----
  const hasPass = !!(input.passphrasePattern && String(input.passphrasePattern).length);
  const hasWordsPattern = !!(input.mnemonicPattern && String(input.mnemonicPattern).length);

  // DIM 1: passphrase set
  let passSet = null, passCard = 1n, passInfinite = false;
  if (hasPass) {
    passSet = rxe.parse(String(input.passphrasePattern));
    if (passSet.isInfinite()) { passInfinite = true; passCard = null; }
    else passCard = passSet.cardinality();
  }
  // DIM 1: mnemonic set (raw cardinality here; checksum survival computed below)
  let wordsSet = null, wordsRaw = 1n, wordsInfinite = false;
  if (hasWordsPattern) {
    wordsSet = rxe.parse(String(input.mnemonicPattern));
    wordsRaw = wordsSet.cardinality();
    if (wordsRaw === null) wordsInfinite = true;
  }

  // ---- mode inference by CARDINALITY (PLAN §11) ----
  const passVaries  = passInfinite  || (passCard !== null && passCard > 1n);
  const wordsVaries = wordsInfinite || (wordsRaw !== null && wordsRaw > 1n);
  let mode;
  if (!hasPass && !hasWordsPattern) mode = 'unknown';
  else if (wordsVaries && passVaries) mode = 'joint';   // both axes open -> product
  else if (wordsVaries) mode = 'words';                 // only the mnemonic varies
  else mode = 'passphrase';                             // only the passphrase varies, or both fixed (single verify)

  // ---- DIM 1: mnemonic checksum survival (only when the mnemonic is a search
  //      axis; a fixed mnemonic is already valid, so the filter is a no-op). The
  //      requireChecksum default is true (standard BIP39 wallets enforce it); off
  //      => every candidate is hashed (off-dictionary/custom words allowed). ----
  let survival = null, validMnemonicCount = 1n;
  const wordsIsAxis = (mode === 'words' || mode === 'joint');
  const generateChecksum = !!input.generateChecksum;
  if (wordsIsAxis && generateChecksum) {
    // GENERATE mode: the [:Nth:] scaffold enumerates exactly the checksum-valid
    // mnemonics (the final word is computed per candidate), so the librxe
    // cardinality already IS the valid count -- exact, 100% survival, no sample.
    if (wordsInfinite) {
      warnings.push('mnemonic pattern is unbounded/infinite -- bound it (no * or {n,} tails).');
      validMnemonicCount = null;
    } else {
      validMnemonicCount = wordsRaw;
      survival = { infinite:false, method:'exact', raw:wordsRaw, validCount:wordsRaw, fraction:1,
                   wordCount:null, theoreticalFraction:null, generate:true };
      notes.push('generate-checksum mode: the [:Nth:] scaffold enumerates only checksum-valid mnemonics (the final word is computed), so the count is EXACT and every candidate is valid -- no rejection, ~2^CS fewer hashes than reject mode.');
    }
  } else if (wordsIsAxis && !requireChecksum) {
    if (wordsInfinite) {
      warnings.push('mnemonic pattern is unbounded/infinite -- bound it (no * or {n,} tails).');
      validMnemonicCount = null;
    } else {
      validMnemonicCount = wordsRaw;
      survival = { infinite:false, method:'none', raw:wordsRaw, validCount:wordsRaw, fraction:1,
                   wordCount:null, theoreticalFraction:null, checksumOff:true };
      notes.push('checksum filter OFF: every candidate is hashed (off-dictionary / custom words allowed) -- candidate count = the full raw set, so expect it to be ~256x slower than with the checksum on.');
    }
  } else if (wordsIsAxis) {
    survival = checksumSurvival(wordsSet, validator, {
      exactThreshold: input.exactThreshold, sampleSize: input.sampleSize,
      exactFallbackCap: input.exactFallbackCap,
    });
    if (survival.infinite) {
      warnings.push('mnemonic pattern is unbounded/infinite -- bound it (no * or {n,} tails).');
      validMnemonicCount = null;
    } else {
      validMnemonicCount = survival.validCount;
      notes.push(
        `checksum-survival: ${survival.method}, ${(survival.fraction * 100).toPrecision(3)}%` +
        (survival.method === 'sampled' ? ` (sampled ${survival.sampleSize} of ${humanCount(survival.raw)})`
                                       : ` (exact over ${humanCount(survival.raw)}${survival.exactFallback ? ', fallback' : ''})`) +
        (survival.theoreticalFraction != null
          ? `; full-entropy theory = ${(survival.theoreticalFraction * 100).toPrecision(3)}%` : ''));
      if (survival.exactFallback)
        notes.push('note: sampling found no valid mnemonic (they are rare here -- most [a-z]{n} tokens are not wordlist words), so it was recounted exactly. This count matches what the search will actually test.');
      if (survival.belowSampleResolution)
        warnings.push('the sample found no checksum-valid mnemonic and the set is too big to count exactly -- the true count is small but non-zero (the search still tests all candidates). Prefer [:bip39:] for the unknown word(s) over [a-z]{n} so candidates stay real words.');
    }
  } else {
    notes.push('passphrase mode: mnemonic is fixed & already checksum-valid -- checksum filter is a no-op here (PLAN §7).');
  }

  // ---- compose DIM 1 total (seeds = KDF evaluations) ----
  let dim1 = null; // BigInt seeds, or null if unbounded/unknown
  if (mode === 'passphrase') dim1 = passInfinite ? null : passCard;
  else if (mode === 'words') dim1 = validMnemonicCount;
  else if (mode === 'joint') {
    if (passInfinite || validMnemonicCount === null) dim1 = null;
    else dim1 = validMnemonicCount * passCard; // the explicit product (PLAN §7.1)
    // PLAN §7.1: always make the product explicit, whatever the verdict.
    notes.push(
      'JOINT mode: keyspace is a PRODUCT (checksum-valid words ' +
      `${dim1 === null ? '' : humanCount(validMnemonicCount) + ' x passphrase ' +
        humanCount(passCard) + ' = ' + humanCount(dim1)}` +
      ') -- it explodes fast; tighten either side to multiply it down.');
  }

  // ---- path-plan multiplier (DIM 2) ----
  const pm = pathMultiplier(input.path, targetType);
  if (pm.collapsed)
    notes.push('xpub target: path fan-out collapses to purposes x accounts (chain-code compare, no change/gap sweep -- PLAN §3/§6).');

  // ---- total candidates = DIM1 x path multiplier ----
  const totalCandidates = dim1 === null ? null : dim1 * BigInt(pm.value);
  const unbounded = dim1 === null;

  // ---- ETA (labelled pre-calibration) ----
  let eta = null;
  if (!unbounded) {
    const seeds = Number(dim1);
    const kdfRate = backend === 'gpu' ? rates.gpu.kdf : rates.cpu.kdfPerCore * cores;
    const seedSec = seeds / kdfRate;
    let ecSec = 0;
    if (targetType === 'address') {
      const derivations = Number(totalCandidates);
      // The address EC (privToPub fan-out) runs on the HOST and is now
      // PARALLELIZED across the worker pool for the GPU path too (derive workers)
      // as well as the CPU path -- so it scales with cores. Measured host rate.
      const ecRate = rates.cpu.ecMultPerCore * cores;
      ecSec = (derivations * MULTS_PER_ADDRESS) / ecRate;
    }
    // The SWEEP: words/joint must unrank + checksum-test the WHOLE raw mnemonic
    // set to find the checksum-valid ones -- this is separate from (and usually
    // dominates) the KDF on those survivors. The KDF is what "candidates" counts;
    // the sweep is why the crack visits the full raw set. The CPU path shards the
    // sweep across cores; the GPU path currently sweeps single-threaded on the host.
    let sweepSec = 0, rawSweep = 0;
    if ((mode === 'words' || mode === 'joint') && survival && !survival.infinite) {
      rawSweep = Number(survival.raw);
      // Both paths shard the sweep across cores: CPU = multicore workers, GPU =
      // the hybrid (workers sweep + checksum-filter, GPU seeds survivors). Use the
      // MEASURED aggregate multicore rate when calibrated -- real worker scaling is
      // sublinear (~44% of cores*single-core on an 8-core box), so the old
      // sweepPerCore*cores overshot the rate ~2x (=> an optimistic ETA). Rescale
      // linearly if the user picks a different core count than was benchmarked.
      const sweepRate = rates.cpu.sweepAggregate
        ? rates.cpu.sweepAggregate * (cores / (rates.cpu.sweepCores || cores))
        : rates.cpu.sweepPerCore * cores;
      sweepSec = rawSweep / sweepRate;
    }
    // Wall-clock: on the GPU path the CPU sweep, GPU seed, and (address) EC pool
    // run on DIFFERENT hardware and pipeline -- so the time is the slowest stage,
    // not their sum. On the CPU path every stage runs on the same worker cores
    // (unrank -> checksum -> KDF -> EC per candidate), so they add up.
    const exhaustSec = backend === 'gpu'
      ? Math.max(sweepSec, seedSec, ecSec)
      : sweepSec + seedSec + ecSec;
    const sweepDominates = sweepSec >= seedSec && sweepSec >= ecSec && sweepSec > 0;
    eta = {
      calibrated: rates.calibrated,
      rateSource: rates.source,
      backend, cores: backend === 'cpu' ? cores : undefined,
      kdfRate, seedSeconds: seedSec, ecSeconds: ecSec,
      sweepSeconds: sweepSec, rawSweep,
      sweepTime: humanTime(sweepSec), seedTime: humanTime(seedSec + ecSec),
      exhaustSeconds: exhaustSec,
      expectedHitSeconds: exhaustSec / 2, // ~half if the guess is in the set
      timeToExhaust: humanTime(exhaustSec),
      expectedTimeToHit: humanTime(exhaustSec / 2),
      note: (rawSweep && sweepDominates)
        ? `SWEEP-bound: finding the ${humanCount(dim1)} checksum-valid mnemonics means unranking + checksum-testing all ${humanCount(rawSweep)} raw candidates; that host sweep (${humanTime(sweepSec)}), not the KDF (${humanTime(seedSec)}), sets the time. GPU/CPU only speed the KDF, so they barely help here -- shrink the raw set (fewer/narrower unknown words) or turn off the checksum only if off-dictionary.`
        : (targetType === 'xpub'
            ? 'xpub target: no EC in the hot loop (KDF-bound).'
            : 'address target: includes host secp256k1 fan-out (EC-bound).'),
    };
  }

  // ---- verdict: a 9-tier feasibility scale on time-to-exhaust ----
  const tier = unbounded ? { key:'hopeless', color:'red' } : verdictTier(eta.exhaustSeconds);
  const verdict = tier.color;   // green/yellow/red kept for styling + lever gating

  // ---- narrowing levers (PLAN §14) ----
  const levers = [];
  if (verdict !== 'green') {
    if (targetType === 'address')
      levers.push('Provide an account xpub -- removes secp256k1 from the hot loop entirely (PLAN §3).');
    levers.push('Tighten a pattern segment (fewer alternatives / shorter quantifier).');
    if (targetType === 'address' && (pm.gap > 1 || pm.change > 1))
      levers.push('Lower --gap / drop change=1 -- shrinks the path multiplier directly.');
    if (mode === 'words' || mode === 'joint')
      levers.push('Remember one more mnemonic word -- divides the words-space by ~2048.');
    if (mode === 'joint')
      levers.push('This is a PRODUCT keyspace (words x passphrase) -- tightening either side multiplies down.');
    if (pm.purposes > 1)
      levers.push('Narrow --paths to the one script type your address implies (1..->44, 3..->49, bc1q->84, bc1p->86).');
  }

  return {
    mode, targetType, backend, unbounded,
    passphrase: hasPass
      ? { pattern: String(input.passphrasePattern), infinite: passInfinite,
          cardinality: passInfinite ? null : passCard,
          cardinalityHuman: passInfinite ? 'unbounded' : humanCount(passCard) }
      : null,
    mnemonic: hasWordsPattern
      ? { pattern: String(input.mnemonicPattern), survival }
      : (mode === 'passphrase' ? { fixed: true } : null),
    validMnemonicCount,
    pathPlan: pm,
    dim1,
    dim1Human: dim1 === null ? 'unbounded' : humanCount(dim1),
    totalCandidates,
    totalCandidatesHuman: totalCandidates === null ? 'unbounded' : humanCount(totalCandidates),
    eta,
    verdict, tier,
    narrowingLevers: levers,
    notes,
    warnings,
    rates,
    // cleanup helper for callers that parsed via this model
    _sets: { passSet, wordsSet },
  };
}

// Merge a (partial) calibration override onto the assumed defaults.
function mergeRates(cal) {
  const r = JSON.parse(JSON.stringify(DEFAULT_RATES));
  if (!cal) return r;
  r.calibrated = true;
  r.source = cal.source || 'calibrated (measured)';
  if (cal.cpu) Object.assign(r.cpu, cal.cpu);
  if (cal.gpu) Object.assign(r.gpu, cal.gpu);
  return r;
}

const _modelExports = {
  estimate, checksumSurvival, pathMultiplier,
  humanCount, humanTime, humanTimeUpper, mergeRates, verdictTier,
  DEFAULT_RATES, GREEN_MAX_SEC, YELLOW_MAX_SEC, MULTS_PER_ADDRESS,
};
if (typeof module !== 'undefined' && module.exports) module.exports = _modelExports;
if (typeof window !== 'undefined') window.BIP39Estimator = _modelExports;
