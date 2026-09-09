// wordset.js -- build a librxe expression for a KNOWN SET of words in UNKNOWN
// ORDER (or an unknown k-subset). librxe's {{k!}}/{{k}} CONCATENATES the chosen
// alternatives with NO separator, so we space-prefix each word: enumerated
// members come out " w_a w_b ... " and consumers trim()+NFKD before use (the
// BIP39 validator already trims + splits on whitespace). ordered=true ->
// permutations {{k!}}, false -> unordered combinations {{k}}; k defaults to all.
'use strict';
function reMeta(w){ return String(w).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function buildWordSetPattern(words, { k = null, ordered = true } = {}) {
  const ws = (Array.isArray(words) ? words : String(words).split(/[\s,]+/))
             .map(s => s.trim()).filter(Boolean);
  if (!ws.length) return null;
  const K = k == null ? ws.length : k;
  const alts = ws.map(w => ' ' + reMeta(w)).join('|');   // space-prefixed -> separated members
  return `(${alts}){{${K}${ordered ? '!' : ''}}}`;
}
// Exact full-decimal with locale thousands separators (no rounding/scientific).
function groupDigits(n){
  const s = (typeof n === 'bigint' ? n : BigInt(n)).toString();
  const neg = s[0] === '-'; const d = neg ? s.slice(1) : s;
  return (neg ? '-' : '') + d.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}
const _wordSetExports = { buildWordSetPattern, groupDigits, reMeta };
if (typeof module !== 'undefined' && module.exports) module.exports = _wordSetExports;
if (typeof window !== 'undefined') window.WordSet = _wordSetExports;
