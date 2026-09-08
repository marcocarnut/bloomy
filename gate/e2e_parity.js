#!/usr/bin/env node
/* e2e_parity.js -- prove the server's program-probe (bloomq / bloom_host_member) gives the
 * SAME membership as the reference cracker's address-probe (`bip39rxcrack --bloom-check`).
 *
 * Generate N addresses from random seeds; build a --classic1 .blf from HALF of them (the
 * members); then for ALL N, compare:
 *   (a) the CLI's `--bloom-check ADDR` verdict (MEMBER = filter1 HIT && filter2 HIT), against
 *   (b) bloomq fed the raw 20-byte program hex (what reseed39 actually sends over the wire).
 * Assert: every true member HITs in both (no false negatives), and the CLI's member set ==
 * bloomq's hit set (byte-for-byte parity). Usage: node gate/e2e_parity.js
 */
'use strict';
const fs=require('fs'), path=require('path'), os=require('os'), crypto=require('crypto');
const { execFileSync }=require('child_process');
const R=process.env.RESEED39_DIR||'/root/bip39rxcrack';
const C=require(path.join(R,'estimator','bip39crypto.js'));
const CLI=process.env.CLI||'/root/bip39rxcrack-cli/bip39rxcrack';
const BLOOMQ=path.join(__dirname,'..','bloomq');
const hex=(u8)=>Buffer.from(u8).toString('hex');

// N addresses from deterministic random seeds; first half are the filter members.
const N=60, MEMBERS=30;
let st=0xC0FFEE>>>0; const rnd=()=>{st^=st<<13;st^=st>>>17;st^=st<<5;st>>>=0;return st;};
const rb=(n)=>{const a=Buffer.alloc(n);for(let i=0;i<n;i++)a[i]=rnd()&255;return a;};
const items=[]; // {addr, progHex}
const seen=new Set();
while(items.length<N){
  const s=rb(64);                                   // a raw 64-byte seed
  const tg=C.addressTarget(s,84,0,0,0,0);           // p2wpkh -> {type, program:hash160}
  const addr=C.encodeAddress(tg,'bc');
  if(seen.has(addr)) continue; seen.add(addr);
  items.push({addr, progHex:hex(tg.program)});
}
const memberSet=new Set(items.slice(0,MEMBERS).map(x=>x.addr));

let fail=0; const ck=(c,m)=>{ console.log((c?'  ok   ':'  FAIL ')+m); if(!c)fail++; };
console.log('== reseed39 bloom-server parity: bloomq (program) vs CLI --bloom-check (address) ==');
console.log(`generated ${N} addresses, ${MEMBERS} planted as members`);

const blf=path.join(os.tmpdir(),`bloomq_${process.pid}.blf`);
execFileSync(CLI,['--bloom-build','-',blf,'--bloom-gib','0.1,0.05','--classic1','--bloom-n','1000'],
  {input:items.slice(0,MEMBERS).map(x=>x.addr).join('\n')+'\n', stdio:['pipe','ignore','inherit']});

// (a) CLI verdicts
const out=execFileSync(CLI,['--bloom',blf,'--bloom-check',items.map(x=>x.addr).join(',')],
  {encoding:'utf8',stdio:['ignore','pipe','inherit']});
const cliMember=new Set();
for(const line of out.split('\n')){ const m=line.match(/^(\S+)\s.*=>\s*MEMBER/); if(m) cliMember.add(m[1]); }

// (b) bloomq verdicts (feed the raw program hex -- what reseed39 sends)
const hitOut=execFileSync(BLOOMQ,[blf],{input:items.map(x=>x.progHex).join('\n')+'\n',encoding:'utf8',stdio:['pipe','pipe','inherit']});
const hitProgs=new Set(hitOut.split('\n').map(s=>s.trim()).filter(Boolean));
const bloomqMember=new Set(items.filter(x=>hitProgs.has(x.progHex)).map(x=>x.addr));

// asserts
let fnCli=0,fnBq=0; for(const a of memberSet){ if(!cliMember.has(a))fnCli++; if(!bloomqMember.has(a))fnBq++; }
ck(fnCli===0, `no false negatives in CLI (${MEMBERS-fnCli}/${MEMBERS} members found)`);
ck(fnBq===0,  `no false negatives in bloomq (${MEMBERS-fnBq}/${MEMBERS} members found)`);
let disagree=0; for(const x of items){ if(cliMember.has(x.addr)!==bloomqMember.has(x.addr)) disagree++; }
ck(disagree===0, `CLI and bloomq agree on all ${N} addresses (0 disagreements)`);
ck(cliMember.size===bloomqMember.size, `member counts match (CLI ${cliMember.size}, bloomq ${bloomqMember.size})`);

try{ fs.unlinkSync(blf); }catch(e){}
console.log(`\n==== e2e_parity: ${fail?'FAILED ('+fail+')':'PASSED'} ====`);
process.exit(fail?1:0);
