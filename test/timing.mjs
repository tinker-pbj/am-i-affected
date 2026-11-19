import fs from 'fs'; globalThis.window = globalThis; eval(fs.readFileSync('../docs/parsers.js','utf8'));
const r = parseLockfile(fs.readFileSync('/home/worker/dl/biglocks/next-pnpm-lock.yaml','utf8'), 'pnpm-lock.yaml');
const q = r.packages.map(p => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version }));
let t0 = performance.now(); const res = [];
for (let i = 0; i < q.length; i += 900) { const x = await fetch('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ queries: q.slice(i, i+900) }) }); res.push(...(await x.json()).results); }
const ids = new Set(); res.forEach(r => (r.vulns||[]).forEach(v => ids.add(v.id)));
console.log('batch', ((performance.now()-t0)/1000).toFixed(1)+'s', 'packages', q.length, 'vuln ids', ids.size, 'hit pkgs', res.filter(r=>r.vulns).length);
for (const C of [8, 24]) { const list=[...ids].slice(0,400); t0=performance.now();
  await Promise.all(Array.from({length:C}, async()=>{ while(list.length){ const id=list.pop(); await fetch('https://api.osv.dev/v1/vulns/'+id).then(r=>r.json()).catch(()=>{}); }}));
  console.log('details conc', C, ((performance.now()-t0)/1000).toFixed(1)+'s'); }
