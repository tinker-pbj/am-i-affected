import fs from 'fs'; globalThis.window = globalThis; eval(fs.readFileSync('../docs/parsers.js','utf8'));
for (const f of fs.readdirSync('/home/worker/dl/biglocks')) {
  const t = fs.readFileSync('/home/worker/dl/biglocks/'+f,'utf8'); const t0=performance.now();
  const r = parseLockfile(t, f.replace(/^[a-z]+-/,'')); console.log(f, r ? r.kind+' '+r.packages.length : 'NULL', (performance.now()-t0).toFixed(0)+'ms');
}
