import fs from 'fs'; import fx from './fixtures.mjs'; import fx2 from './fixtures2.mjs';
globalThis.window = globalThis; eval(fs.readFileSync('../docs/parsers.js','utf8'));
let bad = 0;
for (const [name, text] of Object.entries({...fx, ...fx2})) {
  const a = parseLockfile(text, name.replace('-berry','')), b = parseLockfile(text, '');
  const ok = a && b && a.kind === b.kind;
  if (!a) bad++;
  console.log((ok ? '✓' : (a ? '~' : '✗')), name.padEnd(18), a ? `${a.kind}: ${a.packages.map(p=>p.ecosystem+':'+p.name+'@'+p.version).join(' ')}` : 'NULL', b && a && a.kind !== b.kind ? `| pasted→${b.kind}` : (b ? '' : '| pasted→NULL'));
}
process.exit(bad);
