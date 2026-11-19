import fs from 'fs'; import fx from './fixtures.mjs';
globalThis.window = globalThis; eval(fs.readFileSync('../docs/parsers.js','utf8'));
for (const [name, text] of Object.entries(fx)) {
  const a = parseLockfile(text, name.replace('-berry','')), b = parseLockfile(text, '');
  console.log(name.padEnd(18), a ? `${a.kind}/${a.ecosystem} ${JSON.stringify(a.packages)} ${JSON.stringify(a.extra||{})}` : 'NULL', '| pasted:', b ? b.kind : 'NULL');
}
