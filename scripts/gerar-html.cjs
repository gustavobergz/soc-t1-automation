"use strict";
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const file = path.join(root, 'index.html');
const original = fs.readFileSync(file, 'utf8');
let input=original;
let scripts = [...input.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)];
if(scripts.length===3&&fs.existsSync(path.join(root,'relatorio.js'))){
  input=input.slice(0,scripts[2].index)+'<script id="report-core"></script>\n'+input.slice(scripts[2].index);
  scripts=[...input.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)];
}
if (scripts.length !== 4 || !scripts[0][0].includes('id="sample-data"')) throw new Error('Estrutura do HTML inesperada.');
const bodies = [fs.readFileSync(path.join(root, 'clinica-investigacao-205k.jsonl.gz')).toString('base64'),
  fs.readFileSync(path.join(root, 'motor.js'), 'utf8'),fs.readFileSync(path.join(root,'relatorio.js'),'utf8'), fs.readFileSync(path.join(root, 'interface.js'), 'utf8')];
let result = input;
for (let i = scripts.length - 1; i >= 0; i--) {
  const match = scripts[i];
  const start = match.index + match[0].indexOf('>') + 1;
  const end = match.index + match[0].lastIndexOf('</script>');
  result = result.slice(0, start) + bodies[i] + result.slice(end);
}
if (process.argv.includes('--check')) {
  if (result !== original) { console.error('index.html precisa ser atualizado: execute node scripts/gerar-html.cjs'); process.exitCode = 1; }
  else console.log('HTML, motor, interface e base embutida conferem.');
} else {
  fs.writeFileSync(file + '.tmp', result, 'utf8');
  fs.renameSync(file + '.tmp', file);
  console.log('index.html gerado a partir dos fontes e da base completa.');
}
