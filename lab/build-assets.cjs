const fs = require('node:fs');
const path = require('node:path');
const { gzipSync } = require('node:zlib');

const [upstream, binary] = process.argv.slice(2);
if (!upstream || !binary) {
  throw new Error('Usage: node lab/build-assets.cjs <upstream-directory> <linux-386-soc-binary>');
}

const padding = (length) => Buffer.alloc((4 - length % 4) % 4);

function entry(name, contents, index) {
  const fileName = Buffer.from(`${name}\0`);
  const mode = name === 'TRAILER!!!' ? 0 : 0o100755;
  const fields = [index, mode, 0, 0, 1, 0, contents.length, 0, 0, 0, 0, fileName.length, 0];
  const header = Buffer.from(`070701${fields.map((field) => field.toString(16).padStart(8, '0')).join('')}`);
  return Buffer.concat([header, fileName, padding(header.length + fileName.length), contents, padding(contents.length)]);
}

const init = fs.readFileSync(path.join(__dirname, 'init.sh'), 'utf8').replace(/\r\n/g, '\n');
const initrd = gzipSync(Buffer.concat([
  entry('soc-init', Buffer.from(init), 1),
  entry('soc-lab', fs.readFileSync(binary), 2),
  entry('TRAILER!!!', Buffer.alloc(0), 3),
]), { level: 9 });

const load = (name) => fs.readFileSync(path.join(upstream, name)).toString('base64');
const assets = {
  kernel: load('buildroot.bin'),
  bios: load('seabios.bin'),
  vga: load('vgabios.bin'),
  wasm: load('package/build/v86.wasm'),
  initrd: initrd.toString('base64'),
};

const vendor = path.join(__dirname, 'runtime');
fs.mkdirSync(vendor, { recursive: true });
fs.writeFileSync(path.join(vendor, 'images.js'), `globalThis.SOC_IMAGES = ${JSON.stringify(assets)};\n`);
const emulator = fs.readFileSync(path.join(upstream, 'package/build/libv86.js'), 'utf8');
const guest = fs.readFileSync(path.join(__dirname, 'guest.js'), 'utf8');
fs.writeFileSync(path.join(vendor, 'worker.js'), `globalThis.SOC_WORKER = ${JSON.stringify(`${emulator}\n${guest}`)};\n`);
fs.copyFileSync(path.join(upstream, 'package/LICENSE'), path.join(vendor, 'LICENSE-v86.txt'));
