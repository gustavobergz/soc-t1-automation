'use strict';

const decoder = new TextDecoder();
const prefix = '@@SOC@@';
let guest;
let bytes = [];

function onSerial(byte) {
  if (byte !== 10) {
    if (byte !== 13) bytes.push(byte);
    return;
  }
  const line = decoder.decode(Uint8Array.from(bytes));
  bytes = [];
  if (line.startsWith(prefix)) {
    postMessage({ type: 'event', event: JSON.parse(line.slice(prefix.length)) });
  } else if (line) {
    postMessage({ type: 'serial', line });
  }
}

function boot({ wasm, images, role }) {
  guest = new self.V86({
    wasm_fn: async (imports) => (await WebAssembly.instantiate(wasm, imports)).exports,
    ...images,
    memory_size: 96 * 1024 * 1024,
    vga_memory_size: 2 * 1024 * 1024,
    autostart: true,
    disable_keyboard: true,
    disable_mouse: true,
    disable_speaker: true,
    net_device: { type: 'ne2k' },
    cmdline: `console=ttyS0,115200 loglevel=3 tsc=reliable mitigations=off random.trust_cpu=on rdinit=/soc-init soc.role=${role}`,
  });
  guest.add_listener('serial0-output-byte', onSerial);
  guest.add_listener('net0-send', (frame) => postMessage({ type: 'frame', frame }));
}

self.addEventListener('message', ({ data }) => {
  switch (data.type) {
    case 'boot':
      boot(data);
      break;
    case 'frame':
      guest.bus.send('net0-receive', data.frame);
      break;
    case 'command':
      guest.serial0_send(`${data.line}\n`);
      break;
  }
});
