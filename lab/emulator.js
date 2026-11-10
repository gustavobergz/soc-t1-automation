'use strict';

globalThis.SocEmulator = (() => {
  const roles = ['manager', 'victim', 'attacker', 'soar'];

  function bufferFromBase64(encoded) {
    if (typeof Uint8Array.fromBase64 === 'function') {
      return Uint8Array.fromBase64(encoded).buffer;
    }
    return Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0)).buffer;
  }

  async function start(assets, source, onEvent, onError) {
    const wasm = await WebAssembly.compile(bufferFromBase64(assets.wasm));
    const image = (name) => ({ buffer: bufferFromBase64(assets[name]) });
    const images = { bios: image('bios'), vga_bios: image('vga'), bzimage: image('kernel'), initrd: image('initrd') };
    const url = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
    const workers = new Map();
    try {
      for (const role of roles) {
        const worker = new Worker(url, { name: `soc-${role}` });
        workers.set(role, worker);
        worker.addEventListener('message', ({ data }) => {
          switch (data.type) {
            case 'frame':
              for (const [peer, other] of workers) {
                if (peer !== role) other.postMessage(data);
              }
              break;
            case 'event':
              onEvent(data.event);
              break;
            case 'serial':
              console.debug(`${role} | ${data.line}`);
              break;
          }
        });
        worker.addEventListener('error', (event) => onError(role, event.message));
        worker.postMessage({ type: 'boot', wasm, images, role });
      }
    } catch (error) {
      for (const worker of workers.values()) worker.terminate();
      throw error;
    } finally {
      URL.revokeObjectURL(url);
    }
    return {
      command(role, line) {
        workers.get(role).postMessage({ type: 'command', line });
      },
    };
  }

  return { start };
})();
