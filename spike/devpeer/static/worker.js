// Safe-prime worker: loads its own copy of the WASM build and returns safe
// primes (hex) to the page until it is terminated.
importScripts('wasm_exec.js');
const ready = (async () => {
  const go = new Go();
  const { instance } = await WebAssembly.instantiateStreaming(fetch('shardsign.wasm'), go.importObject);
  go.run(instance);
  while (!self.shardsign) await new Promise((r) => setTimeout(r, 10));
})();
self.onmessage = async () => {
  await ready;
  for (;;) {
    const t = performance.now();
    const prime = await self.shardsign.findSafePrime();
    self.postMessage({ prime, ms: Math.round(performance.now() - t) });
  }
};
