// Day-1 spike client: loads the WASM build of pkg/tss, runs the "user" party
// of a DKG and two signatures against devpeer's signer-a and signer-b.
const $log = document.getElementById('log');
const t0 = performance.now();
const log = (...a) => { const line = `[${((performance.now() - t0) / 1000).toFixed(2)}s] ${a.join(' ')}`; console.log(line); $log.textContent += line + '\n'; };
window.__result = { status: 'idle', timings: {} };

async function loadWasm() {
  const go = new Go();
  const start = performance.now();
  const ready = new Promise((r) => addEventListener('shardsign-ready', r, { once: true }));
  const { instance } = await WebAssembly.instantiateStreaming(fetch('shardsign.wasm'), go.importObject);
  go.run(instance);
  await ready;
  return performance.now() - start;
}

// Each worker searches safe primes; the page assembles pre-parameters as soon
// as four usable primes exist, then stops the workers.
function preParamsInWorkers(n) {
  return new Promise((resolve, reject) => {
    const primes = [];
    const pool = [];
    const stop = () => pool.forEach((w) => w.terminate());
    for (let i = 0; i < n; i++) {
      const w = new Worker('worker.js');
      w.onmessage = ({ data }) => {
        primes.push(data.prime);
        log(`  primo ${primes.length} (worker ${i}, ${(data.ms / 1000).toFixed(1)} s)`);
        if (primes.length < 4) return;
        const pp = shardsign.preParamsFromPrimes(JSON.stringify(primes));
        if (pp) { stop(); resolve(pp); }
      };
      w.onerror = (e) => { stop(); reject(new Error(e.message)); };
      w.postMessage('find');
      pool.push(w);
    }
  });
}

function connect() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://${location.host}/ws`);
    ws.onopen = () => resolve(ws);
    ws.onerror = reject;
  });
}

// Runs one protocol session: asks devpeer to start its side, then runs the
// user's side in WASM and relays envelopes both ways.
function session(ws, request, makeHandle) {
  return new Promise((resolve, reject) => {
    let handle = null;
    let local = null;
    let remote = null;
    const finish = () => { if (local && remote) { ws.onmessage = null; resolve({ local, remote }); } };
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.op === 'ready') {
        handle = makeHandle(m.session, (env) => ws.send(JSON.stringify({ op: 'env', env: JSON.parse(env) })));
        if (handle.error) { reject(new Error(handle.error)); return; }
        handle.done.then((r) => { local = JSON.parse(r); finish(); }, reject);
      } else if (m.op === 'env') {
        const err = handle.deliver(JSON.stringify(m.env));
        if (err) reject(new Error(err));
      } else if (m.op === 'done') {
        remote = m; finish();
      } else if (m.op === 'error') {
        reject(new Error(m.error));
      }
    };
    ws.send(JSON.stringify(request));
  });
}

async function sha256hex(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function run() {
  const R = window.__result;
  R.status = 'running';
  try {
    R.timings.wasmLoadMs = Math.round(await loadWasm());
    log(`WASM cargado en ${R.timings.wasmLoadMs} ms`);

    let pp = null;
    const useCache = document.getElementById('cache').checked || new URLSearchParams(location.search).has('cache');
    try { if (useCache) pp = localStorage.getItem('shardsign-spike-preparams'); } catch {}
    if (pp) {
      log('preparams: reusando los guardados');
      R.timings.preParamsMs = 0;
    } else {
      const workers = Math.max(1, Math.min(8, (navigator.hardwareConcurrency || 4) - 1));
      log(`generando preparams con ${workers} Web Workers (4 primos seguros de 1024 bits)…`);
      const s = performance.now();
      pp = await preParamsInWorkers(workers);
      R.timings.preParamsMs = Math.round(performance.now() - s);
      log(`preparams en ${(R.timings.preParamsMs / 1000).toFixed(1)} s`);
      try { if (useCache) localStorage.setItem('shardsign-spike-preparams', pp); } catch {}
    }

    const ws = await connect();
    let s = performance.now();
    const dkg = await session(ws, { op: 'keygen' }, (session, send) =>
      shardsign.keygen(JSON.stringify({ Session: session, Self: 'user', Parties: ['user', 'signer-a', 'signer-b'], Epoch: 1, Threshold: 2, preParamsJSON: pp }), send));
    R.timings.dkgMs = Math.round(performance.now() - s);
    R.address = dkg.local.address;
    R.addressMatches = dkg.local.address === dkg.remote.address;
    log(`DKG en ${R.timings.dkgMs} ms · browser ${dkg.local.address} · signers ${dkg.remote.address} · coinciden: ${R.addressMatches}`);

    const hash = await sha256hex('shardsign día 1: firma desde el browser');
    R.signatures = {};
    for (const withSigner of ['signer-a', 'signer-b']) {
      s = performance.now();
      const res = await session(ws, { op: 'sign', hash, with: withSigner }, (session, send) =>
        shardsign.sign(JSON.stringify({ Session: session, Self: 'user', Signers: ['user', withSigner], Epoch: 1, Threshold: 2, keyJSON: dkg.local.keyJSON, hash }), send));
      const ms = Math.round(performance.now() - s);
      R.timings[`sign_${withSigner}_ms`] = ms;
      R.signatures[withSigner] = { signature: res.local.signature, verifiedByServer: res.remote.ok };
      log(`firma user+${withSigner} en ${ms} ms · el servidor recupera la dirección de la wallet: ${res.remote.ok}`);
    }
    R.status = R.addressMatches && Object.values(R.signatures).every((x) => x.verifiedByServer) ? 'pass' : 'fail';
    log(`RESULTADO: ${R.status.toUpperCase()}`);
    ws.close();
  } catch (e) {
    R.status = 'error';
    R.error = String(e);
    log('ERROR', e);
  }
}

document.getElementById('run').onclick = run;
if (new URLSearchParams(location.search).has('auto')) run();
