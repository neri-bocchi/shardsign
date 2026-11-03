# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

PoC of a headless EVM wallet whose ECDSA key never exists whole: 2-of-3 TSS between the user (browser, WASM) and two signers whose shares live in OpenBao, signing normal EVM transactions (legacy, EIP-155, `gasPrice=0`) on a local Anvil chain. No ERC-4337. Spec: https://claude.ai/artifact/W6vweYBNtTq9YjZXk36z5i (it still says UserOps/GG20; `PLAN.md` records where the build deviates). `PLAN.md` is the 5-day plan and the day-by-day results; docs and plan are in Spanish.

## Commands

```
make test      # go test ./pkg/... (first run caches preparams in pkg/tss/testdata, ~10 s)
go test ./pkg/tss/ -run TestDKGSignReshare -v   # single test
make wasm      # GOOS=js GOARCH=wasm build of ./wasm → spike/devpeer/static (+ .br, wasm_exec.js)
make devpeer   # spike server; open http://127.0.0.1:8090/?auto (add &cache to reuse browser preparams)
make chain     # Anvil (native, foreground), chainId 7773, gas price and base fee 0, state in .anvil/
make smoke     # deploys TestToken, mines a gasPrice=0 tx from a zero-balance key; writes deployments/local.json
```

Go 1.27 workspace (`go.work`): modules `pkg`, `wasm`, `spike`. Each module's go.mod must keep the tss-lib replace `github.com/agl/ed25519 => github.com/binance-chain/edwards25519 …` and, for `wasm`/`spike`, `github.com/lnet/shardsign/pkg => ../pkg`. Run `go mod tidy` with `GOWORK=off` in those modules. gopls errors about `syscall/js` in `wasm/` are build-tag noise.

## Architecture

- `pkg/tss` is the single TSS implementation used by signers, CLIs and the browser. It wraps bnb-chain/tss-lib v2.0.2 (GG18) in a transport-agnostic `Session`: outgoing messages go to a `SendFunc` as `Envelope{Session, From, To, Broadcast, Payload}` with concrete recipient ids; incoming ones go to `Deliver`. Encryption/authentication of envelopes is the transport's job.
- Party ids are `<name>@<epoch>` (`user`, `app`, `signer-a`, `signer-b`; epoch = key_version). A reshare goes from epoch v to v+1, so one process can be in both committees under two ids; `Session` delivers to itself in that case. `Threshold` in configs means parties needed to sign (2); tss-lib's `t` is Threshold-1.
- Never use `keygen.GeneratePreParams`: it deadlocks under js/wasm. Use `tss.GeneratePreParams` (native) or `tss.FindSafePrime` + `tss.PreParamsFromAny` (browser, one WASM instance per Web Worker).
- `wasm/main.go` exposes `globalThis.shardsign` (preParams, findSafePrime, preParamsFromPrimes, keygen, sign, reshare). Key data and preparams cross to JS as opaque JSON strings (`keyJSON`, `preParamsJSON`) because big ints break under `JSON.parse`. Setup errors return `{error}`; panicking in a `js.FuncOf` kills the page's Go runtime.
- Signatures come out low-S with a recovery id; `tss.EthSignature` returns r||s||v with v ∈ {0,1}.
- `spike/` is throwaway day-1 code (devpeer = both signers in one process over a WebSocket, no auth, keys in memory). The real `signer/`, `coordinator/` and `otp-service/` come on day 2+.
- `infra/dev-keys.env` (Anvil key #0) is a public local-chain-only key, committed on purpose. The spec says Besu; the PoC uses Anvil (see `PLAN.md`), so nothing may depend on Anvil-only RPCs (`anvil_*`, `evm_*`, impersonation) — only standard `eth_*`.
