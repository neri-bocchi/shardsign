STATIC := spike/devpeer/static

.PHONY: test wasm devpeer chain smoke

test:            ## Go tests (first run generates preparams, ~10 s)
	go test ./pkg/... -timeout 20m

wasm:            ## build pkg/tss for the browser (+ brotli)
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o $(STATIC)/shardsign.wasm ./wasm
	brotli -q 11 -k -f $(STATIC)/shardsign.wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" $(STATIC)/

devpeer: wasm    ## spike: signer-a + signer-b in Go, page at http://127.0.0.1:8090/?auto
	go run ./spike/devpeer

chain:           ## Anvil, chainId 7773, gas 0, state kept in .anvil/ (foreground)
	mkdir -p .anvil
	anvil --chain-id 7773 --gas-price 0 --base-fee 0 --host 127.0.0.1 --port 8545 --state .anvil/state.json

smoke:           ## deploy TestToken and mine a gasPrice=0 tx from a zero-balance key (needs make chain)
	./scripts/smoke.sh
