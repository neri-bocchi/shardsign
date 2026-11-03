//go:build js && wasm

// Command wasm exposes pkg/tss to JavaScript as globalThis.shardsign.
//
//	shardsign.preParams(): Promise<string>                      // JSON LocalPreParams
//	shardsign.keygen(cfgJSON, send): Handle                     // KeygenConfig + preParamsJSON
//	shardsign.sign(cfgJSON, send): Handle                       // SignConfig + keyJSON, hash (hex)
//	shardsign.reshare(cfgJSON, send): Handle                    // ReshareConfig + oldKeyJSON?, preParamsJSON?
//	Handle.deliver(envJSON): string | null                       // error text or null
//	Handle.done: Promise<string>                                // JSON {keyJSON?, signature?, pubkey, address}
//	Handle.waitingFor(): string                                 // JSON array of party ids
//
// send(envJSON) is called for every outgoing envelope. All JSON uses the Go
// field names of pkg/tss; []byte fields are base64.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"syscall/js"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/lnet/shardsign/pkg/tss"
)

// Big integers do not survive JSON.parse in JavaScript, so key data and
// pre-parameters cross the boundary as opaque JSON strings (keyJSON,
// preParamsJSON) that JS stores and passes back without parsing.
type result struct {
	KeyJSON   string `json:"keyJSON,omitempty"`
	Signature string `json:"signature,omitempty"` // hex r||s||v, v in {0,1}
	PubKey    string `json:"pubkey,omitempty"`
	Address   string `json:"address,omitempty"`
}

func promise(fn func() (string, error)) js.Value {
	var handler js.Func
	handler = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			defer handler.Release()
			out, err := fn()
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke(out)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func sender(cb js.Value) tss.SendFunc {
	return func(e tss.Envelope) {
		b, _ := json.Marshal(e)
		cb.Invoke(string(b))
	}
}

func handle(s *tss.Session) js.Value {
	h := js.Global().Get("Object").New()
	h.Set("deliver", js.FuncOf(func(_ js.Value, args []js.Value) any {
		var e tss.Envelope
		if err := json.Unmarshal([]byte(args[0].String()), &e); err != nil {
			return err.Error()
		}
		// UpdateFromBytes may run a whole round; keep it off the JS callback.
		go func() { _ = s.Deliver(e) }()
		return nil
	}))
	h.Set("waitingFor", js.FuncOf(func(js.Value, []js.Value) any {
		b, _ := json.Marshal(s.WaitingFor())
		return string(b)
	}))
	h.Set("done", promise(func() (string, error) {
		r := <-s.Done()
		if r.Err != nil {
			return "", r.Err
		}
		var out result
		if r.Sig != nil {
			sig, err := tss.EthSignature(r.Sig)
			if err != nil {
				return "", err
			}
			out.Signature = hex.EncodeToString(sig)
		}
		if r.Key != nil {
			kb, err := json.Marshal(r.Key)
			if err != nil {
				return "", err
			}
			out.KeyJSON = string(kb)
			pub, err := tss.PublicKey(r.Key)
			if err != nil {
				return "", err
			}
			addr, _ := tss.Address(pub)
			out.PubKey, out.Address = hex.EncodeToString(pub), "0x"+hex.EncodeToString(addr[:])
		}
		b, err := json.Marshal(out)
		return string(b), err
	}))
	s.Start()
	return h
}

// fail reports a setup error to JavaScript as { error } instead of panicking,
// which would kill the Go runtime for the whole page.
func fail(err error) js.Value {
	js.Global().Get("console").Call("error", "shardsign: "+err.Error())
	o := js.Global().Get("Object").New()
	o.Set("error", err.Error())
	return o
}

func main() {
	api := js.Global().Get("Object").New()

	// Sequential fallback: one WASM instance searches all four primes.
	api.Set("preParams", js.FuncOf(func(js.Value, []js.Value) any {
		return promise(func() (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			p, err := tss.GeneratePreParams(ctx, 1)
			if err != nil {
				return "", err
			}
			b, err := json.Marshal(p)
			return string(b), err
		})
	}))

	// For Web Workers: each worker calls findSafePrime(); the page collects
	// the primes and calls preParamsFromPrimes(JSON array of hex) until it
	// gets pre-parameters back (null means: find one more prime).
	api.Set("findSafePrime", js.FuncOf(func(js.Value, []js.Value) any {
		return promise(func() (string, error) {
			p, err := tss.FindSafePrime(context.Background(), tss.SafePrimeBits, nil)
			if err != nil {
				return "", err
			}
			return p.Text(16), nil
		})
	}))
	api.Set("preParamsFromPrimes", js.FuncOf(func(_ js.Value, args []js.Value) any {
		var hexes []string
		if err := json.Unmarshal([]byte(args[0].String()), &hexes); err != nil {
			return fail(err)
		}
		var primes []*big.Int
		for _, h := range hexes {
			p, ok := new(big.Int).SetString(h, 16)
			if !ok {
				return fail(errors.New("bad prime hex"))
			}
			primes = append(primes, p)
		}
		pp, err := tss.PreParamsFromAny(primes, nil)
		if err != nil {
			return js.Null()
		}
		b, _ := json.Marshal(pp)
		return string(b)
	}))

	api.Set("keygen", js.FuncOf(func(_ js.Value, args []js.Value) any {
		var c struct {
			tss.KeygenConfig
			PreParamsJSON string `json:"preParamsJSON"`
		}
		if err := json.Unmarshal([]byte(args[0].String()), &c); err != nil {
			return fail(err)
		}
		var pp keygen.LocalPreParams
		if err := json.Unmarshal([]byte(c.PreParamsJSON), &pp); err != nil {
			return fail(err)
		}
		c.KeygenConfig.PreParams = &pp
		s, err := tss.NewKeygen(c.KeygenConfig, sender(args[1]))
		if err != nil {
			return fail(err)
		}
		return handle(s)
	}))

	api.Set("sign", js.FuncOf(func(_ js.Value, args []js.Value) any {
		var c struct {
			tss.SignConfig
			HashHex string `json:"hash"`
			KeyJSON string `json:"keyJSON"`
		}
		if err := json.Unmarshal([]byte(args[0].String()), &c); err != nil {
			return fail(err)
		}
		if err := json.Unmarshal([]byte(c.KeyJSON), &c.SignConfig.Key); err != nil {
			return fail(err)
		}
		h, err := hex.DecodeString(c.HashHex)
		if err != nil || len(h) != 32 {
			return fail(errors.New("hash must be 32 bytes of hex"))
		}
		c.SignConfig.Hash = h
		s, err := tss.NewSign(c.SignConfig, sender(args[1]))
		if err != nil {
			return fail(err)
		}
		return handle(s)
	}))

	api.Set("reshare", js.FuncOf(func(_ js.Value, args []js.Value) any {
		var c struct {
			tss.ReshareConfig
			OldKeyJSON    string `json:"oldKeyJSON"`
			PreParamsJSON string `json:"preParamsJSON"`
		}
		if err := json.Unmarshal([]byte(args[0].String()), &c); err != nil {
			return fail(err)
		}
		if c.OldKeyJSON != "" {
			c.ReshareConfig.OldKey = new(keygen.LocalPartySaveData)
			if err := json.Unmarshal([]byte(c.OldKeyJSON), c.ReshareConfig.OldKey); err != nil {
				return fail(err)
			}
		}
		if c.PreParamsJSON != "" {
			c.ReshareConfig.PreParams = new(keygen.LocalPreParams)
			if err := json.Unmarshal([]byte(c.PreParamsJSON), c.ReshareConfig.PreParams); err != nil {
				return fail(err)
			}
		}
		s, err := tss.NewReshare(c.ReshareConfig, sender(args[1]))
		if err != nil {
			return fail(err)
		}
		return handle(s)
	}))

	js.Global().Set("shardsign", api)
	if js.Global().Get("dispatchEvent").Type() == js.TypeFunction {
		js.Global().Call("dispatchEvent", js.Global().Get("Event").New("shardsign-ready"))
	}
	select {}
}
