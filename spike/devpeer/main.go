// Command devpeer is the day-1 spike: it runs signer-a and signer-b in one
// process behind a WebSocket so a browser running the "user" party in WASM
// can do a DKG and sign against two native Go parties. It also serves the
// test page. Not production code: no auth, no OpenBao, keys in memory.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/lnet/shardsign/pkg/tss"
)

var signers = []string{"signer-a", "signer-b"}

// msg is the control + relay protocol on the WebSocket.
type msg struct {
	Op      string        `json:"op"`
	Session string        `json:"session,omitempty"`
	Env     *tss.Envelope `json:"env,omitempty"`
	Hash    string        `json:"hash,omitempty"`
	With    string        `json:"with,omitempty"` // which signer joins the user in a sign
	Address string        `json:"address,omitempty"`
	OK      bool          `json:"ok,omitempty"`
	Error   string        `json:"error,omitempty"`
	Millis  int64         `json:"millis,omitempty"`
}

func loadPreParams(path string) map[string]*keygen.LocalPreParams {
	pp := map[string]*keygen.LocalPreParams{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &pp)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range signers {
		if p, ok := pp[s]; ok && p.ValidateWithProof() {
			continue
		}
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			log.Printf("generating preparams for %s…", s)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			p, err := tss.GeneratePreParams(ctx, 0)
			if err != nil {
				log.Fatalf("preparams %s: %v", s, err)
			}
			mu.Lock()
			pp[s] = p
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	b, _ := json.Marshal(pp)
	_ = os.WriteFile(path, b, 0o600)
	return pp
}

type conn struct {
	ws   *websocket.Conn
	ctx  context.Context
	wmu  sync.Mutex
	pp   map[string]*keygen.LocalPreParams
	keys map[string]*keygen.LocalPartySaveData
	addr [20]byte

	mu       sync.Mutex
	sessions map[string]*tss.Session // party id -> session (signers only)
}

func (c *conn) write(m msg) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := wsjson.Write(c.ctx, c.ws, m); err != nil {
		log.Printf("ws write: %v", err)
	}
}

// send routes a signer's envelope: to the other signer in process, or to the
// browser over the WebSocket.
func (c *conn) send(e tss.Envelope) {
	var remote []string
	for _, to := range e.To {
		c.mu.Lock()
		dst := c.sessions[to]
		c.mu.Unlock()
		if dst != nil {
			one := e
			one.To = []string{to}
			go func() {
				if err := dst.Deliver(one); err != nil {
					log.Printf("deliver %s: %v", to, err)
				}
			}()
		} else {
			remote = append(remote, to)
		}
	}
	if len(remote) > 0 {
		e.To = remote
		c.write(msg{Op: "env", Env: &e})
	}
}

func (c *conn) start(id string, sessions map[string]*tss.Session, done func(map[string]tss.Result)) {
	c.mu.Lock()
	c.sessions = sessions
	c.mu.Unlock()
	for _, s := range sessions {
		s.Start()
	}
	go func() {
		out := map[string]tss.Result{}
		for pid, s := range sessions {
			select {
			case r := <-s.Done():
				if r.Err != nil {
					c.write(msg{Op: "error", Session: id, Error: fmt.Sprintf("%s: %v", pid, r.Err)})
					return
				}
				out[pid] = r
			case <-time.After(60 * time.Second):
				c.write(msg{Op: "error", Session: id, Error: fmt.Sprintf("%s timed out waiting for %v", pid, s.WaitingFor())})
				return
			}
		}
		done(out)
	}()
}

func (c *conn) keygen() {
	id := fmt.Sprintf("dkg-%d", time.Now().UnixNano())
	parties := []string{"user", "signer-a", "signer-b"}
	sessions := map[string]*tss.Session{}
	for _, s := range signers {
		sess, err := tss.NewKeygen(tss.KeygenConfig{Session: id, Self: s, Parties: parties, Epoch: 1, Threshold: 2, PreParams: c.pp[s]}, c.send)
		if err != nil {
			c.write(msg{Op: "error", Error: err.Error()})
			return
		}
		sessions[tss.PartyRef(s, 1)] = sess
	}
	start := time.Now()
	c.write(msg{Op: "ready", Session: id})
	c.start(id, sessions, func(r map[string]tss.Result) {
		c.keys = map[string]*keygen.LocalPartySaveData{}
		for _, s := range signers {
			c.keys[s] = r[tss.PartyRef(s, 1)].Key
		}
		pub, _ := tss.PublicKey(c.keys["signer-a"])
		c.addr, _ = tss.Address(pub)
		log.Printf("DKG %s done in %s, address 0x%x", id, time.Since(start), c.addr)
		c.write(msg{Op: "done", Session: id, Address: "0x" + hex.EncodeToString(c.addr[:]), Millis: time.Since(start).Milliseconds()})
	})
}

func (c *conn) sign(hashHex, with string) {
	if c.keys == nil {
		c.write(msg{Op: "error", Error: "no wallet yet: run keygen first"})
		return
	}
	if with != "signer-a" && with != "signer-b" {
		with = "signer-a"
	}
	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != 32 {
		c.write(msg{Op: "error", Error: "hash must be 32 bytes hex"})
		return
	}
	id := fmt.Sprintf("sign-%d", time.Now().UnixNano())
	sess, err := tss.NewSign(tss.SignConfig{Session: id, Self: with, Signers: []string{"user", with}, Epoch: 1, Threshold: 2, Key: *c.keys[with], Hash: hash}, c.send)
	if err != nil {
		c.write(msg{Op: "error", Error: err.Error()})
		return
	}
	start := time.Now()
	c.write(msg{Op: "ready", Session: id})
	c.start(id, map[string]*tss.Session{tss.PartyRef(with, 1): sess}, func(r map[string]tss.Result) {
		sig, _ := tss.EthSignature(r[tss.PartyRef(with, 1)].Sig)
		compact := append([]byte{27 + sig[64]}, sig[:64]...)
		pub, _, err := secpecdsa.RecoverCompact(compact, hash)
		ok := false
		if err == nil {
			got, _ := tss.Address(pub.SerializeUncompressed())
			ok = got == c.addr
		}
		log.Printf("sign %s with %s done in %s, recovers wallet address: %v", id, with, time.Since(start), ok)
		c.write(msg{Op: "done", Session: id, OK: ok, Address: "0x" + hex.EncodeToString(c.addr[:]), Millis: time.Since(start).Milliseconds()})
	})
}

func (c *conn) deliver(e *tss.Envelope) {
	for _, to := range e.To {
		c.mu.Lock()
		dst := c.sessions[to]
		c.mu.Unlock()
		if dst == nil {
			log.Printf("envelope for unknown party %s", to)
			continue
		}
		one := *e
		one.To = []string{to}
		go func() {
			if err := dst.Deliver(one); err != nil {
				log.Printf("deliver %s: %v", to, err)
			}
		}()
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "listen address")
	static := flag.String("static", "spike/devpeer/static", "static dir")
	ppPath := flag.String("preparams", "spike/devpeer/preparams.json", "preparams cache (gitignored)")
	flag.Parse()
	pp := loadPreParams(*ppPath)

	files := http.FileServer(http.Dir(*static))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".wasm") {
			w.Header().Set("Content-Type", "application/wasm")
			if strings.Contains(r.Header.Get("Accept-Encoding"), "br") {
				if _, err := os.Stat(filepath.Join(*static, r.URL.Path+".br")); err == nil {
					w.Header().Set("Content-Encoding", "br")
					http.ServeFile(w, r, filepath.Join(*static, r.URL.Path+".br"))
					return
				}
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ws.SetReadLimit(16 << 20)
		c := &conn{ws: ws, ctx: r.Context(), pp: pp}
		defer ws.CloseNow()
		for {
			var m msg
			if err := wsjson.Read(r.Context(), ws, &m); err != nil {
				return
			}
			switch m.Op {
			case "keygen":
				c.keygen()
			case "sign":
				c.sign(m.Hash, m.With)
			case "env":
				if m.Env != nil {
					c.deliver(m.Env)
				}
			}
		}
	})
	log.Printf("devpeer on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
