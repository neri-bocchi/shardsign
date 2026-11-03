package tss

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// preParams loads cached safe primes from testdata (gitignored) or generates
// them; generation takes tens of seconds per party.
func preParams(t *testing.T, names ...string) map[string]*keygen.LocalPreParams {
	t.Helper()
	path := filepath.Join("testdata", "preparams.json")
	cache := map[string]*keygen.LocalPreParams{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cache)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range names {
		if p, ok := cache[n]; ok && p.ValidateWithProof() {
			continue
		}
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			p, err := GeneratePreParams(ctx, 4)
			if err != nil {
				t.Errorf("preparams %s: %v", n, err)
				return
			}
			t.Logf("preparams %s generated in %s", n, time.Since(start).Round(time.Millisecond))
			mu.Lock()
			cache[n] = p
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	_ = os.MkdirAll("testdata", 0o755)
	b, _ := json.Marshal(cache)
	_ = os.WriteFile(path, b, 0o600)
	return cache
}

// network routes envelopes between in-process sessions, one per process.
type network struct {
	mu    sync.Mutex
	procs map[string]*Session // party id -> owning session
}

func (n *network) register(s *Session) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id := range s.locals {
		n.procs[id] = s
	}
}

func (n *network) send(t *testing.T) SendFunc {
	return func(e Envelope) {
		for _, to := range e.To {
			n.mu.Lock()
			dst := n.procs[to]
			n.mu.Unlock()
			if dst == nil {
				t.Errorf("no process for %s", to)
				continue
			}
			one := e
			one.To = []string{to}
			go func() {
				if err := dst.Deliver(one); err != nil {
					t.Errorf("deliver to %s: %v", to, err)
				}
			}()
		}
	}
}

func run(t *testing.T, sessions ...*Session) []Result {
	t.Helper()
	out := make([]Result, len(sessions))
	for _, s := range sessions {
		s.Start()
	}
	for i, s := range sessions {
		select {
		case r := <-s.Done():
			if r.Err != nil {
				t.Fatalf("session %d: %v", i, r.Err)
			}
			out[i] = r
		case <-time.After(2 * time.Minute):
			t.Fatalf("session %d timed out, waiting for %v", i, s.WaitingFor())
		}
	}
	return out
}

func keygenAll(t *testing.T, pp map[string]*keygen.LocalPreParams, parties []string) map[string]*keygen.LocalPartySaveData {
	n := &network{procs: map[string]*Session{}}
	var ss []*Session
	for _, p := range parties {
		s, err := NewKeygen(KeygenConfig{Session: "dkg-1", Self: p, Parties: parties, Epoch: 1, Threshold: 2, PreParams: pp[p]}, n.send(t))
		if err != nil {
			t.Fatal(err)
		}
		n.register(s)
		ss = append(ss, s)
	}
	start := time.Now()
	res := run(t, ss...)
	t.Logf("DKG with %d parties: %s", len(parties), time.Since(start).Round(time.Millisecond))
	keys := map[string]*keygen.LocalPartySaveData{}
	for i, p := range parties {
		keys[p] = res[i].Key
	}
	return keys
}

func sign(t *testing.T, keys map[string]*keygen.LocalPartySaveData, signers []string, epoch int, hash []byte) []byte {
	n := &network{procs: map[string]*Session{}}
	var ss []*Session
	for _, p := range signers {
		s, err := NewSign(SignConfig{Session: "sign-" + fmt.Sprint(signers), Self: p, Signers: signers, Epoch: epoch, Threshold: 2, Key: *keys[p], Hash: hash}, n.send(t))
		if err != nil {
			t.Fatal(err)
		}
		n.register(s)
		ss = append(ss, s)
	}
	start := time.Now()
	res := run(t, ss...)
	t.Logf("sign %v: %s", signers, time.Since(start).Round(time.Millisecond))
	sig, err := EthSignature(res[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// recoverAddress recovers the signer's Ethereum address from r||s||v.
func recoverAddress(t *testing.T, hash, sig []byte) [20]byte {
	t.Helper()
	compact := make([]byte, 65)
	compact[0] = 27 + sig[64]
	copy(compact[1:], sig[:64])
	pub, _, err := secpecdsa.RecoverCompact(compact, hash)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	a, err := Address(pub.SerializeUncompressed())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDKGSignReshare(t *testing.T) {
	parties := []string{"user", "signer-a", "signer-b"}
	pp := preParams(t, "user", "signer-a", "signer-b", "user-new-device")

	keys := keygenAll(t, pp, parties)

	// Every party sees the same public key.
	pub, err := PublicKey(keys["user"])
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range parties {
		other, _ := PublicKey(keys[p])
		if !bytes.Equal(pub, other) {
			t.Fatalf("%s has a different public key", p)
		}
	}
	if _, err := secp256k1.ParsePubKey(pub); err != nil {
		t.Fatalf("public key not on curve: %v", err)
	}
	addr, _ := Address(pub)
	t.Logf("wallet address 0x%x", addr)

	// Every 2-of-3 combination signs for the same address.
	hash := sha256.Sum256([]byte("shardsign day 1"))
	for _, signers := range [][]string{{"user", "signer-a"}, {"user", "signer-b"}, {"signer-a", "signer-b"}} {
		sig := sign(t, keys, signers, 1, hash[:])
		if got := recoverAddress(t, hash[:], sig); got != addr {
			t.Fatalf("%v recovered 0x%x, want 0x%x", signers, got, addr)
		}
	}

	// Reshare to a new browser: A and B hand out epoch-2 shares to
	// user, signer-a and signer-b; the user's new device has new preparams.
	n := &network{procs: map[string]*Session{}}
	newKeys := map[string]*keygen.LocalPartySaveData{}
	var ss []*Session
	cfg := func(self string) ReshareConfig {
		return ReshareConfig{Session: "reshare-1", Self: self, Old: []string{"signer-a", "signer-b"}, New: parties, OldEpoch: 1, Threshold: 2, TotalOld: 3}
	}
	for _, p := range []string{"signer-a", "signer-b"} {
		c := cfg(p)
		c.OldKey, c.PreParams = keys[p], pp[p]
		s, err := NewReshare(c, n.send(t))
		if err != nil {
			t.Fatal(err)
		}
		n.register(s)
		ss = append(ss, s)
	}
	c := cfg("user")
	c.PreParams = pp["user-new-device"]
	s, err := NewReshare(c, n.send(t))
	if err != nil {
		t.Fatal(err)
	}
	n.register(s)
	ss = append(ss, s)
	start := time.Now()
	res := run(t, ss...)
	t.Logf("reshare: %s", time.Since(start).Round(time.Millisecond))
	newKeys["signer-a"], newKeys["signer-b"], newKeys["user"] = res[0].Key, res[1].Key, res[2].Key

	for _, p := range parties {
		k, _ := PublicKey(newKeys[p])
		if !bytes.Equal(pub, k) {
			t.Fatalf("after reshare %s has a different public key", p)
		}
	}
	hash2 := sha256.Sum256([]byte("after reshare"))
	sig := sign(t, newKeys, []string{"user", "signer-a"}, 2, hash2[:])
	if got := recoverAddress(t, hash2[:], sig); got != addr {
		t.Fatalf("after reshare recovered 0x%x, want 0x%x", got, addr)
	}

	// Interpolating two epoch-2 shares gives the wallet key; mixing the old
	// user share with an epoch-2 share does not.
	if !combinesTo(newKeys["user"], newKeys["signer-a"], pub) {
		t.Fatal("epoch-2 shares do not interpolate to the wallet key")
	}
	if combinesTo(keys["user"], newKeys["signer-a"], pub) {
		t.Fatal("old user share still combines with an epoch-2 share")
	}
}

// combinesTo reports whether two shares interpolate (Lagrange at 0) to the
// private key of pub. Test-only: it reconstructs the key in memory.
func combinesTo(a, b *keygen.LocalPartySaveData, pub []byte) bool {
	N := secp256k1.S256().N
	xa, xb := a.ShareID, b.ShareID
	if xa.Cmp(xb) == 0 {
		return false
	}
	lag := func(xi, xj *big.Int) *big.Int { // xj / (xj - xi)
		d := new(big.Int).Sub(xj, xi)
		d.Mod(d, N)
		d.ModInverse(d, N)
		return d.Mul(d, xj).Mod(d, N)
	}
	k := new(big.Int).Mul(lag(xa, xb), a.Xi)
	k.Add(k, new(big.Int).Mul(lag(xb, xa), b.Xi))
	k.Mod(k, N)
	var sc secp256k1.ModNScalar
	sc.SetByteSlice(k.Bytes())
	return bytes.Equal(secp256k1.NewPrivateKey(&sc).PubKey().SerializeUncompressed(), pub)
}

func TestFindSafePrime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	start := time.Now()
	p, err := FindSafePrime(ctx, SafePrimeBits, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("1024-bit safe prime in %s", time.Since(start).Round(time.Millisecond))
	if p.BitLen() != SafePrimeBits || !p.ProbablyPrime(30) || !new(big.Int).Rsh(p, 1).ProbablyPrime(30) {
		t.Fatal("not a 1024-bit safe prime")
	}
}
