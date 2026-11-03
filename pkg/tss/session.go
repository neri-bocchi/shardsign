// Package tss wraps bnb-chain/tss-lib (GG18, ECDSA secp256k1) behind a
// transport-agnostic session API shared by the signers, the CLI and the
// browser (WASM) build.
//
// Parties are named ("user", "app", "signer-a", "signer-b") and every key
// version is an epoch: the tss-lib PartyID of a party is "<name>@<epoch>".
// A reshare moves a wallet from epoch v to v+1, so the same process can sit
// in the old and the new committee at once under two different ids.
//
// The session never touches the network: outgoing messages are handed to the
// Send callback as Envelopes with concrete recipient ids, and incoming
// Envelopes are passed to Deliver. Encryption and authentication of
// envelopes is the transport's job (see the security notes in tss-lib's
// README).
package tss

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	tsslib "github.com/bnb-chain/tss-lib/v2/tss"
)

// Envelope is one protocol message on the wire.
type Envelope struct {
	Session   string   `json:"session"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	Broadcast bool     `json:"broadcast"`
	Payload   []byte   `json:"payload"`
}

// Result is what a session produces when it ends. Key is set for keygen and
// for a reshare when this process is in the new committee; Sig for signing.
type Result struct {
	Key *keygen.LocalPartySaveData
	Sig *common.SignatureData
	Err error
}

// SendFunc delivers an outgoing envelope to the transport. It must not block
// for long; it is called from the session's own goroutine.
type SendFunc func(Envelope)

// PartyRef builds the tss-lib party id for a name at an epoch.
func PartyRef(name string, epoch int) string { return fmt.Sprintf("%s@%d", name, epoch) }

func partyID(name string, epoch int) *tsslib.PartyID {
	id := PartyRef(name, epoch)
	h := sha256.Sum256([]byte(id))
	return tsslib.NewPartyID(id, name, new(big.Int).SetBytes(h[:]))
}

func committee(names []string, epoch int) (tsslib.SortedPartyIDs, error) {
	if len(names) == 0 {
		return nil, errors.New("tss: empty committee")
	}
	seen := map[string]bool{}
	ids := make(tsslib.UnSortedPartyIDs, 0, len(names))
	for _, n := range names {
		if seen[n] {
			return nil, fmt.Errorf("tss: duplicate party %q", n)
		}
		seen[n] = true
		ids = append(ids, partyID(n, epoch))
	}
	return tsslib.SortPartyIDs(ids), nil
}

func find(ids tsslib.SortedPartyIDs, name string, epoch int) *tsslib.PartyID {
	want := PartyRef(name, epoch)
	for _, p := range ids {
		if p.Id == want {
			return p
		}
	}
	return nil
}

// local is one tss-lib party run by this process.
type local struct {
	party tsslib.Party
	out   chan tsslib.Message
	// route turns tss-lib routing into concrete recipient ids.
	route func(tsslib.Message) []string
}

// Session runs one keygen, signing or resharing round set.
type Session struct {
	id     string
	send   SendFunc
	known  map[string]*tsslib.PartyID
	locals map[string]*local // by party id

	once sync.Once
	done chan Result
}

func newSession(id string, send SendFunc) *Session {
	return &Session{
		id:     id,
		send:   send,
		known:  map[string]*tsslib.PartyID{},
		locals: map[string]*local{},
		done:   make(chan Result, 1),
	}
}

// Done yields the result once every local party has finished or one failed.
func (s *Session) Done() <-chan Result { return s.done }

func (s *Session) finish(r Result) {
	s.once.Do(func() { s.done <- r })
}

func (s *Session) add(id string, p tsslib.Party, out chan tsslib.Message, route func(tsslib.Message) []string) {
	s.locals[id] = &local{party: p, out: out, route: route}
}

// Start launches every local party and the goroutines that forward their
// outgoing messages.
func (s *Session) Start() {
	for id, l := range s.locals {
		go s.pump(id, l)
	}
	for _, l := range s.locals {
		go func(l *local) {
			if err := l.party.Start(); err != nil {
				s.finish(Result{Err: err})
			}
		}(l)
	}
}

func (s *Session) pump(from string, l *local) {
	for msg := range l.out {
		wire, routing, err := msg.WireBytes()
		if err != nil {
			s.finish(Result{Err: fmt.Errorf("tss: encode: %w", err)})
			return
		}
		env := Envelope{
			Session:   s.id,
			From:      from,
			To:        l.route(msg),
			Broadcast: routing.IsBroadcast,
			Payload:   wire,
		}
		// A process in both committees of a reshare sends to itself.
		var remote []string
		for _, to := range env.To {
			if _, mine := s.locals[to]; mine {
				self := env
				self.To = []string{to}
				go s.Deliver(self)
			} else {
				remote = append(remote, to)
			}
		}
		if len(remote) > 0 {
			env.To = remote
			s.send(env)
		}
	}
}

// Deliver hands an incoming envelope to the local parties it is addressed to.
func (s *Session) Deliver(env Envelope) error {
	if env.Session != s.id {
		return fmt.Errorf("tss: envelope for session %q, this is %q", env.Session, s.id)
	}
	from, ok := s.known[env.From]
	if !ok {
		return fmt.Errorf("tss: unknown sender %q", env.From)
	}
	delivered := false
	for _, to := range env.To {
		l, ok := s.locals[to]
		if !ok {
			continue
		}
		delivered = true
		if _, err := l.party.UpdateFromBytes(env.Payload, from, env.Broadcast); err != nil {
			s.finish(Result{Err: err})
			return err
		}
	}
	if !delivered {
		return fmt.Errorf("tss: envelope not addressed to this process (%v)", env.To)
	}
	return nil
}

// WaitingFor lists the parties some local party still expects a message from.
func (s *Session) WaitingFor() []string {
	var out []string
	for _, l := range s.locals {
		for _, p := range l.party.WaitingFor() {
			if !slices.Contains(out, p.Id) {
				out = append(out, p.Id)
			}
		}
	}
	return out
}

// routeAll resolves a keygen or signing message: nil To means everyone else.
func routeAll(ids tsslib.SortedPartyIDs, self string) func(tsslib.Message) []string {
	return func(m tsslib.Message) []string {
		var to []string
		if dest := m.GetTo(); dest != nil {
			for _, d := range dest {
				to = append(to, d.Id)
			}
			return to
		}
		for _, p := range ids {
			if p.Id != self {
				to = append(to, p.Id)
			}
		}
		return to
	}
}

// KeygenConfig describes one party's view of a DKG.
type KeygenConfig struct {
	Session   string
	Self      string   // this party's name
	Parties   []string // all party names, this one included
	Epoch     int      // key version, 1 for a new wallet
	Threshold int      // parties needed to sign (2 for 2-of-3)
	PreParams *keygen.LocalPreParams
}

// NewKeygen prepares a DKG party. PreParams are required: generating them
// inside the round would blow the round timeout.
func NewKeygen(c KeygenConfig, send SendFunc) (*Session, error) {
	if c.PreParams == nil {
		return nil, errors.New("tss: keygen needs pre-computed PreParams")
	}
	ids, err := committee(c.Parties, c.Epoch)
	if err != nil {
		return nil, err
	}
	self := find(ids, c.Self, c.Epoch)
	if self == nil {
		return nil, fmt.Errorf("tss: %q is not in the committee", c.Self)
	}
	if c.Threshold < 2 || c.Threshold > len(ids) {
		return nil, fmt.Errorf("tss: threshold %d out of range", c.Threshold)
	}
	s := newSession(c.Session, send)
	for _, p := range ids {
		s.known[p.Id] = p
	}
	// tss-lib's threshold t means t+1 parties sign.
	params := tsslib.NewParameters(tsslib.S256(), tsslib.NewPeerContext(ids), self, len(ids), c.Threshold-1)
	out := make(chan tsslib.Message, 64)
	end := make(chan *keygen.LocalPartySaveData, 1)
	s.add(self.Id, keygen.NewLocalParty(params, out, end, *c.PreParams), out, routeAll(ids, self.Id))
	go func() {
		key := <-end
		s.finish(Result{Key: key})
	}()
	return s, nil
}

// SignConfig describes one party's view of a signing round.
type SignConfig struct {
	Session   string
	Self      string
	Signers   []string // exactly Threshold names, this one included
	Epoch     int
	Threshold int
	Key       keygen.LocalPartySaveData
	Hash      []byte // 32-byte digest to sign
}

// NewSign prepares a signing party.
func NewSign(c SignConfig, send SendFunc) (*Session, error) {
	if len(c.Hash) != 32 {
		return nil, fmt.Errorf("tss: hash must be 32 bytes, got %d", len(c.Hash))
	}
	if len(c.Signers) != c.Threshold {
		return nil, fmt.Errorf("tss: %d signers for threshold %d", len(c.Signers), c.Threshold)
	}
	ids, err := committee(c.Signers, c.Epoch)
	if err != nil {
		return nil, err
	}
	self := find(ids, c.Self, c.Epoch)
	if self == nil {
		return nil, fmt.Errorf("tss: %q is not a signer", c.Self)
	}
	s := newSession(c.Session, send)
	for _, p := range ids {
		s.known[p.Id] = p
	}
	params := tsslib.NewParameters(tsslib.S256(), tsslib.NewPeerContext(ids), self, len(ids), c.Threshold-1)
	out := make(chan tsslib.Message, 64)
	end := make(chan *common.SignatureData, 1)
	msg := new(big.Int).SetBytes(c.Hash)
	s.add(self.Id, signing.NewLocalParty(msg, params, c.Key, out, end, len(c.Hash)), out, routeAll(ids, self.Id))
	go func() {
		sig := <-end
		s.finish(Result{Sig: sig})
	}()
	return s, nil
}

// ReshareConfig describes one process's view of a reshare from OldEpoch to
// OldEpoch+1. A process can be in the old committee, the new one, or both.
type ReshareConfig struct {
	Session   string
	Self      string
	Old       []string // the parties that contribute their current share (at least Threshold)
	New       []string // the parties that receive a share at OldEpoch+1
	OldEpoch  int
	Threshold int
	TotalOld  int                        // party count of the original keygen
	OldKey    *keygen.LocalPartySaveData // required when Self is in Old
	PreParams *keygen.LocalPreParams     // required when Self is in New
}

// NewReshare prepares a reshare. The result's Key is the share at the new
// epoch when Self is in New; the old share must be discarded afterwards.
func NewReshare(c ReshareConfig, send SendFunc) (*Session, error) {
	oldIDs, err := committee(c.Old, c.OldEpoch)
	if err != nil {
		return nil, err
	}
	newEpoch := c.OldEpoch + 1
	newIDs, err := committee(c.New, newEpoch)
	if err != nil {
		return nil, err
	}
	if len(oldIDs) < c.Threshold {
		return nil, fmt.Errorf("tss: %d old parties for threshold %d", len(oldIDs), c.Threshold)
	}
	oldSelf, newSelf := find(oldIDs, c.Self, c.OldEpoch), find(newIDs, c.Self, newEpoch)
	if oldSelf == nil && newSelf == nil {
		return nil, fmt.Errorf("tss: %q is in neither committee", c.Self)
	}
	s := newSession(c.Session, send)
	for _, p := range oldIDs {
		s.known[p.Id] = p
	}
	for _, p := range newIDs {
		s.known[p.Id] = p
	}
	oldCtx, newCtx := tsslib.NewPeerContext(oldIDs), tsslib.NewPeerContext(newIDs)
	route := func(m tsslib.Message) []string {
		var to []string
		dest := m.GetTo()
		if m.IsToOldCommittee() || m.IsToOldAndNewCommittees() {
			for _, d := range dest[:min(len(dest), len(oldIDs))] {
				to = append(to, oldIDs[d.Index].Id)
			}
		}
		if !m.IsToOldCommittee() || m.IsToOldAndNewCommittees() {
			for _, d := range dest {
				to = append(to, newIDs[d.Index].Id)
			}
		}
		return to
	}
	var wg sync.WaitGroup
	var newKey *keygen.LocalPartySaveData
	t := c.Threshold - 1
	if oldSelf != nil {
		if c.OldKey == nil {
			return nil, errors.New("tss: old committee member needs OldKey")
		}
		params := tsslib.NewReSharingParameters(tsslib.S256(), oldCtx, newCtx, oldSelf, c.TotalOld, t, len(newIDs), t)
		out := make(chan tsslib.Message, 64)
		end := make(chan *keygen.LocalPartySaveData, 1)
		s.add(oldSelf.Id, resharing.NewLocalParty(params, *c.OldKey, out, end), out, route)
		wg.Add(1)
		go func() { <-end; wg.Done() }()
	}
	if newSelf != nil {
		if c.PreParams == nil {
			return nil, errors.New("tss: new committee member needs PreParams")
		}
		params := tsslib.NewReSharingParameters(tsslib.S256(), oldCtx, newCtx, newSelf, c.TotalOld, t, len(newIDs), t)
		save := keygen.NewLocalPartySaveData(len(newIDs))
		save.LocalPreParams = *c.PreParams
		out := make(chan tsslib.Message, 64)
		end := make(chan *keygen.LocalPartySaveData, 1)
		s.add(newSelf.Id, resharing.NewLocalParty(params, save, out, end), out, route)
		wg.Add(1)
		go func() { newKey = <-end; wg.Done() }()
	}
	go func() {
		wg.Wait()
		s.finish(Result{Key: newKey})
	}()
	return s, nil
}
