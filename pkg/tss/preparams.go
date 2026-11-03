package tss

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"runtime"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

// SafePrimeBits is the size of every safe prime in the pre-parameters: the
// two Paillier primes (2048-bit modulus) and the two NTilde primes.
const SafePrimeBits = 1024

// Why not keygen.GeneratePreParams: its concurrent safe-prime search
// (common.GetRandomSafePrimesConcurrent) can leave a generator goroutine
// blocked forever on a channel send once enough primes are found. Natively
// the race is rare; under js/wasm, where goroutines are never preempted, it
// deadlocks every time. FindSafePrime is a plain sequential search, and the
// browser gets parallelism by running it in several Web Workers.

var smallPrimes = func() []uint64 {
	const limit = 2000
	sieve := make([]bool, limit)
	var ps []uint64
	for i := 2; i < limit; i++ {
		if !sieve[i] {
			ps = append(ps, uint64(i))
			for j := i * i; j < limit; j += i {
				sieve[j] = true
			}
		}
	}
	return ps
}()

// FindSafePrime returns a safe prime p = 2q+1 of exactly bits bits (top two
// bits set), with q prime.
func FindSafePrime(ctx context.Context, bits int, rnd io.Reader) (*big.Int, error) {
	if bits < 64 {
		return nil, errors.New("tss: safe prime too small")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	qBits := bits - 1
	buf := make([]byte, (qBits+7)/8)
	top := uint(qBits % 8)
	if top == 0 {
		top = 8
	}
	two := big.NewInt(2)
	res := make([]uint64, len(smallPrimes))
	q, p, d := new(big.Int), new(big.Int), new(big.Int)
	mod, m := new(big.Int), new(big.Int)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(rnd, buf); err != nil {
			return nil, err
		}
		buf[0] &= uint8(1<<top - 1)
		if top >= 2 {
			buf[0] |= 3 << (top - 2)
		} else {
			buf[0] |= 1
			buf[1] |= 0x80
		}
		buf[len(buf)-1] |= 1
		q.SetBytes(buf)
		for i, sp := range smallPrimes {
			res[i] = mod.Mod(q, m.SetUint64(sp)).Uint64()
		}
		// Walk q, q+2, q+4… until neither q nor 2q+1 has a small factor.
	delta:
		for delta := uint64(0); delta < 1<<16; delta += 2 {
			if delta%512 == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			for i, sp := range smallPrimes {
				r := (res[i] + delta) % sp
				if r == 0 || (2*r+1)%sp == 0 {
					continue delta
				}
			}
			d.SetUint64(delta)
			c := new(big.Int).Add(q, d)
			if c.BitLen() != qBits || !c.ProbablyPrime(20) {
				continue
			}
			p.Mul(c, two).Add(p, big.NewInt(1))
			// Pocklington: with q prime, 2^(p-1) = 1 mod p proves p prime.
			if new(big.Int).Exp(two, new(big.Int).Sub(p, big.NewInt(1)), p).Cmp(big.NewInt(1)) != 0 {
				continue
			}
			return new(big.Int).Set(p), nil
		}
	}
}

// PreParamsFromSafePrimes builds tss-lib pre-parameters from four distinct
// 1024-bit safe primes, exactly as keygen.GeneratePreParams assembles them:
// two become the Paillier key, two the NTilde modulus for the range proofs.
func PreParamsFromSafePrimes(primes []*big.Int, rnd io.Reader) (*keygen.LocalPreParams, error) {
	if len(primes) != 4 {
		return nil, errors.New("tss: need exactly 4 safe primes")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	// The Paillier pair must satisfy |P-Q| >= 2^1020 (tss-lib KS-BTL-F-03).
	order := [][4]int{{0, 1, 2, 3}, {0, 2, 1, 3}, {0, 3, 1, 2}, {1, 2, 0, 3}, {1, 3, 0, 2}, {2, 3, 0, 1}}
	for _, o := range order {
		P, Q := primes[o[0]], primes[o[1]]
		if new(big.Int).Sub(P, Q).BitLen() < SafePrimeBits-3 {
			continue
		}
		return assemble(P, Q, primes[o[2]], primes[o[3]], rnd)
	}
	return nil, errors.New("tss: no pair of primes is far enough apart for Paillier; find another prime")
}

func assemble(P, Q, NP, NQ *big.Int, rnd io.Reader) (*keygen.LocalPreParams, error) {
	one := big.NewInt(1)
	for _, x := range []*big.Int{P, Q, NP, NQ} {
		if x.BitLen() != SafePrimeBits || !x.ProbablyPrime(30) || !new(big.Int).Rsh(x, 1).ProbablyPrime(30) {
			return nil, errors.New("tss: not a safe prime of the right size")
		}
	}
	// Paillier
	pm1, qm1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(pm1, qm1)
	gcd := new(big.Int).GCD(nil, nil, pm1, qm1)
	sk := &paillier.PrivateKey{
		PublicKey: paillier.PublicKey{N: new(big.Int).Mul(P, Q)},
		LambdaN:   new(big.Int).Div(phiN, gcd),
		PhiN:      phiN,
		P:         P,
		Q:         Q,
	}
	// NTilde, h1, h2 (same as keygen.GeneratePreParams)
	NTilde := new(big.Int).Mul(NP, NQ)
	modNTilde := common.ModInt(NTilde)
	p, q := new(big.Int).Rsh(NP, 1), new(big.Int).Rsh(NQ, 1)
	modPQ := common.ModInt(new(big.Int).Mul(p, q))
	f1 := common.GetRandomPositiveRelativelyPrimeInt(rnd, NTilde)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(rnd, NTilde)
	beta := modPQ.ModInverse(alpha)
	h1 := modNTilde.Mul(f1, f1)
	h2 := modNTilde.Exp(h1, alpha)
	pp := &keygen.LocalPreParams{PaillierSK: sk, NTildei: NTilde, H1i: h1, H2i: h2, Alpha: alpha, Beta: beta, P: p, Q: q}
	if !pp.ValidateWithProof() {
		return nil, errors.New("tss: assembled pre-parameters do not validate")
	}
	return pp, nil
}

// PreParamsFromAny tries every set of four primes that includes the newest
// one (the last element) and returns the first that assembles.
func PreParamsFromAny(primes []*big.Int, rnd io.Reader) (*keygen.LocalPreParams, error) {
	n := len(primes)
	if n < 4 {
		return nil, errors.New("tss: need at least 4 safe primes")
	}
	for i := 0; i < n-3; i++ {
		for j := i + 1; j < n-2; j++ {
			for k := j + 1; k < n-1; k++ {
				set := []*big.Int{primes[i], primes[j], primes[k], primes[n-1]}
				if pp, err := PreParamsFromSafePrimes(set, rnd); err == nil {
					return pp, nil
				}
			}
		}
	}
	return nil, errors.New("tss: no usable set of primes yet; find another one")
}

// GeneratePreParams is the native replacement for keygen.GeneratePreParams:
// workers goroutines search for safe primes until four usable ones exist.
func GeneratePreParams(ctx context.Context, workers int) (*keygen.LocalPreParams, error) {
	if workers < 1 {
		workers = runtime.NumCPU()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	found := make(chan *big.Int, workers)
	errs := make(chan error, workers)
	for range workers {
		go func() {
			for {
				p, err := FindSafePrime(ctx, SafePrimeBits, nil)
				if err != nil {
					errs <- err
					return
				}
				select {
				case found <- p:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	var primes []*big.Int
	for {
		select {
		case p := <-found:
			primes = append(primes, p)
			if len(primes) < 4 {
				continue
			}
			if pp, err := PreParamsFromAny(primes, nil); err == nil {
				return pp, nil
			}
		case err := <-errs:
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
