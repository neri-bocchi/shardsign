package tss

import (
	"errors"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"golang.org/x/crypto/sha3"
)

// PublicKey returns the wallet's uncompressed secp256k1 public key (65 bytes,
// 0x04 prefix) from any party's save data.
func PublicKey(k *keygen.LocalPartySaveData) ([]byte, error) {
	if k == nil || k.ECDSAPub == nil {
		return nil, errors.New("tss: save data has no public key")
	}
	out := make([]byte, 65)
	out[0] = 4
	k.ECDSAPub.X().FillBytes(out[1:33])
	k.ECDSAPub.Y().FillBytes(out[33:65])
	return out, nil
}

// Address is the Ethereum address of an uncompressed public key.
func Address(pub []byte) ([20]byte, error) {
	var a [20]byte
	if len(pub) != 65 || pub[0] != 4 {
		return a, errors.New("tss: want a 65-byte uncompressed public key")
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(pub[1:])
	copy(a[:], h.Sum(nil)[12:])
	return a, nil
}

// EthSignature returns the 65-byte r||s||v signature (v = 0 or 1, low-S) that
// tss-lib produces; add 27 or the EIP-155 offset when building a transaction.
func EthSignature(sig *common.SignatureData) ([]byte, error) {
	if sig == nil || len(sig.SignatureRecovery) == 0 {
		return nil, errors.New("tss: empty signature")
	}
	out := make([]byte, 65)
	new32 := func(b []byte, dst []byte) { copy(dst[32-len(b):], b) }
	new32(sig.R, out[0:32])
	new32(sig.S, out[32:64])
	out[64] = sig.SignatureRecovery[0] & 1
	return out, nil
}
