package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

const (
	PSS = "PSS"
)

type pssSignScheme struct {
	signScheme string
}

func NewPssSignScheme() *pssSignScheme {
	return &pssSignScheme{signScheme: PSS}
}

func (s *pssSignScheme) SignScheme() string {
	return s.signScheme
}

func (s *pssSignScheme) Sign(
	hash crypto.Hash,
	privateKey *rsa.PrivateKey,
	hashedMsgBytes []byte,
) (signatureByte []byte, err error) {
	rng := rand.Reader

	signatureByte, err = rsa.SignPSS(rng, privateKey, hash, hashedMsgBytes, nil)
	if err != nil {
		return
	}

	return
}

func (s *pssSignScheme) Verify(
	hash crypto.Hash,
	publicKey *rsa.PublicKey,
	hashedMessageBytes,
	signatureBytes []byte,
	opts *rsa.PSSOptions,
) error {
	return rsa.VerifyPSS(publicKey, hash, hashedMessageBytes, signatureBytes, opts)
}
