package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

const (
	PKCS1v15 = "PKCS1v15"
)

type pKCS1v15SignScheme struct {
	signScheme string
}

func NewPKCS1v15SignScheme() *pKCS1v15SignScheme {
	return &pKCS1v15SignScheme{signScheme: PKCS1v15}
}

func (s *pKCS1v15SignScheme) SignScheme() string {
	return s.signScheme
}

func (s *pKCS1v15SignScheme) Sign(
	hash crypto.Hash,
	privateKey *rsa.PrivateKey,
	hashedMsgBytes []byte,
) (signatureByte []byte, err error) {
	rng := rand.Reader

	signatureByte, err = rsa.SignPKCS1v15(rng, privateKey, hash, hashedMsgBytes)
	if err != nil {
		return
	}

	return
}

func (s *pKCS1v15SignScheme) Verify(
	hash crypto.Hash,
	publicKey *rsa.PublicKey,
	hashedMessageBytes,
	signatureBytes []byte,
	opts *rsa.PSSOptions,
) error {
	return rsa.VerifyPKCS1v15(publicKey, hash, hashedMessageBytes, signatureBytes)
}
