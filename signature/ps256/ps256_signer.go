package ps256

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	rsaUtils "github.com/imylam/crypto-utils/rsa"
	textcoder "github.com/imylam/text-coder"
)

type signer struct {
	hash       crypto.Hash
	signScheme rsaUtils.SignScheme
	privateKey *rsa.PrivateKey
	msgCoder   textcoder.Coder
	sigCoder   textcoder.Coder
}

// NewSigner creates signer which sign message
// with RSA private key using SHA256 and PSS Sign Scheme.
//
// Implements signature.Signer.
func NewSigner(privateKey *rsa.PrivateKey, msgCoder textcoder.Coder, sigCoder textcoder.Coder) signer {
	return signer{
		hash:       hash,
		signScheme: signScheme,
		privateKey: privateKey,
		msgCoder:   msgCoder,
		sigCoder:   sigCoder,
	}
}

// Algo returns the algorithm used for signing.
func (s signer) Algo() string {
	return ALGO
}

// Sign message and return signature.
func (s signer) Sign(msg string) (signature string, err error) {
	msgBytes, err := s.msgCoder.Decode(msg)
	if err != nil {
		err = fmt.Errorf("failed to decode message: %w", err)
		return
	}

	sigBytes, err := rsaUtils.Sign(s.hash, s.signScheme, s.privateKey, msgBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %w", err)
	}

	signature = s.sigCoder.Encode(sigBytes)

	return
}
