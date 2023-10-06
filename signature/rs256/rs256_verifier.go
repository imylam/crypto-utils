package rs256

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	rsaUtils "github.com/imylam/crypto-utils/rsa"
	textcoder "github.com/imylam/text-coder"
)

type verifier struct {
	hash       crypto.Hash
	signScheme rsaUtils.SignScheme
	publicKey  *rsa.PublicKey
	msgCoder   textcoder.Coder
	sigCoder   textcoder.Coder
}

// NewVerifier creates verifier which verify signature of message
// with RSA public key using SHA256 and PKCS #1 v1.5 Sign Scheme.
//
// Implements signature.Verifier.
func NewVerifier(
	publicKey *rsa.PublicKey,
	msgCoder textcoder.Coder,
	sigCoder textcoder.Coder,
) *verifier {
	return &verifier{
		hash:       hash,
		signScheme: signScheme,
		publicKey:  publicKey,
		msgCoder:   msgCoder,
		sigCoder:   sigCoder,
	}
}

// Algo returns the algorithm used for verifying.
func (s *verifier) Algo() string {
	return ALGO
}

// Verify message against signature.
func (s *verifier) Verify(
	msg string,
	signature string,
) (err error) {

	msgBytes, err := s.msgCoder.Decode(msg)
	if err != nil {
		err = fmt.Errorf("failed to decode message: %w", err)
		return
	}

	sigBytes, err := s.sigCoder.Decode(signature)
	if err != nil {
		err = fmt.Errorf("failed to decode signature: %w", err)
		return
	}

	err = rsaUtils.Verify(s.hash, s.signScheme, s.publicKey, msgBytes, sigBytes)
	if err != nil {
		err = fmt.Errorf("failed to verify signature: %w", err)
	}

	return
}
