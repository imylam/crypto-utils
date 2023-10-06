package hs512

import (
	"crypto"
	"fmt"

	"github.com/imylam/crypto-utils/hmac"
	textcoder "github.com/imylam/text-coder"
)

const (
	ALGO                  = "HS512"
	ERR_INVALID_SIGNATURE = "invalid signature"
)

var hasher = crypto.SHA512

type HS512 struct {
	key      []byte
	msgCoder textcoder.Coder
	sigCoder textcoder.Coder
}

// NewHS512 creates HS512 which sign and verify message
// with secret using HMAC with SHA-512.
//
// Implements signature.Signer and signature.Verifier.
func NewHS512(
	key []byte,
	msgCoder textcoder.Coder,
	sigCoder textcoder.Coder,
) *HS512 {
	hs512 := &HS512{
		key:      key,
		msgCoder: msgCoder,
		sigCoder: sigCoder,
	}
	return hs512
}

// Algo returns the algorithm used for signing/verifying.
func (s *HS512) Algo() (algo string) {
	return ALGO
}

// Sign message and return signature.
func (s *HS512) Sign(msg string) (signature string, err error) {
	msgBytes, err := s.msgCoder.Decode(msg)
	if err != nil {
		err = fmt.Errorf("failed to decode message: %w", err)
		return
	}

	signatureBytes := hmac.Sign(hasher, s.key, msgBytes)
	signature = s.sigCoder.Encode(signatureBytes)

	return
}

// Verify message against signature.
func (s *HS512) Verify(msg, signature string) (err error) {
	messageBytes, err := s.msgCoder.Decode(msg)
	if err != nil {
		err = fmt.Errorf("failed to decode message: %w", err)
		return
	}

	signatureBytes, err := s.sigCoder.Decode(signature)
	if err != nil {
		err = fmt.Errorf("failed to decode signature: %w", err)
		return
	}

	err = hmac.Verify(hasher, s.key, messageBytes, signatureBytes)
	if err != nil {
		err = fmt.Errorf("failed to verify signature: %w", err)
		return
	}
	return
}
