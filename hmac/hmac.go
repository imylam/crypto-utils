package hmac

import (
	"crypto"
	"crypto/hmac"
	"errors"
)

const (
	ERR_INVALID_SIGNATURE = "invalid signature"
)

// Sign message and return signature.
func Sign(
	hasher crypto.Hash,
	key []byte,
	msg []byte,
) (signature []byte) {

	hash := hmac.New(hasher.HashFunc().New, key)
	hash.Write(msg)
	signature = hash.Sum(nil)

	return
}

// Verify message against signature.
func Verify(
	hasher crypto.Hash,
	key,
	msg,
	signature []byte,
) (err error) {

	hash := hmac.New(hasher.HashFunc().New, key)
	hash.Write(msg)
	expectedSignature := hash.Sum(nil)

	isSignatureValid := hmac.Equal(signature, expectedSignature)
	if !isSignatureValid {
		err = errors.New(ERR_INVALID_SIGNATURE)
		return
	}

	return
}
