package rsa

import (
	"crypto"
	"crypto/rsa"
)

type SignScheme interface {
	SignScheme() string
	Sign(crypto.Hash, *rsa.PrivateKey, []byte) ([]byte, error)
	Verify(crypto.Hash, *rsa.PublicKey, []byte, []byte, *rsa.PSSOptions) error
}
