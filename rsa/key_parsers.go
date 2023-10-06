package rsa

import (
	"crypto/rsa"
)

type PrivateKeyParser interface {
	Marshal(*rsa.PrivateKey) (string, error)
	Parse(string) (*rsa.PrivateKey, error)
}

type PublicKeyParser interface {
	Marshal(*rsa.PublicKey) (string, error)
	Parse(publicKeyPem string) (*rsa.PublicKey, error)
}
