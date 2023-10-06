package rsa

import (
	"crypto/rand"
	"crypto/rsa"
)

const (
	keySize = 2048
)

// NewPkcs1KeysGenerator creates rsa keysGenerator which
// generates and return rsa key pair as PEM strings in
//
// - private key: PKCS #1, ASN.1 DER form.
// - public key: PKCS #1, ASN.1 DER form.
func NewPkcs1KeysGenerator() *keysGenerator {
	return NewKeysGenerator(
		WithPrivateKeyParser(&Pkcs1PrivateKeyParser{}),
		WithPublicKeyParser(&Pkcs1PublicKeyParser{}),
	)
}

// NewPkcs1PkixKeysGenerator creates rsa keysGenerator which
// generates and return rsa key pair as PEM strings in
//
// - private key: PKCS #1, ASN.1 DER form.
// - public key: PKIX, ASN.1 DER form.
func NewPkcs1PkixKeysGenerator() *keysGenerator {
	return NewKeysGenerator(
		WithPrivateKeyParser(&Pkcs1PrivateKeyParser{}),
		WithPublicKeyParser(&PkixPublicKeyParser{}),
	)
}

// NewPkcs8Pkcs1KeysGenerator creates rsa keysGenerator which
// generates and return rsa key pair as PEM strings in
//
// - private key: PKCS #8, ASN.1 DER form.
// - public key: PKCS #1, ASN.1 DER form.
func NewPkcs8Pkcs1KeysGenerator() *keysGenerator {
	return NewKeysGenerator(
		WithPrivateKeyParser(&Pkcs8PrivateKeyParser{}),
		WithPublicKeyParser(&Pkcs1PublicKeyParser{}),
	)
}

// NewPkcs8PkixKeysGenerator creates rsa keysGenerator which
// generates and return rsa key pair as PEM strings in
//
// - private key: PKCS #8, ASN.1 DER form.
// - public key: PKIX, ASN.1 DER form.
func NewPkcs8PkixKeysGenerator() *keysGenerator {
	return NewKeysGenerator(
		WithPrivateKeyParser(&Pkcs8PrivateKeyParser{}),
		WithPublicKeyParser(&PkixPublicKeyParser{}),
	)
}

type keysGenerator struct {
	priKeyParser PrivateKeyParser
	pubKeyParser PublicKeyParser
}

func NewKeysGenerator(
	options ...func(*keysGenerator),
) *keysGenerator {
	g := &keysGenerator{}
	for _, o := range options {
		o(g)
	}
	return g
}

func WithPrivateKeyParser(
	priKeyParser PrivateKeyParser,
) func(*keysGenerator) {
	return func(rkpg *keysGenerator) {
		rkpg.priKeyParser = priKeyParser
	}
}

func WithPublicKeyParser(
	pubKeyParser PublicKeyParser,
) func(*keysGenerator) {
	return func(g *keysGenerator) {
		g.pubKeyParser = pubKeyParser
	}
}

// GenKeyPair generates 2048 RSA private and public key pair as pem strings
func (g *keysGenerator) GenKeyPair() (privateKeyPem, publicKeyPem string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return
	}

	err = privateKey.Validate()
	if err != nil {
		return
	}

	privateKeyBytes, err := g.priKeyParser.Marshal(privateKey)
	if err != nil {
		return
	}

	publicKeyBytes, err := g.pubKeyParser.Marshal(&privateKey.PublicKey)
	if err != nil {
		return
	}

	privateKeyPem = string(privateKeyBytes)
	publicKeyPem = string(publicKeyBytes)

	return
}
