package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type Pkcs1PrivateKeyParser struct{}

// Marsal *rsa.PrivateKey to PKCS #1, ASN.1 DER form.
func (p *Pkcs1PrivateKeyParser) Marshal(privateKey *rsa.PrivateKey) (string, error) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)
	return string(privkeyPem), nil
}

// Parse an RSA private key pem in PKCS #1, ASN.1 DER form.
func (p *Pkcs1PrivateKeyParser) Parse(privatePem string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privatePem))
	if block == nil {
		return nil, errors.New("failed to decode PKCS #1 private key pem") //
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS #1 private key pem: %w", err)
	}

	return privateKey, nil
}
