package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type Pkcs1PublicKeyParser struct{}

// Marshal *rsa.PublicKey to an RSA public key to PKCS #1, ASN.1 DER form.
func (p *Pkcs1PublicKeyParser) Marshal(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return string(publicKeyPem), nil
}

// Parse an RSA public key pem in PKCS #1, ASN.1 DER form.
func (p *Pkcs1PublicKeyParser) Parse(publicKeyPem string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return nil, errors.New("failed to decode Pkcs1 public key pem")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS #1 publi key pem: %w", err)
	}

	return publicKey, nil
}
