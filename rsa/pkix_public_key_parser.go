package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type PkixPublicKeyParser struct{}

// Marshal *rsa.PublicKey to an RSA public key to PKIX, ASN.1 DER form.
func (p *PkixPublicKeyParser) Marshal(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key to PKCS #8 form: %w", err)
	}

	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return string(publicKeyPem), nil
}

// Parse an RSA public key pem in PKIX, ASN.1 DER form.
func (p *PkixPublicKeyParser) Parse(publicKeyPem string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return nil, errors.New("failed to decode PKIX public key pem")
	}

	result, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key pem: %w", err)
	}

	publicKey, ok := result.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("pem given is not an rsa public key")
	}

	return publicKey, nil
}
