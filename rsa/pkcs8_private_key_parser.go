package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type Pkcs8PrivateKeyParser struct{}

// Marsal *rsa.PrivateKey to PKCS #8, ASN.1 DER form.
func (p *Pkcs8PrivateKeyParser) Marshal(privateKey *rsa.PrivateKey) (string, error) {
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key to PKCS #8 form: %w", err)
	}

	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)
	return string(privkeyPem), nil
}

// Parse an RSA private key pem in PKCS #8, ASN.1 DER form.
func (p *Pkcs8PrivateKeyParser) Parse(privatePem string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privatePem))
	if block == nil {
		return nil, errors.New("failed to decode PKCS #8 private key pem") //
	}

	result, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse to PKCS #8 private key pem: %w", err)
	}

	privateKey, ok := result.(*rsa.PrivateKey)
	if !ok {
		err = fmt.Errorf("failed to parse to PKCS #8 private key pem: %w", err)
	}

	return privateKey, err
}
