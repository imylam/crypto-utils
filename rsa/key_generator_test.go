package rsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenKeyPair(t *testing.T) {
	pkcs1KeysGenerator := NewPkcs1KeysGenerator()
	pkcs1PkixKeysGenerator := NewPkcs1PkixKeysGenerator()
	pkcs8Pkcs1Generator := NewPkcs8Pkcs1KeysGenerator()
	pkcs8PkixGenerator := NewPkcs8PkixKeysGenerator()

	pkcs1PrivateKeyParser := &Pkcs1PrivateKeyParser{}
	pkcs1PublicKeyParser := &Pkcs1PublicKeyParser{}
	pkcs8PrivateKeyParser := &Pkcs8PrivateKeyParser{}
	pkixPublicKeyParser := &PkixPublicKeyParser{}

	testCases := []struct {
		name         string
		keyGen       *keysGenerator
		priKeyParser PrivateKeyParser
		pubKeyParser PublicKeyParser
	}{
		{
			name:         "GIVEN_pkcs1KeysGenerator_WHEN_generate_key_pairs_THEN_private_key_pem_in_PKCS_#1_and_public_key_in_PKCS_#1_form",
			keyGen:       pkcs1KeysGenerator,
			priKeyParser: pkcs1PrivateKeyParser,
			pubKeyParser: pkcs1PublicKeyParser,
		},
		{
			name:         "GIVEN_pkcs1PkixKeysGenerator_WHEN_generate_key_pairs_THEN_private_key_pem_in_PKCS_#1_and_public_key_in_PKIX_form",
			keyGen:       pkcs1PkixKeysGenerator,
			priKeyParser: pkcs1PrivateKeyParser,
			pubKeyParser: pkixPublicKeyParser,
		},
		{
			name:         "GIVEN_pkcs8Pkcs1Generator_WHEN_generate_key_pairs_THEN_private_key_pem_in_PKCS_#8_and_public_key_in_PKCS_#1_form",
			keyGen:       pkcs8Pkcs1Generator,
			priKeyParser: pkcs8PrivateKeyParser,
			pubKeyParser: pkcs1PublicKeyParser,
		},
		{
			name:         "GIVEN_pkcs8PkixGenerator_WHEN_generate_key_pairs_THEN_private_key_pem_in_PKCS_#8_and_public_key_in_PKIX_form",
			keyGen:       pkcs8PkixGenerator,
			priKeyParser: pkcs8PrivateKeyParser,
			pubKeyParser: pkixPublicKeyParser,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			priKey, pubKey, err := tc.keyGen.GenKeyPair()
			assert.NoError(t, err)

			tc.priKeyParser.Parse(priKey)
			assert.NoError(t, err)

			tc.pubKeyParser.Parse(pubKey)
			assert.NoError(t, err)
		})
	}
}
