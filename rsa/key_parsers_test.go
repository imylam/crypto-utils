package rsa

import (
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	pkcs1PriKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtJ/a8+raUXOeqvgKH1sln255Rf2fWPNzUc0FtN63u9FmrRpQ
uTTcBvlF7at4dkBh3h0hTj8ZkJp5eyL6vzb1jKe5FvtlPSF7exhjPPIM3sYT59ot
o4H60PCeeC6Fl44P94sqWoWOEMglg4R//d5TwRnHiS5+rJ+29odea5X96J2QeoQA
GDVHHadswzpoZW+k60yZyPUJl4gTGmEnqz/wmqx1HW24JtMOlCfkkacSzAz2wqgA
qX5gvVuSGJbhvJjHVNqclq8F3n2MC6M4UOk9q9+td/1o+mT0+MVmzeBIt/UoI6BU
40zsaGiLkes0hp3HCfHmbIsJx+uVALIyViDnQwIDAQABAoIBAG3gTHZS6GniFqRU
bPv0G2fn8TgFd7jJp94cBRuo3EYRtQ8aUf7ITAyl+McCpy3wLljKiacqtWeEwN+K
QNSvHyJoKSz00voj8xTHmh7J89BU2GkTDO5JNIWDyjK7wiKWldn1O1eDpQ9KYZ+m
q6GIbJSsFPi7Yu2p3sgLQwHZZXLp2PSKmh1wNlpTrisaZqIwGDNkggfmme/AA5b/
rRshKzS0XnAms9yUXqxFqrOs7beKc5oW6FIMDbpEp3BFWoHzwpNCO7LwAKw79xTj
ceDYJOXauQy+G3TTo0OwyCBfHRgM3Ea1b8cJXvtFtPiJFxMuy3T29w1CrOyyqlUt
HdF+kKECgYEA0aibbYrraTNNOU6yGGtMMPAdCPS7kzC1h/ChKPcSZQFS/Q3q1OFy
jzDBe9pl4ZWdHbIYkki9EQQOfuRVEDdYaj/9u6+jSo2d8FI9nMTLnYKm8yX0DCGj
AmXNDcNKY2V5IZtB/ofH7q5+wJVJxPPPAQCHDlZ91sofp2nXe7dNh/MCgYEA3Ixe
O6u3m+0ZuJWD6lyjKIvkj8eaOhVpsZAL/ApK+odXH9Cm2ormQLLtIRBvzwiZqApm
IFvcEhVNwe+dO/V4H4uqWwkX/72ExRQiNeos74+gFH+5Nck67NtjyoFxdUMcr4UM
7kVR5xmELg3LY5bnxjLoz8aEuZsvwRPWLg9ex3ECgYBJP+A10HBZC+xyFjWQ5IP1
IR7zzxVt4nm56e9UcaYClgjZkrA1+iJdNsqSrAYmX3BKPLvq9/Debg1mdf3mMX/5
dyv+E+o4FOxWV1VhXTxKZqhPkTYHuwTJxKl0ooNt4LkGbckL1YKbuGlefYoNfqUX
E4kcEEnc7jdK9Wasuakj0wKBgQC+s7EXr5eIADBpZv81uvxppuzvVgyJhNJrcr6q
JMxIbJZtMCHWfpwx/YUFPg0v26PhpXxBJqzYBgvCUcqHee1weXfIV8iknd8b+hjK
vb41Nt+YWghv9Zw6CknzZJISbwFy030m2lHDnlCo8cyYRHgM7SBZ6LIDO6jDLr/X
+/pcQQKBgDwor5ZUJfTcqMdDjEYmlsFJSSuR5CQ0WGgINg4D/lUfiPwj3hTd+Dsz
wbnOZrZMz5Gr18bJSmW6AK3RDw7HDhDXa2NTilXxJizQggLwhyMF4Iian9G5MdZt
1zhRkTep/J+HV34L77gwAviEl1U9OamkSs+gN/c1WE37LOdEh/GE
-----END RSA PRIVATE KEY-----`
	pkcs1PubKeyPem = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAtJ/a8+raUXOeqvgKH1sln255Rf2fWPNzUc0FtN63u9FmrRpQuTTc
BvlF7at4dkBh3h0hTj8ZkJp5eyL6vzb1jKe5FvtlPSF7exhjPPIM3sYT59oto4H6
0PCeeC6Fl44P94sqWoWOEMglg4R//d5TwRnHiS5+rJ+29odea5X96J2QeoQAGDVH
HadswzpoZW+k60yZyPUJl4gTGmEnqz/wmqx1HW24JtMOlCfkkacSzAz2wqgAqX5g
vVuSGJbhvJjHVNqclq8F3n2MC6M4UOk9q9+td/1o+mT0+MVmzeBIt/UoI6BU40zs
aGiLkes0hp3HCfHmbIsJx+uVALIyViDnQwIDAQAB
-----END RSA PUBLIC KEY-----`
	pkcs8PriKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQD1SDWj+wDz0sZI
hqDJBDXqzhGbwIE9cvD/Cim+OaDq1S05PdgeycYgSqCm3JgcISwHdoyjRYyla0ja
L855g4VBTE203yq06O31DxoxpLcaq5yV8KQ5KIa2jIZOaH3YWTDZPHHeztMowlth
eRK+wvl8nFacu4gokpj0/oTcSBFPHtnMqB2DJGM1sx2GDQUH9/wrtj5yJDWtzGbH
tqnbVDWNoZyFNBAl4zydJtTdsOyKTJIZ6r4siqkdc83Y5m2ObqkVUQQ7kgEHk1/S
bGpNdxIB8UOrrmQqy9vLSbeqQmS/TrwlUE9ADluUh9CoixxcgS/4Np6DF5YSxhyl
DpNQjGDnAgMBAAECggEAY4kpE2FRkqBvDJFtgAVwZ9e195GYILqbJ7QVGnfCYGmf
z4HUSTIyb3o5VV1hcNDZUDIAgmU/3QT7bGdID7GaitQPGJ4Tc5Sus+qsA4dHMtB/
W61qxzM177B49CqdHwWauB06TGN79ydf898xBy6SFcpPr4y+hVBwN8NtYQLx2zvr
XWuTegTZw3cF5JLoPrDneEOfYGC4w64FyYPSKpeT//iclbAfOljAvPu/7B5Fkmyz
OwahAycI+HbAlOxfBONVDqR4JPl71zWiLNJ6lPcnGqEF3y4jdSerWFYxI9FEFUkj
idEO5eQqmNoaugG6aJ0j2MfCc0rrf/q+MULRFatHYQKBgQD4Jbpwa9w2kX72HQYB
z45JGwu7prrIiz5QtoQ90RWWLT6YBq5ajtu4AK26Nwy0zNZ8VmNz04jzRydRE6R7
4fvtp+iUP/5QczYE9Z9+PFz1XYVKphQcJR93GQhrOK59HDsxuTV+HPVpycdi2Fa9
IDopG4FlnHJ+/yysMDHyda//sQKBgQD9C0TgvNWISUoY9MIpFTC93RvoOOylESnC
yeH2Y3+GK7LR/njg/Q3cUx6GjHAgIXiv9B8IQjFi1BPvWbLWN9i87eOVTr0GaCEV
asaYE6o/vYPjYYeU7ha8MgYQ6FZ7rXXj0XMli/1rYE1TrZD6f1hguGwStHsdHOo1
UyH4Q0ToFwKBgHTliQuWtBl8tvuHtqG5vgSQWhmfNJRui/+Hy4o3adziGX+SfiYo
8DahEzYK4tB1QoE2TQluWDCKj2nxP+YgEgblt3nHH62UaJkzgFv+Yagw0y7UR9ru
XgFD6KRiAkjruLL21c1AJRgdtvDIiyvy95MP4wgUCBfta4T9+zmF2VAxAoGAFAMT
JG7quEeLi6O3w0YAv9M/xMLTvE46LkSHEVRXHoZQMxlb9/crZHRSYrOynmfnQosc
9Ss++qDpHrHKWfS6uF5b9E/w1RPhIe9620Ya3cWgK5hn/5hAxgtyvV2SkV9rhmPn
Jl4G4boRA4AjihwOIkATk/sgDXJe926mrhqr1WsCgYB8cqUGHkLcFBz8FhBARpx9
ZxOpeUt2f2gqFRRcXNo3OKSP2gRZpARt9SiGJJeZgI2PBk00YLGMf861vSPW0sRq
BLF8O0iANAT8YW1YpKppEV2zdnyvFjCfooAA0+ajspFqjEZSotDj+L6qseQqI4go
1YGpowhtyi7VD24auZ7XwQ==
-----END RSA PRIVATE KEY-----`
	pkixPubKeyPem = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9Ug1o/sA89LGSIagyQQ1
6s4Rm8CBPXLw/wopvjmg6tUtOT3YHsnGIEqgptyYHCEsB3aMo0WMpWtI2i/OeYOF
QUxNtN8qtOjt9Q8aMaS3GquclfCkOSiGtoyGTmh92Fkw2Txx3s7TKMJbYXkSvsL5
fJxWnLuIKJKY9P6E3EgRTx7ZzKgdgyRjNbMdhg0FB/f8K7Y+ciQ1rcxmx7ap21Q1
jaGchTQQJeM8nSbU3bDsikySGeq+LIqpHXPN2OZtjm6pFVEEO5IBB5Nf0mxqTXcS
AfFDq65kKsvby0m3qkJkv068JVBPQA5blIfQqIscXIEv+DaegxeWEsYcpQ6TUIxg
5wIDAQAB
-----END RSA PUBLIC KEY-----`
)

var (
	pkcs1PriKeyParser = &Pkcs1PrivateKeyParser{}
	pkcs1PubKeyParser = &Pkcs1PublicKeyParser{}
	pkcs8PriKeyParser = &Pkcs8PrivateKeyParser{}
	pkixPubKeyParser  = &PkixPublicKeyParser{}
)

func TestSuccessPrivateKeyParsing(t *testing.T) {

	testCases := []struct {
		name         string
		priKeyParser PrivateKeyParser
		priKeyPem    string
	}{
		{
			name:         "GIVEN_pkcs1PriKeyParser_WHEN_parse_pkcs1PrivateKeyPem_return_rsa_private_key_without_error",
			priKeyParser: pkcs1PriKeyParser,
			priKeyPem:    pkcs1PriKeyPem,
		},
		{
			name:         "GIVEN_pkcs8PriKeyParser_WHEN_parse_pkcs8PrivateKeyPem_return_rsa_private_key_without_error",
			priKeyParser: pkcs8PriKeyParser,
			priKeyPem:    pkcs8PriKeyPem,
		},
	}

	for _, tc := range testCases {
		key, err := tc.priKeyParser.Parse(tc.priKeyPem)

		assert.NoError(t, err)
		assert.IsType(t, &rsa.PrivateKey{}, key)
	}
}

func TestFailedPrivateKeyParsing(t *testing.T) {

	testCases := []struct {
		name         string
		priKeyParser PrivateKeyParser
		keyPem       string
	}{
		{
			name:         "GIVEN_pkcs1PriKeyParser_WHEN_parse_pkcs8PrivateKeyPem_return_error",
			priKeyParser: pkcs1PriKeyParser,
			keyPem:       pkcs8PriKeyPem,
		},
		{
			name:         "GIVEN_pkcs1PriKeyParser_WHEN_parse_pkcs1PublicKeyPem_return_error",
			priKeyParser: pkcs1PriKeyParser,
			keyPem:       pkcs1PubKeyPem,
		},
		{
			name:         "GIVEN_pkcs1PriKeyParser_WHEN_parse_pkixPublicKeyPem_return_error",
			priKeyParser: pkcs1PriKeyParser,
			keyPem:       pkixPubKeyPem,
		},
		{
			name:         "GIVEN_pkcs8PriKeyParser_WHEN_parse_pkcs1PrivateKeyPem_return_error",
			priKeyParser: pkcs8PriKeyParser,
			keyPem:       pkcs1PriKeyPem,
		},
		{
			name:         "GIVEN_pkcs8PriKeyParser_WHEN_parse_pkcs1PublicKeyPem_return_error",
			priKeyParser: pkcs8PriKeyParser,
			keyPem:       pkcs1PubKeyPem,
		},
		{
			name:         "GIVEN_pkcs8PriKeyParser_WHEN_parse_pkixPublicKeyPem_return_error",
			priKeyParser: pkcs8PriKeyParser,
			keyPem:       pkixPubKeyPem,
		},
	}

	for _, tc := range testCases {
		key, err := tc.priKeyParser.Parse(tc.keyPem)

		expectedErrMsg := "failed to parse"
		assert.Nil(t, key)
		assert.ErrorContainsf(
			t,
			err,
			expectedErrMsg,
			"expected error containing %q, got %s", expectedErrMsg, err,
		)
	}
}

func TestFailedNonPrivateKeyPemParsing(t *testing.T) {

	testCases := []struct {
		name         string
		priKeyParser PrivateKeyParser
		keyPem       string
	}{
		{
			name:         "GIVEN_pkcs1PriKeyParser_WHEN_parse_empty_string_return_error",
			priKeyParser: pkcs1PriKeyParser,
			keyPem:       "",
		},
		{
			name:         "GIVEN_pkcs1PriKeyParser_WHEN_parse_abc_string_return_error",
			priKeyParser: pkcs1PriKeyParser,
			keyPem:       "abc",
		},
		{
			name:         "GIVEN_pkcs8PriKeyParser_WHEN_parse_pkcs1PrivateKeyPem_return_error",
			priKeyParser: pkcs8PriKeyParser,
			keyPem:       "",
		},
		{
			name:         "GIVEN_pkcs8PriKeyParser_WHEN_parse_abc_string_return_error",
			priKeyParser: pkcs8PriKeyParser,
			keyPem:       "abc",
		},
	}

	for _, tc := range testCases {
		key, err := tc.priKeyParser.Parse(tc.keyPem)

		expectedErrMsg := "failed to decode"
		assert.Nil(t, key)
		assert.ErrorContainsf(
			t,
			err,
			expectedErrMsg,
			"expected error containing %q, got %s", expectedErrMsg, err,
		)
	}
}

func TestSuccessPublicKeyParsing(t *testing.T) {

	testCases := []struct {
		name         string
		pubKeyParser PublicKeyParser
		priKeyPem    string
	}{
		{
			name:         "GIVEN_pkcs1PubKeyParser_WHEN_parse_pkcs1PublicKeyPem_return_rsa_public_key_without_error",
			pubKeyParser: pkcs1PubKeyParser,
			priKeyPem:    pkcs1PubKeyPem,
		},
		{
			name:         "GIVEN_pkixPubKeyParser_WHEN_parse_pkixPublicKeyPemreturn_rsa_public_key_without_error",
			pubKeyParser: pkixPubKeyParser,
			priKeyPem:    pkixPubKeyPem,
		},
	}

	for _, tc := range testCases {
		key, err := tc.pubKeyParser.Parse(tc.priKeyPem)

		assert.NoError(t, err)
		assert.IsType(t, &rsa.PublicKey{}, key)
	}
}

func TestFailedPublicKeyParsing(t *testing.T) {

	testCases := []struct {
		name         string
		pubKeyParser PublicKeyParser
		keyPem       string
	}{
		{
			name:         "GIVEN_pkcs1PubKeyParser_WHEN_parse_pkcs1PrivateKeyPem_return_error",
			pubKeyParser: pkcs1PubKeyParser,
			keyPem:       pkcs1PriKeyPem,
		},
		{
			name:         "GIVEN_pkcs1PubKeyParser_WHEN_parse_pkcs8PrivateKeyPem_return_error",
			pubKeyParser: pkcs1PubKeyParser,
			keyPem:       pkcs8PriKeyPem,
		},
		{
			name:         "GIVEN_pkcs1PubKeyParser_WHEN_parse_pkixPublicKeyPem_return_error",
			pubKeyParser: pkcs1PubKeyParser,
			keyPem:       pkixPubKeyPem,
		},
		{
			name:         "GIVEN_pkixPubKeyParser_WHEN_parse_pkcs1PrivateKeyPem_return_error",
			pubKeyParser: pkixPubKeyParser,
			keyPem:       pkcs1PriKeyPem,
		},
		{
			name:         "GIVEN_pkixPubKeyParserWHEN_parse_pkcs8PrivateKeyPem_return_error",
			pubKeyParser: pkixPubKeyParser,
			keyPem:       pkcs8PriKeyPem,
		},
		{
			name:         "GIVEN_pkixPubKeyParser_WHEN_parse_pkcs1PublicKeyPem_return_error",
			pubKeyParser: pkixPubKeyParser,
			keyPem:       pkcs1PubKeyPem,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := tc.pubKeyParser.Parse(tc.keyPem)

			expectedErrMsg := "failed to parse"
			assert.Nil(t, key)
			assert.ErrorContainsf(
				t,
				err,
				expectedErrMsg,
				"expected error containing %q, got %s", expectedErrMsg, err,
			)
		})
	}
}

func TestFailedNonPublicKeyPemParsing(t *testing.T) {

	testCases := []struct {
		name         string
		pubKeyParser PublicKeyParser
		keyPem       string
	}{
		{
			name:         "GIVEN_pkcs1PubKeyParser_WHEN_parse_empty_string_return_error",
			pubKeyParser: pkcs1PubKeyParser,
			keyPem:       "",
		},
		{
			name:         "GIVEN_pkcs1PubKeyParser_WHEN_parse_abc_string_return_error",
			pubKeyParser: pkcs1PubKeyParser,
			keyPem:       "abc",
		},
		{
			name:         "GIVEN_pkixPubKeyParser_WHEN_parse_pkcs1PrivateKeyPem_return_error",
			pubKeyParser: pkixPubKeyParser,
			keyPem:       "",
		},
		{
			name:         "GIVEN_pkixPubKeyParser_WHEN_parse_abc_string_return_error",
			pubKeyParser: pkixPubKeyParser,
			keyPem:       "abc",
		},
	}

	for _, tc := range testCases {
		key, err := tc.pubKeyParser.Parse(tc.keyPem)

		expectedErrMsg := "failed to decode"
		assert.Nil(t, key)
		assert.ErrorContainsf(
			t,
			err,
			expectedErrMsg,
			"expected error containing %q, got %s", expectedErrMsg, err,
		)
	}
}
