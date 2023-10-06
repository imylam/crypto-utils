package rs512

import (
	"testing"

	"github.com/imylam/crypto-utils/rsa"
	textcoder "github.com/imylam/text-coder"
	"github.com/stretchr/testify/assert"
)

const (
	PrivateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAi92VhWPbganUmFAVFQNcTF/Osr15ikWdp2xWl5OT4ag1by95
dXP+Sp07ZHGhc8EKEou6Xs+tARzkDCtVddoEycIO0YtJlPY6nDA5RMEQKMzi4fbQ
qVu/jKFK83JpWMwdbfqGZEyQp95VHlKTxKZIORfP+lutWlPRqn6hiwgCq1utEECZ
O22KggGaY/RZ6QrhqKE8jj8BzMtsd4cFKFVzcn+v3Ad56VbGvWMkj8fYai2CsZC9
RhvVi6GKwfkUigWpdvsUrsxaaqyicu+wJ+J/ijIU8UxJGv1tnfKUQ03uVXEV5ZUv
IWfoX1BjQHmHgiQdVUlNm3dKCdkrKCDIdV/THQIDAQABAoIBAAmQKAYL0tllxEx5
xUc/iJMMRfTAscu7gNEOvkj05TqbprOoelSGjs+JOqNehZyFiWvFNAQBjSGzWQBg
AiLhukwVQbAgJvLRdyZwwamqzbEMeULb/l5mEI3MBXTp0LwqkKSRaZj4BzgDIqzF
Fqdueye0Mhs7I3o2mvJeYCtCa/RNYRL2s4vnAWRG6Ei00NhucnOAi6KbHnWXtMjr
AV04OKibpx7MJw21NssGlfzZPmHlzLRkIV04ZZuoDNRkmcJ4d/k7wVsKFKuWXgrd
g+j9nmDtXyQgT1zIKl82qMza5XuQUHn8op+PvxrroY7mvAT62TfLTD2i5Qra+uJi
U1wSmIECgYEA40xoUPyLtMmbkWazM2mM/yfH3bsltlEgShfO7oiyi6RT3bFQttGe
TxeA1JPqGooYn9mO+bDfwDMGyJpbbMbmLPPcZHgFvqL4qr3vZsgMpP+myUo2HV7O
ed+asxfu4Uc5Tjb36DV8EilaR9vY4yj5O/kuPi52ScOWjqXvxeGC0+ECgYEAnYbX
vSgOQ+h8K2dW4qui+AtVKds5rxPL58emlydJclsJRdRf7s4fKJ+T/H3wLnh+ito+
kH0VEsWveAgc0XaOPHyCHkIeqZ/hlB2wUTq6S73rGUro8/iKLhvdDI8UpfdvQEQ7
Ujjat35q2oUeKU5vQPV4d0rGdgisM+Ht9DcWJr0CgYBJXD/O47Ozhd5P73WnAkof
kBdR2TUywrxJLaX8FuKJb2AiDTifyMfvfwZ1lcfZCPkpnm4m6I9O2Sk3VZpsYUWo
/IwFYTd5b+ASO3spESgDmP+bt/f/QrohW6nyY6cVzocQV21r5NdGhVI+HxbBOlg2
oxXpu9UxuY6+O5BHraEsAQKBgAUC9jghXxrP+atT1VLOzReBHMuBGvuz8IfGNUmX
yWFm/guHrymkyx76vLWKuCpyUOxP9y+XmyUGvwddkrUjRXEtMOKPjfQtjvqsWyCq
cqTYPPOIC5M/c/31ivnMT4bcMWDlCtIZ1vOBhRrAo24C/c0eQh/hdCDrM7dO18gu
PHktAoGBANopgKxEDccjSyK8Td1fgEOUKOKdMy7YsjR827amVQNOZ8xLL5XakeAi
EQjVZEU/chhhSML4qvtZoflGvysKxJw7WNR9tISR1oWx9DvJr/8SVZXFOT+EKLZ5
QX96L0VHL/L6nU7o1Hcz3SnzVoulwih+PP3deYh8hOPnyaP1UvDb
-----END RSA PRIVATE KEY-----`
	PublicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi92VhWPbganUmFAVFQNc
TF/Osr15ikWdp2xWl5OT4ag1by95dXP+Sp07ZHGhc8EKEou6Xs+tARzkDCtVddoE
ycIO0YtJlPY6nDA5RMEQKMzi4fbQqVu/jKFK83JpWMwdbfqGZEyQp95VHlKTxKZI
ORfP+lutWlPRqn6hiwgCq1utEECZO22KggGaY/RZ6QrhqKE8jj8BzMtsd4cFKFVz
cn+v3Ad56VbGvWMkj8fYai2CsZC9RhvVi6GKwfkUigWpdvsUrsxaaqyicu+wJ+J/
ijIU8UxJGv1tnfKUQ03uVXEV5ZUvIWfoX1BjQHmHgiQdVUlNm3dKCdkrKCDIdV/T
HQIDAQAB
-----END PUBLIC KEY-----`
	Message          = "message"
	Signature        = "bpF3k6KcMxRBPFMPiwC5/NauUrGhDfEd7E9CiEdkdq63V22/7WeTTGQHmUDI1Bw0BlHHoMDsaQcvupsNaXjP39woC3ShvUJWURXGsFPewKFP6nwMFAx8Ug9vUJDA6oIPAXIGJvoMrsajYOhCICedUmGoRuDErPKlc0kV9YF/xcGUNTPk9sYFSog5/OEpE0Frx+vcW6z7040oPSMk31fOsVa/ZWREprGs5d9QZPr9DUCmRqwMDA+6SYYx9kzEUeoLw4J52xkDnlLJss+66QhyS5gYRFkhq7dOxiJB5M0hA5atg+fKdVGfBpXu0KBTvSz8abcyQCZoKdWCqddmrtVDUA=="
	AnotherSignature = "LExUqtUh4kWYlW5cGP6EAI/tekpgahvW1xg9ko/is9QQybfffkzRyltBJXUcp8RTQHKyll6MkoV1P2Mpbq7FZ5834eKDrBzrpLeUGNG+CYkrQTXPC8H9aYzhnASeQ6O9bxImi0lziIKThZaEdTKjlbf2c6VplKVOoXn7g30XcqszGxRIWuzXCJUAxYQXYFgKpuZb3LAx+9M6s32+ql+yJjj10fx0ECE7Y945LP3J9qJvGDqgI6itHe11K54EXTGvcqfYp9uYMcaTynMBqdoYioChuFbxVTMsrExEFrk+z+AdHEhBg65MY/ONacqwvko81ud54dMTAkHnKqOjPkMdwQ=="
)

var (
	privateKeyParser = rsa.Pkcs1PrivateKeyParser{}
	publicKeyParser  = rsa.PkixPublicKeyParser{}
	privateKey, _    = privateKeyParser.Parse(PrivateKeyPem)
	publicKey, _     = publicKeyParser.Parse(PublicKeyPem)
	rsSigner         = NewSigner(privateKey, &textcoder.Utf8Coder{}, &textcoder.Base64StdCoder{})
	rsVerifier       = NewVerifier(publicKey, &textcoder.Utf8Coder{}, &textcoder.Base64StdCoder{})
)

func TestAlgo(t *testing.T) {
	sAlgo := rsSigner.Algo()
	assert.Equal(t, ALGO, sAlgo)

	vAlgo := rsVerifier.Algo()
	assert.Equal(t, ALGO, vAlgo)
}

func TestSign(t *testing.T) {
	sig, err := rsSigner.Sign(Message)

	assert.NoError(t, err)
	assert.Equal(t, Signature, sig)

}

func TestVerify(t *testing.T) {
	err := rsVerifier.Verify(Message, Signature)

	assert.NoError(t, err)
}

func TestVerifyWrongSignatureShouldThrowError(t *testing.T) {
	err := rsVerifier.Verify(Message, AnotherSignature)

	expectedErrMsg := "failed to verify signature:"
	assert.ErrorContainsf(
		t,
		err,
		expectedErrMsg,
		"expected error containing %q, got %s", expectedErrMsg, err,
	)
}

func TestWrongMessageOrSignatureCodingShouldThrowError(t *testing.T) {

	utf8Msg := "abc"
	utf8Signature := "hello"
	hexMsg := "68656c6c6f0d0a"
	errDecodeMsg := "failed to decode message:"
	errDecodeSig := "failed to decode signature:"

	hexSigner := NewSigner(privateKey, &textcoder.HexCoder{}, &textcoder.HexCoder{})
	hexVerifier := NewVerifier(publicKey, &textcoder.HexCoder{}, &textcoder.HexCoder{})

	t.Run("GIVEN_wrong_message_coding_WHEN_signing_THEN_return_err", func(t *testing.T) {
		sig, err := hexSigner.Sign(utf8Msg)

		assert.Empty(t, sig)
		assert.ErrorContainsf(
			t,
			err,
			errDecodeMsg,
			"expected error containing %q, got %s", errDecodeMsg, err,
		)
	})

	t.Run("GIVEN_wrong_message_coding_WHEN_verifying_THEN_return_err", func(t *testing.T) {
		err := hexVerifier.Verify(utf8Msg, Signature)

		assert.ErrorContainsf(
			t,
			err,
			errDecodeMsg,
			"expected error containing %q, got %s", errDecodeMsg, err,
		)
	})

	t.Run("GIVEN_wrong_signature_coding_WHEN_verifying_THEN_return_err", func(t *testing.T) {
		err := hexVerifier.Verify(hexMsg, utf8Signature)

		assert.ErrorContainsf(
			t,
			err,
			errDecodeSig,
			"expected error containing %q, got %s", errDecodeSig, err,
		)

	})
}

func TestVerifyOwnSignedDigest(t *testing.T) {
	testMsg := "lorem ipsum"

	testPriKeyPem, testPubKeyPem, _ := rsa.NewPkcs1PkixKeysGenerator().GenKeyPair()
	testPriKey, _ := privateKeyParser.Parse(testPriKeyPem)
	testPubKey, _ := publicKeyParser.Parse(testPubKeyPem)

	testSinger := NewSigner(testPriKey, &textcoder.Utf8Coder{}, &textcoder.HexCoder{})
	testVerifier := NewVerifier(testPubKey, &textcoder.Utf8Coder{}, &textcoder.HexCoder{})

	t.Run("GIVEN_same_message_WHEN_verifing_own_signed_signature_THEN_no_error", func(t *testing.T) {
		sig, err := testSinger.Sign(testMsg)
		assert.NoError(t, err)

		err = testVerifier.Verify(testMsg, sig)
		assert.NoError(t, err)
	})

	t.Run("GIVEN_different_message_WHEN_verifing_own_signed_signature_THEN_return_error", func(t *testing.T) {
		sig, err := testSinger.Sign(testMsg)
		assert.NoError(t, err)

		err = testVerifier.Verify(Message, sig)

		expectedErrMsg := "failed to verify signature:"
		assert.ErrorContainsf(
			t,
			err,
			expectedErrMsg,
			"expected error containing %q, got %s", expectedErrMsg, err,
		)
	})
}
