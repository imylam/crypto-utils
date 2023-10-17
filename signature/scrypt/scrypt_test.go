package scrypt

import (
	"testing"

	textcoder "github.com/imylam/text-coder"
	"github.com/stretchr/testify/assert"
)

const (
	// Key              = "key"
	Password  = "password"
	Signature = "32768$8$1$e6ade915861f38af$d8f83302984581f11ce4900473814d01d99a963af56038d96bf5260c05fef83d"
	// AnotherSignature = "e477384d7ca229dd1426e64b63ebf2d36ebd6d7e669a6735424e72ea6c01d3f8b56eb39c36d8232f5427999b8d1a3f9cd1128fc69f4d75b434216810fa367e99"
)

var (
	scryptPw = NewScrypt(DefaultParams, &textcoder.Utf8Coder{}, &textcoder.HexCoder{})
)

func TestAlgo(t *testing.T) {
	sAlgo := scryptPw.Algo()
	assert.Equal(t, ALGO, sAlgo)
}

func TestWrongPasswordOrSignatureCodingShouldThrowError(t *testing.T) {

	utf8Pw := "abc"
	utf8Signature := "hello"
	hexPw := "68656c6c6f0d0a"
	errDecodePw := "failed to decode password:"
	errDecodeHash := "failed to decode hash:"

	hexScrypt := NewScrypt(DefaultParams, &textcoder.HexCoder{}, &textcoder.HexCoder{})
	// hexVerifier := NewVerifier(publicKey, &textcoder.HexCoder{}, &textcoder.HexCoder{})

	t.Run("GIVEN_wrong_password_coding_WHEN_signing_THEN_return_err", func(t *testing.T) {
		sig, err := hexScrypt.Sign(utf8Pw)

		assert.Empty(t, sig)
		assert.ErrorContainsf(
			t,
			err,
			errDecodePw,
			"expected error containing %q, got %s", errDecodePw, err,
		)
	})

	t.Run("GIVEN_wrong_password_coding_WHEN_verifying_THEN_return_err", func(t *testing.T) {
		err := hexScrypt.Verify(utf8Pw, Signature)

		assert.ErrorContainsf(
			t,
			err,
			errDecodePw,
			"expected error containing %q, got %s", errDecodePw, err,
		)
	})

	t.Run("GIVEN_wrong_hash_coding_WHEN_verifying_THEN_return_err", func(t *testing.T) {
		err := hexScrypt.Verify(hexPw, utf8Signature)

		assert.ErrorContainsf(
			t,
			err,
			errDecodeHash,
			"expected error containing %q, got %s", errDecodeHash, err,
		)
	})
}

func TestVerifyOwnPasswordHash(t *testing.T) {
	testPw := "lorem ipsum"

	t.Run("GIVEN_same_message_WHEN_verifing_own_signed_signature_THEN_no_error", func(t *testing.T) {
		sig, err := scryptPw.Sign(testPw)
		assert.NoError(t, err)

		err = scryptPw.Verify(testPw, sig)
		assert.NoError(t, err)
	})

	t.Run("GIVEN_different_message_WHEN_verifing_own_signed_signature_THEN_return_error", func(t *testing.T) {
		sig, err := scryptPw.Sign(testPw)
		assert.NoError(t, err)

		err = scryptPw.Verify(Password, sig)

		expectedErrMsg := "hashed password does not match the hash of password provided"
		assert.ErrorContainsf(
			t,
			err,
			expectedErrMsg,
			"expected error containing %q, got %s", expectedErrMsg, err,
		)
	})
}
