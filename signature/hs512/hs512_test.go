package hs512

import (
	"testing"

	textcoder "github.com/imylam/text-coder"
	"github.com/stretchr/testify/assert"
)

const (
	Key              = "key"
	Message          = "message"
	Signature        = "e477384d7ca229dd1426e64b63ebf2d36ebd6d7e669a6735424e72ea6c01d3f8b56eb39c36d8232f5427999b8d1a3f9cd1128fc69f4d75b434216810fa367e98"
	AnotherSignature = "e477384d7ca229dd1426e64b63ebf2d36ebd6d7e669a6735424e72ea6c01d3f8b56eb39c36d8232f5427999b8d1a3f9cd1128fc69f4d75b434216810fa367e99"
)

var (
	signer = NewHS512([]byte(Key), &textcoder.Utf8Coder{}, &textcoder.HexCoder{})
)

func TestSign(t *testing.T) {
	sig, err := signer.Sign(Message)

	assert.NoError(t, err)
	assert.Equal(t, Signature, sig)

}

func TestVerify(t *testing.T) {
	err := signer.Verify(Message, Signature)

	assert.NoError(t, err)
}

func TestVerifyWrongSignatureShouldThrowError(t *testing.T) {
	err := signer.Verify(Message, AnotherSignature)

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

	hexSigner := NewHS512([]byte(Key), &textcoder.HexCoder{}, &textcoder.HexCoder{})

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
		err := hexSigner.Verify(utf8Msg, Signature)

		assert.ErrorContainsf(
			t,
			err,
			errDecodeMsg,
			"expected error containing %q, got %s", errDecodeMsg, err,
		)

	})

	t.Run("GIVEN_wrong_signature_coding_WHEN_verifying_THEN_return_err", func(t *testing.T) {
		err := hexSigner.Verify(hexMsg, utf8Signature)

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
	testSinger := NewHS512([]byte("secret"), &textcoder.Utf8Coder{}, &textcoder.HexCoder{})

	sig, err := testSinger.Sign(testMsg)
	assert.NoError(t, err)

	err = testSinger.Verify(testMsg, sig)
	assert.NoError(t, err)
}
