package scrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/imylam/crypto-utils/signature"
	textcoder "github.com/imylam/text-coder"
	"golang.org/x/crypto/scrypt"
)

const (
	ALGO                  = "scrypt"
	ERR_MALFOMATTED_HASH  = "malformatted hash provided"
	ERR_INVALID_SIGNATURE = "invalid signature"
)

var _ signature.Signer = (*Scrypt)(nil)
var _ signature.Verifier = (*Scrypt)(nil)

type Scrypt struct {
	// key      []byte
	params   Params
	pwCoder  textcoder.Coder
	sigCoder textcoder.Coder
}

func NewScrypt(
	// key []byte,
	params Params,
	pwCoder textcoder.Coder,
	sigCoder textcoder.Coder,
) *Scrypt {
	return &Scrypt{
		// key:      key,
		params:   params,
		pwCoder:  pwCoder,
		sigCoder: sigCoder,
	}
}

// Algo returns the algorithm used for signing/verifying.
func (s *Scrypt) Algo() (algo string) {
	return ALGO
}

// Sign implements signature.Signer.
func (s *Scrypt) Sign(
	pw string,
) (pwHash string, err error) {
	pwBytes, err := s.pwCoder.Decode(pw)
	if err != nil {
		err = fmt.Errorf("failed to decode password: %w", err)
		return
	}

	salt, err := generateRandomBytes(s.params.SaltLen)
	if err != nil {
		err = fmt.Errorf("failed to generate salt: %w", err)
		return
	}

	dk, err := scrypt.Key(
		pwBytes,
		salt,
		s.params.N,
		s.params.R,
		s.params.P,
		s.params.DKLen,
	)
	if err != nil {
		return "", err
	}

	pwHash = fmt.Sprintf(
		"%d$%d$%d$%s$%s",
		s.params.N,
		s.params.R,
		s.params.P,
		s.sigCoder.Encode(salt),
		s.sigCoder.Encode(dk),
	)

	return
}

// Verify implements signature.Verifier.
func (s *Scrypt) Verify(pw string, hash string) (err error) {
	params, salt, dk, err := s.decodeHash(hash)
	if err != nil {
		err = fmt.Errorf("failed to decode hash: %w", err)
		return
	}

	pwBytes, err := s.pwCoder.Decode(pw)
	if err != nil {
		err = fmt.Errorf("failed to decode password: %w", err)
		return
	}

	other, err := scrypt.Key(pwBytes, salt, params.N, params.R, params.P, params.DKLen)
	if err != nil {
		err = fmt.Errorf("failed to hash password: %w", err)
		return err
	}

	if subtle.ConstantTimeCompare(dk, other) != 1 {
		err = errors.New("hashed password does not match the hash of password provided")
		return
	}

	return

}

func (s *Scrypt) decodeHash(hash string) (Params, []byte, []byte, error) {
	vals := strings.Split(hash, "$")

	// P, N, R, salt, scrypt derived key
	if len(vals) != 5 {
		return Params{}, nil, nil, errors.New(ERR_MALFOMATTED_HASH)
	}

	var params Params
	var err error

	params.N, err = strconv.Atoi(vals[0])
	if err != nil {
		return params, nil, nil, fmt.Errorf(ERR_MALFOMATTED_HASH+" %w", err)
	}

	params.R, err = strconv.Atoi(vals[1])
	if err != nil {
		return params, nil, nil, fmt.Errorf(ERR_MALFOMATTED_HASH+" %w", err)
	}

	params.P, err = strconv.Atoi(vals[2])
	if err != nil {
		return params, nil, nil, fmt.Errorf(ERR_MALFOMATTED_HASH+" %w", err)
	}

	salt, err := s.sigCoder.Decode(vals[3])
	if err != nil {
		return params, nil, nil, fmt.Errorf(ERR_MALFOMATTED_HASH+" %w", err)
	}
	params.SaltLen = len(salt)

	dk, err := s.sigCoder.Decode(vals[4])
	if err != nil {
		return params, nil, nil, fmt.Errorf(ERR_MALFOMATTED_HASH+" %w", err)
	}
	params.DKLen = len(dk)

	if err := params.Check(); err != nil {
		return params, nil, nil, err
	}

	return params, salt, dk, nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
