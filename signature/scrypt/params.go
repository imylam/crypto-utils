package scrypt

import "errors"

const (
	errInvalidParams = "invalid parameters"
	maxInt           = 1<<31 - 1
	minDKLen         = 16 // the minimum derived key length in bytes.
	minSaltLen       = 8  // the minimum allowed salt length in bytes.
)

var DefaultParams = Params{N: 32768, R: 8, P: 1, SaltLen: 8, DKLen: 32}

// Params describes the input parameters to the scrypt
// key derivation function as per Colin Percival's scrypt
// paper: http://www.tarsnap.com/scrypt/scrypt.pdf
type Params struct {
	N       int // CPU/memory cost parameter (logN)
	R       int // block size parameter (octets)
	P       int // parallelisation parameter (positive int)
	SaltLen int // bytes to use as salt (octets)
	DKLen   int // length of the derived key (octets)
}

func (p *Params) Check() error {
	// Validate N
	if p.N > maxInt || p.N <= 1 || p.N%2 != 0 {
		return errors.New(errInvalidParams)
	}

	// Validate r
	if p.R < 1 || p.R > maxInt {
		return errors.New(errInvalidParams)
	}

	// Validate p
	if p.P < 1 || p.P > maxInt {
		return errors.New(errInvalidParams)
	}

	// Validate that r & p don't exceed 2^30 and that N, r, p values don't
	// exceed the limits defined by the scrypt algorithm.
	if uint64(p.R)*uint64(p.P) >= 1<<30 || p.R > maxInt/128/p.P || p.R > maxInt/256 || p.N > maxInt/128/p.R {
		return errors.New(errInvalidParams)
	}

	// Validate the salt length
	if p.SaltLen < minSaltLen || p.SaltLen > maxInt {
		return errors.New(errInvalidParams)
	}

	// Validate the derived key length
	if p.DKLen < minDKLen || p.DKLen > maxInt {
		return errors.New(errInvalidParams)
	}

	return nil
}
