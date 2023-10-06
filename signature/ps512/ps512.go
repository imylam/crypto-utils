package ps512

import (
	"crypto"

	"github.com/imylam/crypto-utils/rsa"
)

const ALGO string = "PS512"

var (
	hash       = crypto.SHA512
	signScheme = rsa.NewPssSignScheme()
)
