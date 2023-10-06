package ps256

import (
	"crypto"

	"github.com/imylam/crypto-utils/rsa"
)

const ALGO string = "PS256"

var (
	hash       = crypto.SHA256
	signScheme = rsa.NewPssSignScheme()
)
