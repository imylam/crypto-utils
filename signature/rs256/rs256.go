package rs256

import (
	"crypto"

	"github.com/imylam/crypto-utils/rsa"
)

const ALGO string = "RS256"

var (
	hash       = crypto.SHA256
	signScheme = rsa.NewPKCS1v15SignScheme()
)
