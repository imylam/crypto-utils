package rs512

import (
	"crypto"

	"github.com/imylam/crypto-utils/rsa"
)

const ALGO string = "RS512"

var (
	hash       = crypto.SHA512
	signScheme = rsa.NewPKCS1v15SignScheme()
)
