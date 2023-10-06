package rsa

import (
	"crypto"
	"crypto/rsa"
)

// // Encrypt plainText with public key using RSA-OAEP
// func Encrypt(
// 	hash crypto.Hash,
// 	publicKey *rsa.PublicKey,
// 	plainText string,
// 	keyParser PublicKeyParser,
// 	plainTextCoder, cipherTextCoder textcoder.Coder,
// ) (cipherText string, err error) {
// 	plainTextByte, err := plainTextCoder.Decode(plainText)
// 	if err != nil {
// 		err = fmt.Errorf("failed to decode plain text: %w", err)
// 		return
// 	}

// 	rng := rand.Reader
// 	cipherTextBytes, err := rsa.EncryptOAEP(hash.New(), rng, publicKey, plainTextByte, nil)
// 	if err != nil {
// 		return
// 	}

// 	cipherText = cipherTextCoder.Encode(cipherTextBytes)
// 	return
// }

// // Decrypt cipherText with private key using RSA-OAEP
// func Decrypt(
// 	hash crypto.Hash,
// 	privateKey *rsa.PrivateKey,
// 	cipherText string,
// 	keyParser PrivateKeyParser,
// 	cipherTextCoder, plainTextCoder textcoder.Coder,
// ) (plainText string, err error) {
// 	cipherTextBytes, err := cipherTextCoder.Decode(cipherText)
// 	if err != nil {
// 		err = fmt.Errorf("failed to decode cipher text: %w", err)
// 		return
// 	}

// 	rng := rand.Reader
// 	plainTextBytes, err := rsa.DecryptOAEP(hash.New(), rng, privateKey, cipherTextBytes, nil)
// 	if err != nil {
// 		return
// 	}

// 	plainText = plainTextCoder.Encode(plainTextBytes)
// 	return
// }

// Sign a message with PrivateKey using RSA-PSS and the crypto hash given
func Sign(
	hash crypto.Hash,
	signScheme SignScheme,
	privateKey *rsa.PrivateKey,
	messageByte []byte,
) (signature []byte, err error) {

	hasher := hash.New()
	hasher.Write(messageByte)
	hashedMessage := hasher.Sum(nil)

	return signScheme.Sign(hash, privateKey, hashedMessage)
}

// Verify a signature with PublicKey using RSA-PSS and the crypto hash given
func Verify(
	hash crypto.Hash,
	signScheme SignScheme,
	publicKey *rsa.PublicKey,
	messageBytes, signatureBytes []byte,
) (err error) {
	hasher := hash.New()
	hasher.Write(messageBytes)
	hashedMessageBytes := hasher.Sum(nil)

	return signScheme.Verify(hash, publicKey, hashedMessageBytes, signatureBytes, nil)
}
