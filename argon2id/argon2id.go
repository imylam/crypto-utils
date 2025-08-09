package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const ALGO string = "argon2id"

func Sign(configs *Argon2Configs, password string) (signature string, err error) {
	salt, err := genPasswordSalt(16)
	if err != nil {
		return "", err
	}

	// Execute Argon2id hashing algorithm
	hashRaw := argon2.IDKey(
		[]byte(password),
		salt,
		configs.TimeCost,
		configs.MemoryCost,
		configs.Threads,
		configs.KeyLength,
	)

	// Generate standardized hash format
	signature = fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		ALGO,
		argon2.Version,
		configs.MemoryCost,
		configs.TimeCost,
		configs.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hashRaw),
	)

	return
}

func Verify(signature, password string) (bool, error) {
	// Parse stored hash parameters
	hash, salt, configs, err := parseHash(signature)
	if err != nil {
		return false, fmt.Errorf("hash parsing failed: %w", err)
	}

	// Generate hash using identical parameters
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		configs.TimeCost,
		configs.MemoryCost,
		configs.Threads,
		configs.KeyLength,
	)

	// Perform constant-time comparison to prevent timing attacks
	match := subtle.ConstantTimeCompare(hash, computedHash) == 1

	return match, nil
}

func parseHash(encodedHash string) (hash, salt []byte, configs Argon2Configs, err error) {
	components := strings.Split(encodedHash, "$")
	if len(components) != 6 {
		return []byte{}, []byte{}, configs, errors.New("invalid hash format structure")
	}

	// Validate algorithm identifier
	if !strings.HasPrefix(components[1], ALGO) {
		return []byte{}, []byte{}, configs, errors.New("unsupported algorithm variant")
	}

	// Extract version information
	var version int
	fmt.Sscanf(components[2], "v=%d", &version)

	// Parse configuration parameters
	fmt.Sscanf(components[3], "m=%d,t=%d,p=%d", &configs.MemoryCost, &configs.TimeCost, &configs.Threads)

	// Decode salt component
	salt, err = base64.RawStdEncoding.DecodeString(components[4])
	if err != nil {
		return []byte{}, []byte{}, configs, errors.New("unsupported algorithm variant")
	}

	// Decode hash component
	hash, err = base64.RawStdEncoding.DecodeString(components[5])
	if err != nil {
		return []byte{}, []byte{}, configs, errors.New("unsupported algorithm variant")
	}

	configs.KeyLength = uint32(len(hash))

	return
}

func genPasswordSalt(saltSize uint32) ([]byte, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failure to generate salt: %w", err)
	}

	return salt, nil
}
