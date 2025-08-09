package argon2id

import (
	"testing"

	stringsdk "github.com/imylam/crypto-utils/string-sdk"
	"github.com/stretchr/testify/assert"
)

func TestHashLengthIs97(t *testing.T) {
	configs := newConfigs()

	for i := 0; i < 20; i++ {
		randStr := stringsdk.RandomStr(i)

		hash, _ := Sign(configs, randStr)
		assert.Equal(t, len(hash), 97)
	}
}

func TestRoundTripSuccess(t *testing.T) {
	configs := newConfigs()

	for i := 1; i < 15; i++ {
		randPw := stringsdk.RandomStr(i)
		hash, _ := Sign(configs, randPw)

		isMatch, _ := Verify(hash, randPw)

		assert.True(t, isMatch)

	}
}

func TestRoundTripFail(t *testing.T) {
	configs := newConfigs()

	for i := 1; i < 15; i++ {
		randPw := stringsdk.RandomStr(i)
		wrongPw := stringsdk.RandomStr(i)

		hash, _ := Sign(configs, randPw)

		isMatch, _ := Verify(hash, wrongPw)

		assert.False(t, isMatch)
	}
}

func newConfigs() *Argon2Configs {
	return &Argon2Configs{
		TimeCost:   2,
		MemoryCost: 64 * 1024,
		Threads:    4,
		KeyLength:  32,
	}
}
