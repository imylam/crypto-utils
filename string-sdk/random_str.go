package stringsdk

import (
	"math/rand"
	"strings"
	"time"
)

const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!~@#$%^&*()_"
const (
	charIdxBits = 6                  // 6 bits to represent a letter index
	charIdxMask = 1<<charIdxBits - 1 // All 1-bits, as many as letterIdxBits
	charIdxMax  = 63 / charIdxBits   // # of letter indices fitting in 63 bits
)

func RandomStr(length int) string {
	src := rand.NewSource(time.Now().UnixNano())

	sb := strings.Builder{}
	sb.Grow(length)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := length-1, src.Int63(), charIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), charIdxMax
		}
		if idx := int(cache & charIdxMask); idx < len(chars) {
			sb.WriteByte(chars[idx])
			i--
		}
		cache >>= charIdxBits
		remain--
	}

	return sb.String()
}
