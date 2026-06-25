// Package id generates random opaque identifiers.
package id

import (
	"crypto/rand"
	"encoding/hex"
)

// New returns a random 128-bit identifier as a hex string. It panics if the
// system CSPRNG is unavailable, which is not a recoverable condition.
func New() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
