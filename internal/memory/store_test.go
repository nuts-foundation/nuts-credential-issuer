package memory

import (
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-credential-issuer/internal/issuance"
)

func newIssuance(id string, now time.Time) *issuance.Issuance {
	return issuance.New(issuance.Params{ID: id}, now)
}

func TestCodeIsSingleUse(t *testing.T) {
	s := NewStore(time.Hour, time.Now)
	t.Cleanup(s.Close)
	iss := newIssuance("a", time.Now())
	s.Create(iss)
	s.BindCode("code", "a")

	if _, ok := s.TakeByCode("code"); !ok {
		t.Fatal("first TakeByCode should succeed")
	}
	if _, ok := s.TakeByCode("code"); ok {
		t.Error("second TakeByCode should fail (code is single-use)")
	}
}

func TestNonceIsSingleUse(t *testing.T) {
	s := NewStore(time.Hour, time.Now)
	t.Cleanup(s.Close)
	s.PutNonce("n")
	if !s.ConsumeNonce("n") {
		t.Fatal("first consume should succeed")
	}
	if s.ConsumeNonce("n") {
		t.Error("second consume should fail")
	}
	if s.ConsumeNonce("never-issued") {
		t.Error("unknown nonce should fail")
	}
}

func TestExpiry(t *testing.T) {
	now := time.Now()
	clock := now
	s := NewStore(time.Minute, func() time.Time { return clock })
	t.Cleanup(s.Close)
	s.Create(newIssuance("a", now))
	s.PutNonce("n")

	clock = now.Add(2 * time.Minute) // advance past TTL
	if _, ok := s.Get("a"); ok {
		t.Error("issuance should have expired")
	}
	if s.ConsumeNonce("n") {
		t.Error("nonce should have expired")
	}
}
