package nkeys

import (
	"testing"
	"time"
)

func newTestSigningKey(t *testing.T, prefix PrefixByte) (KeyPair, string) {
	t.Helper()
	kp, err := CreatePair(prefix)
	if err != nil {
		t.Fatal(err)
	}
	public, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return kp, public
}

func TestKeyRingRotationWindow(t *testing.T) {
	oldKey, oldPublic := newTestSigningKey(t, PrefixByteUser)
	newKey, newPublic := newTestSigningKey(t, PrefixByteUser)

	rotation := time.Unix(1_700_000_000, 0)
	retirement := rotation.Add(15 * time.Minute)
	ring, err := NewKeyRing(
		KeyWindow{PublicKey: oldPublic, NotAfter: retirement},
		KeyWindow{PublicKey: newPublic, NotBefore: rotation},
	)
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("request signed during key rotation")
	oldSignature, err := oldKey.Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	newSignature, err := newKey.Sign(input)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		at         time.Time
		oldAllowed bool
		newAllowed bool
	}{
		{name: "before new key activates", at: rotation.Add(-time.Nanosecond), oldAllowed: true},
		{name: "overlap", at: rotation.Add(10 * time.Minute), oldAllowed: true, newAllowed: true},
		{name: "retirement boundary", at: retirement, oldAllowed: true, newAllowed: true},
		{name: "after retirement", at: retirement.Add(time.Nanosecond), newAllowed: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ring.VerifyAt(input, oldSignature, test.at) == nil; got != test.oldAllowed {
				t.Fatalf("old key allowed = %v, want %v", got, test.oldAllowed)
			}
			if got := ring.VerifyAt(input, newSignature, test.at) == nil; got != test.newAllowed {
				t.Fatalf("new key allowed = %v, want %v", got, test.newAllowed)
			}

			active := ring.ActivePublicKeys(test.at)
			wantActive := 0
			if test.oldAllowed {
				wantActive++
			}
			if test.newAllowed {
				wantActive++
			}
			if len(active) != wantActive {
				t.Fatalf("active keys = %d, want %d", len(active), wantActive)
			}
		})
	}
}

func TestKeyRingRejectsWeakKeys(t *testing.T) {
	weak, err := Encode(PrefixByteUser, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyRing(KeyWindow{PublicKey: string(weak)}); err != ErrInvalidPublicKey {
		t.Fatalf("expected %v, got %v", ErrInvalidPublicKey, err)
	}
}

func TestKeyRingRejectsDisallowedPrefix(t *testing.T) {
	_, accountPublic := newTestSigningKey(t, PrefixByteAccount)
	_, err := NewKeyRingForPrefixes(
		[]KeyWindow{{PublicKey: accountPublic}},
		PrefixByteUser,
	)
	if err != ErrIncompatibleKey {
		t.Fatalf("expected %v, got %v", ErrIncompatibleKey, err)
	}
}

func TestKeyRingRejectsCurveKey(t *testing.T) {
	curve, err := CreateCurveKeys()
	if err != nil {
		t.Fatal(err)
	}
	public, err := curve.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyRing(KeyWindow{PublicKey: public}); err != ErrInvalidNKeyOperation {
		t.Fatalf("expected %v, got %v", ErrInvalidNKeyOperation, err)
	}
}

func TestKeyRingRejectsInvalidConfiguration(t *testing.T) {
	_, public := newTestSigningKey(t, PrefixByteUser)

	if _, err := NewKeyRing(); err != ErrNoVerificationKeys {
		t.Fatalf("expected %v, got %v", ErrNoVerificationKeys, err)
	}

	notBefore := time.Unix(1_700_000_000, 0)
	_, err := NewKeyRing(KeyWindow{
		PublicKey: public,
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(-time.Second),
	})
	if err != ErrInvalidKeyWindow {
		t.Fatalf("expected %v, got %v", ErrInvalidKeyWindow, err)
	}

	if _, err := NewKeyRingForPrefixes(
		[]KeyWindow{{PublicKey: public}},
		PrefixByte(127),
	); err != ErrInvalidPrefixByte {
		t.Fatalf("expected %v, got %v", ErrInvalidPrefixByte, err)
	}
}

func TestKeyRingRejectsInvalidSignature(t *testing.T) {
	key, public := newTestSigningKey(t, PrefixByteUser)
	otherKey, _ := newTestSigningKey(t, PrefixByteUser)
	ring, err := NewKeyRing(KeyWindow{PublicKey: public})
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("payload")
	signature, err := otherKey.Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Verify(input, signature); err != ErrInvalidSignature {
		t.Fatalf("expected %v, got %v", ErrInvalidSignature, err)
	}

	validSignature, err := key.Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Verify(input, validSignature); err != nil {
		t.Fatal(err)
	}
}

func TestKeyRingCurrentKeyCanBeUnbounded(t *testing.T) {
	key, public := newTestSigningKey(t, PrefixByteUser)
	ring, err := NewKeyRing(KeyWindow{PublicKey: public})
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("payload")
	signature, err := key.Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0).Add(100 * 365 * 24 * time.Hour)
	if err := ring.VerifyAt(input, signature, at); err != nil {
		t.Fatal(err)
	}
}

func TestIsValidPublicKeyForPrefixes(t *testing.T) {
	_, userPublic := newTestSigningKey(t, PrefixByteUser)
	_, accountPublic := newTestSigningKey(t, PrefixByteAccount)

	if !IsValidPublicKeyForPrefixes(userPublic, PrefixByteUser, PrefixByteAccount) {
		t.Fatal("expected user key to be accepted")
	}
	if !IsValidPublicKeyForPrefixes(accountPublic, PrefixByteUser, PrefixByteAccount) {
		t.Fatal("expected account key to be accepted")
	}
	if IsValidPublicKeyForPrefixes(accountPublic, PrefixByteUser) {
		t.Fatal("expected account key to be rejected")
	}
	if !IsValidPublicKeyForPrefixes(userPublic) {
		t.Fatal("expected any valid public key prefix to be accepted")
	}

	weak, err := Encode(PrefixByteUser, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if IsValidPublicKeyForPrefixes(string(weak), PrefixByteUser) {
		t.Fatal("expected weak key to be rejected")
	}
}
