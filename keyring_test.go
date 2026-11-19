package nkeys

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func newKeyRingTestKey(t *testing.T, prefix PrefixByte) (KeyPair, string) {
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

func TestKeyRingTwoClientExtendedRotationWindow(t *testing.T) {
	oldKey, oldPublic := newKeyRingTestKey(t, PrefixByteUser)
	newKey, newPublic := newKeyRingTestKey(t, PrefixByteUser)

	rotation := time.Unix(1_700_000_000, 0)
	plannedWindow := 5 * time.Minute
	actualSwitch := 12 * time.Minute
	retirement := rotation.Add(actualSwitch + 3*time.Minute)

	if retirement.Before(rotation.Add(plannedWindow)) {
		t.Fatal("test retirement must extend past the planned rotation window")
	}

	ring, err := NewKeyRing(
		KeyWindow{
			PublicKey: oldPublic,
			NotAfter:  retirement,
		},
		KeyWindow{
			PublicKey: newPublic,
			NotBefore: rotation,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("request signed while both clients are active")
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
		{
			name:       "before rotation only old client",
			at:         rotation.Add(-time.Nanosecond),
			oldAllowed: true,
		},
		{
			name:       "rotation starts",
			at:         rotation,
			oldAllowed: true,
			newAllowed: true,
		},
		{
			name:       "planned five minute window ends",
			at:         rotation.Add(plannedWindow),
			oldAllowed: true,
			newAllowed: true,
		},
		{
			name:       "actual twelve minute switch completes",
			at:         rotation.Add(actualSwitch),
			oldAllowed: true,
			newAllowed: true,
		},
		{
			name:       "retirement boundary is inclusive",
			at:         retirement,
			oldAllowed: true,
			newAllowed: true,
		},
		{
			name:       "old client rejected after retirement",
			at:         retirement.Add(time.Nanosecond),
			newAllowed: true,
		},
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

func TestKeyRingRejectsWeakOrMalformedKeys(t *testing.T) {
	short, err := Encode(PrefixByteUser, make([]byte, ed25519.PublicKeySize-1))
	if err != nil {
		t.Fatal(err)
	}
	long, err := Encode(PrefixByteUser, make([]byte, ed25519.PublicKeySize+1))
	if err != nil {
		t.Fatal(err)
	}
	smallOrder, err := Encode(PrefixByteUser, make([]byte, ed25519.PublicKeySize))
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalSmallOrder, err := Encode(PrefixByteUser, []byte{
		236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		publicKey string
		wantErr   error
	}{
		{name: "short key", publicKey: string(short), wantErr: ErrInvalidPublicKey},
		{name: "long key", publicKey: string(long), wantErr: ErrInvalidPublicKey},
		{name: "identity point", publicKey: string(smallOrder), wantErr: ErrInvalidPublicKey},
		{name: "noncanonical small order point", publicKey: string(noncanonicalSmallOrder), wantErr: ErrInvalidPublicKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewKeyRing(KeyWindow{PublicKey: test.publicKey}); err != test.wantErr {
				t.Fatalf("NewKeyRing() error = %v, want %v", err, test.wantErr)
			}
		})
	}

	curve, err := CreateCurveKeys()
	if err != nil {
		t.Fatal(err)
	}
	curvePublic, err := curve.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyRing(KeyWindow{PublicKey: curvePublic}); err != ErrInvalidNKeyOperation {
		t.Fatalf("NewKeyRing() error = %v, want %v", err, ErrInvalidNKeyOperation)
	}
}

func TestKeyRingPrefixRestrictions(t *testing.T) {
	_, userPublic := newKeyRingTestKey(t, PrefixByteUser)
	_, accountPublic := newKeyRingTestKey(t, PrefixByteAccount)

	ring, err := NewKeyRingForPrefixes(
		[]KeyWindow{{PublicKey: userPublic}},
		PrefixByteUser,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(ring.ActivePublicKeys(time.Unix(1_700_000_000, 0))) != 1 {
		t.Fatal("expected the user key to be active")
	}

	if _, err := NewKeyRingForPrefixes(
		[]KeyWindow{{PublicKey: accountPublic}},
		PrefixByteUser,
	); err != ErrIncompatibleKey {
		t.Fatalf("NewKeyRingForPrefixes() error = %v, want %v", err, ErrIncompatibleKey)
	}

	if _, err := NewKeyRingForPrefixes(
		[]KeyWindow{{PublicKey: userPublic}},
		PrefixByteCurve,
	); err != ErrInvalidNKeyOperation {
		t.Fatalf("NewKeyRingForPrefixes() error = %v, want %v", err, ErrInvalidNKeyOperation)
	}
}

func TestKeyRingConfigurationErrors(t *testing.T) {
	_, public := newKeyRingTestKey(t, PrefixByteUser)

	if _, err := NewKeyRing(); err != ErrNoVerificationKeys {
		t.Fatalf("NewKeyRing() error = %v, want %v", err, ErrNoVerificationKeys)
	}

	notBefore := time.Unix(1_700_000_000, 0)
	if _, err := NewKeyRing(KeyWindow{
		PublicKey: public,
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(-time.Second),
	}); err != ErrInvalidKeyWindow {
		t.Fatalf("NewKeyRing() error = %v, want %v", err, ErrInvalidKeyWindow)
	}

	if _, err := NewKeyRingForPrefixes(
		[]KeyWindow{{PublicKey: public}},
		PrefixByte(127),
	); err != ErrInvalidPrefixByte {
		t.Fatalf("NewKeyRingForPrefixes() error = %v, want %v", err, ErrInvalidPrefixByte)
	}
}

func TestKeyRingRejectsInvalidSignature(t *testing.T) {
	key, public := newKeyRingTestKey(t, PrefixByteUser)
	otherKey, _ := newKeyRingTestKey(t, PrefixByteUser)
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
		t.Fatalf("Verify() error = %v, want %v", err, ErrInvalidSignature)
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
	key, public := newKeyRingTestKey(t, PrefixByteUser)
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
	_, userPublic := newKeyRingTestKey(t, PrefixByteUser)
	_, accountPublic := newKeyRingTestKey(t, PrefixByteAccount)

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

	weak, err := Encode(PrefixByteUser, make([]byte, ed25519.PublicKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if IsValidPublicKeyForPrefixes(string(weak), PrefixByteUser) {
		t.Fatal("expected weak key to be rejected")
	}
}
