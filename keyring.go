package nkeys

import "time"

// KeyWindow associates a verification public key with the time interval in
// which it is accepted. NotBefore and NotAfter are inclusive. A zero NotBefore
// means the key is valid immediately, and a zero NotAfter means it does not
// expire.
//
// For a rotation, give the previous key a finite NotAfter and give the current
// key a NotBefore at or before the start of the migration. The overlap keeps
// clients on either generation working while the old key is retired
// automatically once its window closes.
type KeyWindow struct {
	PublicKey string
	NotBefore time.Time
	NotAfter  time.Time
}

func (w KeyWindow) validAt(at time.Time) bool {
	if !w.NotBefore.IsZero() && at.Before(w.NotBefore) {
		return false
	}
	if !w.NotAfter.IsZero() && at.After(w.NotAfter) {
		return false
	}
	return true
}

type keyRingEntry struct {
	publicKey string
	key       *pub
	window    KeyWindow
}

// KeyRing verifies signatures against one or more generations of public keys.
// Only keys whose validity windows contain the verification time are used, so
// a previous and a current key can be accepted together during a controlled
// rotation.
//
// Keys are validated when the KeyRing is created using the same strict checks
// as FromPublicKey. Malformed keys, invalid lengths, curve keys, and Ed25519
// small-order points are rejected. A KeyRing is immutable and safe for
// concurrent use.
type KeyRing struct {
	keys []keyRingEntry
}

// NewKeyRing creates a verifier for the supplied key generations.
func NewKeyRing(keys ...KeyWindow) (*KeyRing, error) {
	return newKeyRing(keys, nil)
}

// NewKeyRingForPrefixes creates a verifier and requires every key to have one
// of the supplied prefixes. If no prefixes are supplied, any valid non-curve
// public key prefix is accepted.
func NewKeyRingForPrefixes(keys []KeyWindow, prefixes ...PrefixByte) (*KeyRing, error) {
	return newKeyRing(keys, prefixes)
}

// NewKeyRingWithPrefixes is an alias for NewKeyRingForPrefixes.
func NewKeyRingWithPrefixes(keys []KeyWindow, prefixes ...PrefixByte) (*KeyRing, error) {
	return NewKeyRingForPrefixes(keys, prefixes...)
}

// RotatingKeyRing is an alias for KeyRing.
type RotatingKeyRing = KeyRing

// NewRotatingKeyRing creates a verifier for a key rotation.
func NewRotatingKeyRing(keys ...KeyWindow) (*RotatingKeyRing, error) {
	return NewKeyRing(keys...)
}

func newKeyRing(keys []KeyWindow, prefixes []PrefixByte) (*KeyRing, error) {
	if len(keys) == 0 {
		return nil, ErrNoVerificationKeys
	}

	var allowed map[PrefixByte]struct{}
	if len(prefixes) > 0 {
		allowed = make(map[PrefixByte]struct{}, len(prefixes))
		for _, prefix := range prefixes {
			if err := checkValidPublicPrefixByte(prefix); err != nil {
				return nil, err
			}
			if prefix == PrefixByteCurve {
				return nil, ErrInvalidNKeyOperation
			}
			allowed[prefix] = struct{}{}
		}
	}

	ring := &KeyRing{keys: make([]keyRingEntry, 0, len(keys))}
	for _, window := range keys {
		prefix, raw, err := decodePublicKey(window.PublicKey)
		if err != nil {
			return nil, err
		}
		if prefix == PrefixByteCurve {
			return nil, ErrInvalidNKeyOperation
		}
		if allowed != nil {
			if _, ok := allowed[prefix]; !ok {
				return nil, ErrIncompatibleKey
			}
		}
		if !window.NotBefore.IsZero() &&
			!window.NotAfter.IsZero() &&
			window.NotAfter.Before(window.NotBefore) {
			return nil, ErrInvalidKeyWindow
		}
		ring.keys = append(ring.keys, keyRingEntry{
			publicKey: window.PublicKey,
			key:       &pub{pre: prefix, pub: raw},
			window:    window,
		})
	}
	return ring, nil
}

// Verify verifies input against sig using the keys valid at the current time.
func (r *KeyRing) Verify(input []byte, sig []byte) error {
	return r.VerifyAt(input, sig, time.Now())
}

// VerifyAt verifies input against sig using the keys valid at at.
func (r *KeyRing) VerifyAt(input []byte, sig []byte, at time.Time) error {
	if r == nil {
		return ErrInvalidSignature
	}
	for i := range r.keys {
		entry := &r.keys[i]
		if !entry.window.validAt(at) {
			continue
		}
		if entry.key.Verify(input, sig) == nil {
			return nil
		}
	}
	return ErrInvalidSignature
}

// ActivePublicKeys returns the public keys that are valid at at, in the order
// in which they were added to the ring.
func (r *KeyRing) ActivePublicKeys(at time.Time) []string {
	if r == nil {
		return nil
	}
	keys := make([]string, 0, len(r.keys))
	for i := range r.keys {
		entry := &r.keys[i]
		if entry.window.validAt(at) {
			keys = append(keys, entry.publicKey)
		}
	}
	return keys
}
