package nkeys

import "time"

// KeyWindow describes a verification key and the time interval in which it is
// accepted. NotBefore and NotAfter are both inclusive. A zero NotBefore means
// the key is valid from the beginning of time, and a zero NotAfter means the
// key does not expire.
//
// During a key rotation, give the new key a NotBefore and give the old key a
// finite NotAfter. The overlap keeps old clients working while ensuring the
// old key is rejected automatically once the migration window closes.
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
// A key is only considered during its configured validity window, so callers
// can accept an old and a new key simultaneously and then retire the old key
// without a second rollout.
//
// Every key added to a KeyRing is decoded with the same strict public-key
// validation used by FromPublicKey. This rejects malformed keys, wrong key
// lengths, and Ed25519 small-order points. Curve keys are rejected because
// they cannot verify Ed25519 signatures.
//
// A KeyRing is immutable and safe for concurrent use.
type KeyRing struct {
	keys []keyRingEntry
}

// NewKeyRing creates a verifier for the supplied key generations.
func NewKeyRing(keys ...KeyWindow) (*KeyRing, error) {
	return newKeyRing(keys, nil)
}

// NewKeyRingForPrefixes creates a verifier and requires every key to have one
// of the supplied prefixes. This is useful when a verifier must remain limited
// to a role, even while accepting keys from more than one generation.
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
