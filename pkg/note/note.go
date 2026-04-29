/*
Copyright 2025 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Heavily borrowed from https://gist.githubusercontent.com/AlCutter/c6c69076dc55652e2d278900ccc1a5e7/raw/aac2bafc17a8efa162bd99b4453070b724779307/ecdsa_note.go - thanks, Al

package note

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"golang.org/x/mod/sumdb/note"
)

const (
	algEd25519 = 1
	algUndef   = 255
	rsaID      = "PKIX-RSA-PKCS#1v1.5"
)

// noteSigner uses an arbitrary sigstore signer to implement golang.org/x/mod/sumdb/note.Signer,
// which is used in Tessera to sign checkpoints in the signed notes format
// (https://github.com/C2SP/C2SP/blob/main/signed-note.md).
type noteSigner struct {
	name string
	hash uint32
	sign func(msg []byte) ([]byte, error)
}

// Name returns the server name associated with the key.
func (n *noteSigner) Name() string {
	return n.name
}

// KeyHash returns the key hash.
func (n *noteSigner) KeyHash() uint32 {
	return n.hash
}

// Sign returns a signature for the given message.
func (n *noteSigner) Sign(msg []byte) ([]byte, error) {
	return n.sign(msg)
}

type noteVerifier struct {
	name   string
	hash   uint32
	verify func(msg, sig []byte) bool
}

// Name implements note.Verifier.
func (n *noteVerifier) Name() string {
	return n.name
}

// Keyhash implements note.Verifier.
func (n *noteVerifier) KeyHash() uint32 {
	return n.hash
}

// Verify implements note.Verifier.
func (n *noteVerifier) Verify(msg, sig []byte) bool {
	return n.verify(msg, sig)
}

// isValidName reports whether the name conforms to the spec for the origin string of the note text
// as defined in https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md#note-text.
func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

// genConformantKeyHash generates a truncated (4-byte) and non-truncated
// identifier for typical (non-ECDSA) keys.
func genConformantKeyHash(name string, sigType, key []byte) (uint32, []byte) {
	hash := sha256.New()
	hash.Write([]byte(name))
	hash.Write([]byte("\n"))
	hash.Write(sigType)
	hash.Write(key)
	sum := hash.Sum(nil)
	return binary.BigEndian.Uint32(sum), sum
}

// ed25519KeyHash generates the 4-byte key ID for an Ed25519 public key.
// Ed25519 keys are the only key type compatible with witnessing.
func ed25519KeyHash(name string, key []byte) (uint32, []byte) {
	return genConformantKeyHash(name, []byte{algEd25519}, key)
}

// ecdsaKeyHash generates the 4-byte key ID for an ECDSA public key.
// ECDSA key IDs do not conform to the note standard for other key type
// (see https://github.com/C2SP/C2SP/blob/8991f70ddf8a11de3a68d5a081e7be27e59d87c8/signed-note.md#signature-types).
func ecdsaKeyHash(key *ecdsa.PublicKey) (uint32, []byte, error) {
	marshaled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return 0, nil, fmt.Errorf("marshaling public key: %w", err)
	}
	hash := sha256.Sum256(marshaled)
	return binary.BigEndian.Uint32(hash[:]), hash[:], nil
}

// rsaKeyhash generates the 4-byte key ID for an RSA public key.
func rsaKeyHash(name string, key *rsa.PublicKey) (uint32, []byte, error) {
	marshaled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return 0, nil, fmt.Errorf("marshaling public key: %w", err)
	}
	rsaAlg := append([]byte{algUndef}, []byte(rsaID)...)
	id, hash := genConformantKeyHash(name, rsaAlg, marshaled)
	return id, hash, nil
}

// KeyHash generates a truncated (4-byte) and non-truncated identifier for a
// public key/origin
func KeyHash(origin string, key crypto.PublicKey) (uint32, []byte, error) {
	var keyID uint32
	var logID []byte
	var err error

	switch pk := key.(type) {
	case *ecdsa.PublicKey:
		keyID, logID, err = ecdsaKeyHash(pk)
		if err != nil {
			return 0, nil, fmt.Errorf("getting ECDSA key hash: %w", err)
		}
	case ed25519.PublicKey:
		keyID, logID = ed25519KeyHash(origin, pk)
	case *rsa.PublicKey:
		keyID, logID, err = rsaKeyHash(origin, pk)
		if err != nil {
			return 0, nil, fmt.Errorf("getting RSA key hash: %w", err)
		}
	default:
		// Try PQ key hash (enabled when built with pq_circl or pq_openssl tags)
		keyID, logID, err = tryPQKeyHash(origin, key)
		//nolint:staticcheck // SA4023: stub always errors, but real impl may succeed
		if err != nil {
			return 0, nil, fmt.Errorf("unsupported key type: %T", key)
		}
	}

	return keyID, logID, nil
}

// NewNoteSigner converts a sigstore/sigstore/pkg/signature.Signer into a note.Signer.
func NewNoteSigner(ctx context.Context, origin string, signer signature.Signer) (note.Signer, error) {
	if !isValidName(origin) {
		return nil, fmt.Errorf("invalid name %s", origin)
	}

	pubKey, err := signer.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	keyID, _, err := KeyHash(origin, pubKey)
	if err != nil {
		return nil, err
	}

	sign := func(msg []byte) ([]byte, error) {
		return signer.SignMessage(bytes.NewReader(msg), options.WithContext(ctx))
	}

	return &noteSigner{
		name: origin,
		hash: keyID,
		sign: sign,
	}, nil
}

// NewNoteVerifier converts a sigstore/sigstore/pkg/signature.Verifier into a note.Verifier.
func NewNoteVerifier(origin string, verifier signature.Verifier) (note.Verifier, error) {
	if !isValidName(origin) {
		return nil, fmt.Errorf("invalid name %s", origin)
	}

	pubKey, err := verifier.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	keyID, _, err := KeyHash(origin, pubKey)
	if err != nil {
		return nil, err
	}

	return &noteVerifier{
		name: origin,
		hash: keyID,
		verify: func(msg, sig []byte) bool {
			if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
				return false
			}
			return true
		},
	}, nil
}

// multiNoteSigner uses multiple sigstore signers to implement note.Signer,
// producing multiple signatures in the signed-note format for hybrid PQC support.
type multiNoteSigner struct {
	ctx     context.Context
	origin  string
	signers []signature.Signer
	hashes  []uint32
}

// Name returns the server name associated with the signers.
func (m *multiNoteSigner) Name() string {
	return m.origin
}

// KeyHash returns the key hash of the first signer (for interface compatibility).
// In hybrid mode, each signature in the note will have its own hash.
func (m *multiNoteSigner) KeyHash() uint32 {
	if len(m.hashes) == 0 {
		return 0
	}
	return m.hashes[0]
}

// Sign produces multiple signatures for the given message, one per signer.
// The returned bytes contain all signatures in the C2SP signed-note format.
// Format:
//
//	<message>
//
//	— <origin> <hash1><sig1>
//	— <origin> <hash2><sig2>
//	...
func (m *multiNoteSigner) Sign(msg []byte) ([]byte, error) {
	if len(m.signers) == 0 {
		return nil, fmt.Errorf("no signers configured")
	}

	n := &note.Note{Text: string(msg)}

	noteSigners := make([]note.Signer, len(m.signers))
	for i := range m.signers {
		idx := i
		noteSigners[i] = &noteSigner{
			name: m.origin,
			hash: m.hashes[idx],
			sign: func(message []byte) ([]byte, error) {
				sig, err := m.signers[idx].SignMessage(bytes.NewReader(message), options.WithContext(m.ctx))
				if err != nil {
					return nil, err
				}
				// Prepend the 4-byte hash to the signature (note format requirement)
				var hbuf [4]byte
				binary.BigEndian.PutUint32(hbuf[:], m.hashes[idx])
				return append(hbuf[:], sig...), nil
			},
		}
	}

	return note.Sign(n, noteSigners...)
}

// NewMultiNoteSigner creates a note.Signer that signs with multiple sigstore signers.
// This enables hybrid post-quantum signing where checkpoints are signed with both
// classical (e.g., ECDSA) and post-quantum (e.g., ML-DSA) algorithms.
//
// All signers must share the same origin string.
func NewMultiNoteSigner(ctx context.Context, origin string, signers []signature.Signer) (note.Signer, error) {
	if !isValidName(origin) {
		return nil, fmt.Errorf("invalid name %s", origin)
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("no signers provided")
	}

	hashes := make([]uint32, len(signers))
	for i, signer := range signers {
		pubKey, err := signer.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("getting public key for signer %d: %w", i, err)
		}

		keyID, _, err := KeyHash(origin, pubKey)
		if err != nil {
			return nil, fmt.Errorf("computing key hash for signer %d: %w", i, err)
		}
		hashes[i] = keyID
	}

	return &multiNoteSigner{
		ctx:     ctx,
		origin:  origin,
		signers: signers,
		hashes:  hashes,
	}, nil
}

// VerifyAll checks that ALL provided verifiers have corresponding valid signatures.
// This is the recommended verification method for hybrid signing mode, as it ensures
// security from all signature algorithms (e.g., both ECDSA and ML-DSA must be valid).
// Returns false if any verifier lacks a valid signature.
func VerifyAll(signedNote []byte, verifiers []signature.Verifier) (bool, error) {
	if len(verifiers) == 0 {
		return false, fmt.Errorf("no verifiers provided")
	}

	n := &note.Note{}
	if _, err := note.Open(signedNote, note.VerifierList()); err != nil {
		return false, fmt.Errorf("parsing signed note: %w", err)
	}

	// Message is everything before the first signature line
	msg := []byte(n.Text)

	for vi, verifier := range verifiers {
		pk, err := verifier.PublicKey()
		if err != nil {
			return false, fmt.Errorf("getting public key for verifier %d: %w", vi, err)
		}

		verifierPkHash, _, err := KeyHash(n.Sigs[0].Name, pk)
		if err != nil {
			return false, fmt.Errorf("computing key hash for verifier %d: %w", vi, err)
		}

		foundValid := false
		for _, sig := range n.Sigs {
			if sig.Hash != verifierPkHash {
				continue
			}

			// Decode signature (4-byte hash + signature bytes)
			fullSig, err := base64.StdEncoding.DecodeString(sig.Base64)
			if err != nil {
				continue
			}
			if len(fullSig) < 4 {
				continue
			}
			sigBytes := fullSig[4:] // Skip hash prefix

			if err := verifier.VerifySignature(bytes.NewReader(sigBytes), bytes.NewReader(msg)); err != nil {
				continue
			}

			foundValid = true
			break
		}

		if !foundValid {
			return false, fmt.Errorf("no valid signature found for verifier %d", vi)
		}
	}

	return true, nil
}
