//go:build pq_circl || pq_openssl

// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package note

import (
	"fmt"

	"github.com/sigstore/sigstore/pkg/pqcrypto"
)

const (
	mldsaID = "04"
)

// pqKeyHash generates key hashes for post-quantum (ML-DSA) keys
func pqKeyHash(origin string, key *pqcrypto.PQPublicKey) (uint32, []byte, error) {
	marshaled, err := pqcrypto.MarshalMLDSAPublicKeyToDER(key)
	if err != nil {
		return 0, nil, fmt.Errorf("marshaling ML-DSA public key: %w", err)
	}

	// ML-DSA algorithm identifier: algUndef (0x05) + "04" (ML-DSA)
	mldsaAlg := append([]byte{algUndef}, []byte(mldsaID)...)
	id, hash := genConformantKeyHash(origin, mldsaAlg, marshaled)
	return id, hash, nil
}

// init function to register PQ key hash support
func init() {
	registerPQKeyHasher()
}

// registerPQKeyHasher is called to enable PQ key support in KeyHash
func registerPQKeyHasher() {
	// This will be called via init() when built with pq_circl or pq_openssl tags
	pqKeyHashEnabled = true
}

var pqKeyHashEnabled = false

// tryPQKeyHash attempts to hash a PQ key if PQ support is enabled
func tryPQKeyHash(origin string, key interface{}) (uint32, []byte, error) {
	if !pqKeyHashEnabled {
		return 0, nil, fmt.Errorf("PQ support not enabled")
	}

	pqKey, ok := key.(*pqcrypto.PQPublicKey)
	if !ok {
		return 0, nil, fmt.Errorf("not a PQ key")
	}

	return pqKeyHash(origin, pqKey)
}
