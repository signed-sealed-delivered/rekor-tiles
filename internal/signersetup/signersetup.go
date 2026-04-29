/*
Copyright 2026 The Sigstore Authors

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

// Package signersetup provides common functionality for initializing signers
// across different backends (AWS, GCP, POSIX).
package signersetup

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// HashAlgMap maps hash algorithm names to crypto.Hash values.
var HashAlgMap = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

// Config holds configuration for initializing signers.
type Config struct {
	// File-based signer configuration
	FilePaths []string
	Passwords []string

	// KMS-based signer configuration
	KMSKeys   []string
	KMSHashes []string

	// Backend-specific factory function for creating signers
	// This allows each backend to inject its own KMS configuration
	CreateSigner SignerFactory
}

// SignerFactory is a function that creates a signer from configuration options.
// Backends can implement this to add their specific options (e.g., GCP retry configuration).
type SignerFactory func(ctx context.Context, opts interface{}) (signature.Signer, error)

// InitializeSigners creates signers based on the provided configuration.
// Returns the list of signers or an error if initialization fails.
func InitializeSigners(ctx context.Context, cfg Config) ([]signature.Signer, error) {
	// Check for hybrid mode
	totalSigners := len(cfg.FilePaths) + len(cfg.KMSKeys)
	if totalSigners == 0 {
		return nil, fmt.Errorf("no signer configuration provided")
	}

	if totalSigners > 1 {
		slog.Info("Initializing hybrid signing mode",
			"file_signers", len(cfg.FilePaths),
			"kms_signers", len(cfg.KMSKeys))
	} else {
		slog.Info("Initializing single signer")
	}

	signers := make([]signature.Signer, 0, totalSigners)

	// Create file-based signers
	for i, filepath := range cfg.FilePaths {
		if filepath == "" {
			continue
		}

		password := ""
		if i < len(cfg.Passwords) {
			password = cfg.Passwords[i]
		}

		opts := FileSignerOpts{
			FilePath: filepath,
			Password: password,
		}

		signer, err := cfg.CreateSigner(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("creating file signer %d: %w", i, err)
		}
		signers = append(signers, signer)
	}

	// Create KMS signers
	for i, kmsKey := range cfg.KMSKeys {
		if kmsKey == "" {
			continue
		}

		// Get hash algorithm for this KMS key
		hashAlg := crypto.SHA256 // default
		if i < len(cfg.KMSHashes) {
			if h, ok := HashAlgMap[cfg.KMSHashes[i]]; ok {
				hashAlg = h
			}
		}

		opts := KMSSignerOpts{
			KMSKey:  kmsKey,
			HashAlg: hashAlg,
		}

		signer, err := cfg.CreateSigner(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("creating KMS signer %d: %w", i, err)
		}
		signers = append(signers, signer)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no valid signers configured")
	}

	slog.Info("Signers initialized", "count", len(signers))
	return signers, nil
}

// FileSignerOpts holds options for creating a file-based signer.
type FileSignerOpts struct {
	FilePath string
	Password string
}

// KMSSignerOpts holds options for creating a KMS-based signer.
type KMSSignerOpts struct {
	KMSKey  string
	HashAlg crypto.Hash
	// Backend-specific options (e.g., GCP RPC options) can be added by the backend
	Extra interface{}
}

// LogPublicKeys logs all public keys from the signers in base64 DER format.
func LogPublicKeys(signers []signature.Signer) error {
	for i, signer := range signers {
		pubkey, err := signer.PublicKey()
		if err != nil {
			return fmt.Errorf("failed to get public key from signer %d: %w", i, err)
		}

		der, err := cryptoutils.MarshalPublicKeyToDER(pubkey)
		if err != nil {
			return fmt.Errorf("failed to marshal public key to DER for signer %d: %w", i, err)
		}

		slog.Info("Loaded signing key",
			"signer", i,
			"pubkey in base64 DER", base64.StdEncoding.EncodeToString(der))
	}
	return nil
}

// LogPublicKeyTypes logs the types of public keys from the signers.
// This is useful for GCP backends that prefer to log algorithm types.
func LogPublicKeyTypes(signers []signature.Signer) error {
	for i, signer := range signers {
		pubkey, err := signer.PublicKey()
		if err != nil {
			return fmt.Errorf("failed to get public key from signer %d: %w", i, err)
		}

		slog.Info("Loaded signing key",
			"signer", i,
			"algorithm", fmt.Sprintf("%T", pubkey))
	}
	return nil
}
