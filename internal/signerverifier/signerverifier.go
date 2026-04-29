/*
Copyright 2025 The Sigstore Authors

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

package signerverifier

import (
	"context"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"
)

// SignerConfig holds configuration for a single signer.
// Used for hybrid signing mode where multiple signers are configured.
type SignerConfig struct {
	// Filepath to signing key (file-based signer)
	Filepath string
	Password string

	// KMS key URI (KMS-based signer)
	KMSKey  string
	KMSHash string

	// Tink configuration
	TinkKEKURI     string
	TinkKeysetPath string
}

// NewMultiple creates multiple signers from a slice of configurations.
// This is used for hybrid post-quantum signing mode.
// NOTE: Currently only supports file-based signers. For KMS/Tink signers,
// use backend-specific signer creation (see cmd/rekor-server/*/app/serve.go).
func NewMultiple(_ context.Context, configs []SignerConfig, opts ...func(*SignerConfig)) ([]signature.Signer, error) {
	if len(configs) == 0 {
		return nil, fmt.Errorf("no signer configurations provided")
	}

	signers := make([]signature.Signer, 0, len(configs))
	for i, cfg := range configs {
		// Apply any option functions
		for _, opt := range opts {
			opt(&cfg)
		}

		var signer signature.Signer
		var err error

		switch {
		case cfg.Filepath != "":
			signer, err = NewFileSignerVerifier(cfg.Filepath, cfg.Password)
		case cfg.TinkKEKURI != "":
			// Tink requires backend-specific setup (GCP KMS client initialization)
			// For hybrid mode with Tink, initialize signers directly in serve.go
			// using internal/tessera/<backend>/signerverifier.NewTinkSignerVerifier()
			return nil, fmt.Errorf("signer %d: Tink not supported in NewMultiple; use backend-specific initialization", i)
		default:
			return nil, fmt.Errorf("signer %d: no valid configuration (need filepath)", i)
		}

		if err != nil {
			return nil, fmt.Errorf("creating signer %d: %w", i, err)
		}
		signers = append(signers, signer)
	}

	return signers, nil
}
