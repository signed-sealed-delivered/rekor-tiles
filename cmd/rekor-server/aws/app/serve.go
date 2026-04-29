//
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

package app

import (
	"context"
	"crypto"
	"encoding/base64"
	"log/slog"
	"os"

	"k8s.io/klog/v2"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	"github.com/sigstore/rekor-tiles/v2/internal/cli"
	"github.com/sigstore/rekor-tiles/v2/internal/server"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	awsDriver "github.com/sigstore/rekor-tiles/v2/internal/tessera/aws"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera/aws/signerverifier"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start the Rekor server",
	Long:  "start the Rekor server",
	Run: func(cmd *cobra.Command, _ []string) {
		ctx := cmd.Context()

		logLevel := slog.LevelInfo
		if err := logLevel.UnmarshalText([]byte(viper.GetString("log-level"))); err != nil {
			slog.Error("invalid log-level specified; must be one of 'debug', 'info', 'error', or 'warn'")
			os.Exit(1)
		}
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

		// tessera uses klog so pipe all klog messages to be written through slog
		klog.SetSlogLogger(slog.Default())

		slog.Info("starting rekor-server", "version", version.GetVersionInfo())

		// Parse signer configuration(s)
		// Check for hybrid mode first (multiple signers)
		signerFilepaths := viper.GetStringSlice("signer-filepaths")
		signerKMSKeys := viper.GetStringSlice("signer-kmskeys")
		signerKMSHashes := viper.GetStringSlice("signer-kmshashes")

		var signers []signature.Signer
		var err error

		if len(signerFilepaths) > 0 || len(signerKMSKeys) > 0 {
			// Multiple signer mode: Use --signer-filepaths and/or --signer-kmskeys
			if len(signerFilepaths)+len(signerKMSKeys) > 1 {
				slog.Info("Initializing hybrid signing mode", "file_signers", len(signerFilepaths), "kms_signers", len(signerKMSKeys))
			} else {
				slog.Info("Initializing single signer")
			}

			signerOpts := make([][]signerverifier.Option, 0)

			// Add file-based signers
			for i, filepath := range signerFilepaths {
				if filepath != "" {
					password := ""
					if passwords := viper.GetStringSlice("signer-passwords"); i < len(passwords) {
						password = passwords[i]
					}
					signerOpts = append(signerOpts, []signerverifier.Option{
						signerverifier.WithFile(filepath, password),
					})
				}
			}

			// Add KMS signers
			for i, kmsKey := range signerKMSKeys {
				if kmsKey != "" {
					// Get hash algorithm for this KMS key
					hashAlg := crypto.SHA256 // default
					if i < len(signerKMSHashes) {
						if h, ok := hashAlgMap[signerKMSHashes[i]]; ok {
							hashAlg = h
						}
					}

					signerOpts = append(signerOpts, []signerverifier.Option{
						signerverifier.WithKMS(kmsKey, hashAlg),
					})
				}
			}

			if len(signerOpts) == 0 {
				slog.Error("hybrid mode enabled but no valid signers configured")
				os.Exit(1)
			}

			signers, err = signerverifier.NewMultiple(ctx, signerOpts...)
			if err != nil {
				slog.Error("failed to initialize hybrid signers", "error", err)
				os.Exit(1)
			}

			slog.Info("Hybrid signers initialized", "count", len(signers))
		} else {
			// Single signer mode (backwards compatible)
			var signerOpts []signerverifier.Option
			switch {
			case viper.GetString("signer-filepath") != "":
				signerOpts = []signerverifier.Option{signerverifier.WithFile(viper.GetString("signer-filepath"), viper.GetString("signer-password"))}
			case viper.GetString("signer-kmskey") != "":
				kmshash := viper.GetString("signer-kmshash")
				hashAlg, ok := hashAlgMap[kmshash]
				if !ok {
					slog.Error("invalid hash algorithm for --signer-kmshash", "algorithm", kmshash)
					os.Exit(1)
				}

				signerOpts = []signerverifier.Option{signerverifier.WithKMS(viper.GetString("signer-kmskey"), hashAlg)}
			case viper.GetString("signer-tink-kek-uri") != "":
				signerOpts = []signerverifier.Option{signerverifier.WithTink(viper.GetString("signer-tink-kek-uri"), viper.GetString("signer-tink-keyset-path"))}
			default:
				slog.Error("no signer configured; must provide a signer using a file, KMS, or Tink")
				os.Exit(1)
			}

			signer, err := signerverifier.New(ctx, signerOpts...)
			if err != nil {
				slog.Error("failed to initialize signer", "error", err)
				os.Exit(1)
			}
			signers = []signature.Signer{signer}
		}

		// Log all public keys for verification
		for i, signer := range signers {
			pubkey, err := signer.PublicKey()
			if err != nil {
				slog.Error("failed to get public key from signing key", "signer", i, "error", err)
				os.Exit(1)
			}
			der, err := cryptoutils.MarshalPublicKeyToDER(pubkey)
			if err != nil {
				slog.Error("failed to marshal public key to DER", "signer", i, "error", err)
				os.Exit(1)
			}
			slog.Info("Loaded signing key", "signer", i, "pubkey in base64 DER", base64.StdEncoding.EncodeToString(der))
		}

		// Create append options with signers (handles both single and hybrid modes)
		appendOptions, err := tessera.NewAppendOptionsMulti(ctx, viper.GetString("hostname"), signers)
		if err != nil {
			slog.Error("failed to initialize append options", "error", err)
			os.Exit(1)
		}

		// Compute log ID for TransparencyLogEntry, to be used by clients to look up
		// the correct instance in a trust root. Log ID is equivalent to the non-truncated
		// hash of the public key and origin per the signed-note C2SP spec.
		// Use the first signer's public key for backwards compatibility
		pubKey, err := signers[0].PublicKey(options.WithContext(ctx))
		if err != nil {
			slog.Error("failed to get public key", "error", err)
			os.Exit(1)
		}
		_, logID, err := note.KeyHash(viper.GetString("hostname"), pubKey)
		if err != nil {
			slog.Error("failed to get log ID", "error", err)
			os.Exit(1)
		}

		readOnly := viper.GetBool("read-only")
		var tesseraStorage tessera.Storage
		shutdownFn := func(_ context.Context) error { return nil }
		// if in read-only mode, don't start the appender, because we don't want new checkpoints being published.
		if !readOnly {
			driverConfig := awsDriver.DriverConfiguration{
				AWSBucket:           viper.GetString("aws-bucket"),
				AWSMySQLDSN:         viper.GetString("aws-mysql-dsn"),
				MaxOpenConns:        viper.GetInt("aws-max-open-conns"),
				MaxIdleConns:        viper.GetInt("aws-max-idle-conns"),
				PersistentAntispam:  viper.GetBool("persistent-antispam"),
				ASMaxBatchSize:      viper.GetUint("antispam-max-batch-size"),
				ASPushbackThreshold: viper.GetUint("antispam-pushback-threshold"),
			}
			tesseraDriver, persistentAntispam, err := awsDriver.NewDriver(ctx, driverConfig)
			if err != nil {
				slog.Error("failed to initialize driver", "error", err)
				os.Exit(1)
			}
			appendOptions = tessera.WithLifecycleOptions(appendOptions, viper.GetUint("batch-max-size"), viper.GetDuration("batch-max-age"), viper.GetDuration("checkpoint-interval"), viper.GetUint("pushback-max-outstanding"))
			appendOptions = tessera.WithAntispamOptions(appendOptions, persistentAntispam)
			if wpf := viper.GetString("witness-policy-path"); wpf != "" {
				f, err := os.ReadFile(wpf)
				if err != nil {
					slog.Error("failed to read witness policy file", "file", wpf, "error", err)
					os.Exit(1)
				}
				appendOptions, err = tessera.WithWitnessing(appendOptions, f)
				if err != nil {
					slog.Error("failed to initialize witnessing", "error", err)
					os.Exit(1)
				}
			}
			tesseraStorage, shutdownFn, err = tessera.NewStorage(ctx, viper.GetString("hostname"), tesseraDriver, appendOptions)
			if err != nil {
				slog.Error("failed to initialize tessera storage", "error", err)
				os.Exit(1)
			}
		}
		algorithmRegistry, err := algorithmregistry.AlgorithmRegistry(viper.GetStringSlice("client-signing-algorithms"))
		if err != nil {
			slog.Error("failed to get algorithm registry", "error", err)
			os.Exit(1)
		}

		rekorServer := server.NewServer(tesseraStorage, readOnly, algorithmRegistry, logID)

		server.Serve(
			ctx,
			server.NewHTTPConfig(
				server.WithHTTPPort(viper.GetInt("http-port")),
				server.WithHTTPHost(viper.GetString("http-address")),
				server.WithHTTPTimeout(viper.GetDuration("server-timeout")),
				server.WithHTTPMaxRequestBodySize(viper.GetInt("max-request-body-size")),
				server.WithHTTPMetricsPort(viper.GetInt("http-metrics-port")),
				server.WithHTTPTLSCredentials(viper.GetString("http-tls-cert-file"), viper.GetString("http-tls-key-file")),
				server.WithGRPCTLSCredentials(viper.GetString("grpc-tls-cert-file")),
			),
			server.NewGRPCConfig(
				server.WithGRPCPort(viper.GetInt("grpc-port")),
				server.WithGRPCHost(viper.GetString("grpc-address")),
				server.WithGRPCTimeout(viper.GetDuration("server-timeout")),
				server.WithGRPCMaxMessageSize(viper.GetInt("max-request-body-size")),
				server.WithGRPCLogLevel(logLevel, viper.GetBool("request-response-logging")),
				server.WithTLSCredentials(viper.GetString("grpc-tls-cert-file"), viper.GetString("grpc-tls-key-file")),
			),
			viper.GetDuration("tlog-timeout"),
			rekorServer,
			shutdownFn,
		)
	},
}

func init() {
	if err := cli.Initialize(serveCmd); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	// aws configs
	serveCmd.Flags().String("aws-bucket", "", "S3 bucket for tile and checkpoint storage")
	serveCmd.Flags().String("aws-mysql-dsn", "", "MySQL DSN for Aurora/RDS (e.g., user:pass@tcp(host:3306)/dbname)")
	serveCmd.Flags().Int("aws-max-open-conns", 0, "[optional] maximum number of connections to the MySQL database")
	serveCmd.Flags().Int("aws-max-idle-conns", 0, "[optional] maximum number of idle database connections in the connection pool")

	// checkpoint signing configs
	serveCmd.Flags().String("signer-filepath", "", "path to the signing key")
	serveCmd.Flags().String("signer-password", "", "password to decrypt the signing key")
	serveCmd.Flags().String("signer-kmskey", "", "URI of the KMS key, in the form of awskms://keyname")
	serveCmd.Flags().String("signer-kmshash", "sha256", "hash algorithm used by the KMS")
	serveCmd.Flags().String("signer-tink-kek-uri", "", "encryption key for decrypting Tink keyset, in the form aws-kms://keyname")
	serveCmd.Flags().String("signer-tink-keyset-path", "", "path to encrypted Tink keyset")
	// Hybrid signing configuration (multiple signers)
	serveCmd.Flags().StringSlice("signer-filepaths", []string{}, "paths to signing keys (for hybrid mode)")
	serveCmd.Flags().StringSlice("signer-passwords", []string{}, "passwords for signing keys (for hybrid mode)")
	serveCmd.Flags().StringSlice("signer-kmskeys", []string{}, "KMS key URIs (for hybrid mode)")
	serveCmd.Flags().StringSlice("signer-kmshashes", []string{}, "hash algorithms for KMS keys (for hybrid mode)")

	if err := viper.BindPFlags(serveCmd.Flags()); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	rootCmd.AddCommand(serveCmd)
}

var hashAlgMap = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}
