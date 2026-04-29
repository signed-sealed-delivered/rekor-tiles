//
// Copyright 2025 The Sigstore Authors.
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
	"fmt"
	"log/slog"
	"os"
	"time"

	clog "github.com/chainguard-dev/clog/gcp"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"k8s.io/klog/v2"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/release-utils/version"

	"github.com/sigstore/rekor-tiles/v2/internal/algorithmregistry"
	"github.com/sigstore/rekor-tiles/v2/internal/cli"
	"github.com/sigstore/rekor-tiles/v2/internal/server"
	"github.com/sigstore/rekor-tiles/v2/internal/signersetup"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera"
	gcpDriver "github.com/sigstore/rekor-tiles/v2/internal/tessera/gcp"
	"github.com/sigstore/rekor-tiles/v2/internal/tessera/gcp/signerverifier"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"
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
		slog.SetDefault(slog.New(clog.NewHandler(logLevel)))

		// tessera uses klog so pipe all klog messages to be written through slog
		klog.SetSlogLogger(slog.Default())

		slog.Info("starting rekor-server", "version", version.GetVersionInfo())

		// Parse signer configuration(s)
		var signers []signature.Signer
		var err error

		// GCP KMS RPC options (used for both hybrid and single signer modes)
		gcpKMSRPCOpts := make([]signature.RPCOption, 0)
		callOpts := []grpc_retry.CallOption{
			grpc_retry.WithMax(viper.GetUint("gcp-kms-retries")),
			grpc_retry.WithPerRetryTimeout(time.Duration(viper.GetUint32("gcp-kms-timeout")) * time.Second)}
		gcpKMSRPCOpts = append(gcpKMSRPCOpts, gcp.WithGoogleAPIClientOption(
			option.WithGRPCDialOption(grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(callOpts...)))))

		// GCP signer factory
		gcpSignerFactory := func(ctx context.Context, opts interface{}) (signature.Signer, error) {
			switch o := opts.(type) {
			case signersetup.FileSignerOpts:
				return signerverifier.New(ctx, signerverifier.WithFile(o.FilePath, o.Password))
			case signersetup.KMSSignerOpts:
				return signerverifier.New(ctx, signerverifier.WithKMS(o.KMSKey, o.HashAlg, gcpKMSRPCOpts))
			default:
				return nil, fmt.Errorf("unsupported signer options type: %T", opts)
			}
		}

		// Check for hybrid mode (multiple signers via slices)
		signerFilepaths := viper.GetStringSlice("signer-filepaths")
		signerKMSKeys := viper.GetStringSlice("signer-kmskeys")

		if len(signerFilepaths) > 0 || len(signerKMSKeys) > 0 {
			// Hybrid mode using common setup
			cfg := signersetup.Config{
				FilePaths:    signerFilepaths,
				Passwords:    viper.GetStringSlice("signer-passwords"),
				KMSKeys:      signerKMSKeys,
				KMSHashes:    viper.GetStringSlice("signer-kmshashes"),
				CreateSigner: gcpSignerFactory,
			}

			signers, err = signersetup.InitializeSigners(ctx, cfg)
			if err != nil {
				slog.Error("failed to initialize signers", "error", err)
				os.Exit(1)
			}
		} else {
			// Single signer mode (backwards compatible)
			var signerOpts []signerverifier.Option
			switch {
			case viper.GetString("signer-filepath") != "":
				signerOpts = []signerverifier.Option{
					signerverifier.WithFile(viper.GetString("signer-filepath"), viper.GetString("signer-password"))}
			case viper.GetString("signer-kmskey") != "":
				kmshash := viper.GetString("signer-kmshash")
				hashAlg, ok := signersetup.HashAlgMap[kmshash]
				if !ok {
					slog.Error("invalid hash algorithm for --signer-kmshash", "algorithm", kmshash)
					os.Exit(1)
				}
				signerOpts = []signerverifier.Option{
					signerverifier.WithKMS(viper.GetString("signer-kmskey"), hashAlg, gcpKMSRPCOpts)}
			case viper.GetString("signer-tink-kek-uri") != "":
				signerOpts = []signerverifier.Option{
					signerverifier.WithTink(viper.GetString("signer-tink-kek-uri"), viper.GetString("signer-tink-keyset-path"))}
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

		// Log all public keys for verification (GCP uses type logging)
		if err := signersetup.LogPublicKeyTypes(signers); err != nil {
			slog.Error("failed to log public keys", "error", err)
			os.Exit(1)
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
			driverConfig := gcpDriver.DriverConfiguration{
				Hostname:            viper.GetString("hostname"),
				GCPBucket:           viper.GetString("gcp-bucket"),
				GCPSpannerDB:        viper.GetString("gcp-spanner"),
				PersistentAntispam:  viper.GetBool("persistent-antispam"),
				ASMaxBatchSize:      viper.GetUint("antispam-max-batch-size"),
				ASPushbackThreshold: viper.GetUint("antispam-pushback-threshold"),
			}
			tesseraDriver, persistentAntispam, err := gcpDriver.NewDriver(ctx, driverConfig)
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
				server.WithGCPSupport(true),
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

	// gcp configs
	serveCmd.Flags().String("gcp-bucket", "", "GCS bucket for tile and checkpoint storage")
	serveCmd.Flags().String("gcp-spanner", "", "Spanner database URI")

	// checkpoint signing configs
	serveCmd.Flags().String("signer-filepath", "", "path to the signing key")
	serveCmd.Flags().String("signer-password", "", "password to decrypt the signing key")
	serveCmd.Flags().String("signer-kmskey", "", "URI of the KMS key, in the form of gcpkms://keyname")
	serveCmd.Flags().String("signer-kmshash", "sha256", "hash algorithm used by the KMS")
	serveCmd.Flags().String("signer-tink-kek-uri", "", "encryption key for decrypting Tink keyset, in the form gcp-kms://keyname")
	serveCmd.Flags().String("signer-tink-keyset-path", "", "path to encrypted Tink keyset")
	serveCmd.Flags().Uint("gcp-kms-retries", 0, "number of retries for GCP KMS requests")
	serveCmd.Flags().Uint32("gcp-kms-timeout", 0, "sets the RPC timeout per call for GCP KMS requests in seconds, defaults to 0 (no timeout)")
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
