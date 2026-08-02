// Package csr answers the Server's request_csr commands: read what to sign,
// have the keystore produce or reuse the certificate's key, build the CSR, and
// hand it back. The Client is told what to sign and chooses nothing.
//
// Every outcome here is deliberate about one distinction: an error return
// leaves the command pending, so the Runner tries again later and, if the
// condition never clears, the command's expiry fails the certificate naming
// this Client. A nil return acks the command as handled. Terminal refusals from
// the Server (already submitted, stale, rejected) are therefore nil: retrying
// the same submission cannot change them, and the Server has already recorded
// what it thinks.
package csr

import (
	"context"
	"crypto/ecdsa"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/easyssl-io/easyssl-contract/wire"

	"github.com/easyssl-io/easyssl-client/internal/commands"
	"github.com/easyssl-io/easyssl-client/internal/keystore"
	"github.com/easyssl-io/easyssl-client/internal/serverapi"
)

// API is the slice of the Server wrapper this handler uses, narrowed so a test
// can stand in for the Server. The real implementation is *serverapi.Client,
// the Client's single HTTP path.
type API interface {
	CSRWork(ctx context.Context, token, certificateID string) (wire.CSRWork, error)
	SubmitCSR(ctx context.Context, token, certificateID, csrPEM string) error
}

var _ API = (*serverapi.Client)(nil)

// ensureKey is keystore.Ensure, indirected only so tests can supply an
// in-memory key: Ensure requires root and a real filesystem, which is its job,
// not this handler's. CSR building stays the real keystore code either way.
var ensureKey = keystore.Ensure

// New returns the handler for wire.CommandRequestCSR.
func New(api API, token string, logger *slog.Logger) commands.Handler {
	return func(ctx context.Context, cmd wire.Command) error {
		work, err := api.CSRWork(ctx, token, cmd.RefID)
		if err != nil {
			var apiErr *serverapi.APIError
			if errors.As(err, &apiErr) && apiErr.Status == 404 {
				// Unknown here means "not this Client's or gone", which no
				// retry changes: a stale instruction, discarded and acked.
				logger.Warn("csr work not found; discarding command", "certificate", cmd.RefID)
				return nil
			}
			return err // transport or Server trouble: leave pending, retry later
		}
		if work.KeyType != wire.KeyTypeECP256 {
			// A key type this Client cannot generate: it is older than its
			// Server. Acked as handled; the certificate keeps waiting and the
			// command's expiry reports the failure naming this Client.
			logger.Error("csr work asks for a key type this Client cannot generate",
				"certificate", cmd.RefID, "keyType", work.KeyType)
			return nil
		}
		if len(work.Domains) == 0 {
			logger.Error("csr work carries no domains; discarding command", "certificate", cmd.RefID)
			return nil
		}

		key, err := ensureKey(work.CertificateID)
		if err != nil {
			// Keystore refusals are environmental (permissions, inconsistent
			// state) and worth retrying only until the command expires; the
			// expiry is the clock on this wait by design.
			return fmt.Errorf("csr: %w", err)
		}
		csrPEM, err := buildPEM(key, work.Domains)
		if err != nil {
			return err
		}

		err = api.SubmitCSR(ctx, token, work.CertificateID, csrPEM)
		var apiErr *serverapi.APIError
		switch {
		case err == nil:
			logger.Info("csr submitted", "certificate", work.CertificateID)
			return nil
		case errors.As(err, &apiErr) && apiErr.Code == wire.CodeCSRAlreadySubmitted:
			// Success from an earlier run this Client cannot recognize
			// byte-wise; the stored CSR is from the same key (idempotent
			// generation), so there is nothing left to do.
			logger.Info("csr already submitted", "certificate", work.CertificateID)
			return nil
		case errors.As(err, &apiErr) && apiErr.Code == wire.CodeNotAwaitingCSR:
			logger.Warn("certificate no longer awaiting a csr; discarding command", "certificate", work.CertificateID)
			return nil
		case errors.As(err, &apiErr) && apiErr.Code == wire.CodeCSRMismatch:
			// The Server rejected what this Client built. Retrying the same
			// build cannot help, so the refusal is recorded here and the
			// command acked; the Server keeps the certificate waiting.
			logger.Error("server rejected the csr", "certificate", work.CertificateID, "err", err)
			return nil
		default:
			return err // transport or Server trouble: leave pending, retry later
		}
	}
}

// buildPEM builds the CSR (keystore.CSR: SANs only, no Common Name) and
// PEM-encodes it for the wire.
func buildPEM(key *ecdsa.PrivateKey, domains []string) (string, error) {
	der, err := keystore.CSR(key, domains)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}
