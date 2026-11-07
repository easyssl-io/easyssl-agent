// Package csr answers the Server's request_csr commands: it has the keystore
// produce a key or load the one the Server named, builds the CSR and hands it
// back. The Agent is told what to sign and with which key, and chooses nothing.
//
// An error return leaves the command pending, so the Runner tries again and, if
// the condition never clears, the command's expiry fails the Certificate naming
// this Agent. A nil return acks the command. Terminal refusals from the Server
// (already submitted, stale, rejected) are therefore nil: retrying cannot
// change them, and the Server has already recorded what it thinks. Work this
// Agent cannot do returns commands.ErrUnsupported, which fails the Certificate
// at once.
package csr

import (
	"context"
	"crypto"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/easyssl-io/easyssl-contract/wire"

	"github.com/easyssl-io/easyssl-agent/internal/commands"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
)

// API is the slice of the Server wrapper this handler uses, so a test can stand
// in for the Server.
type API interface {
	CSRWork(ctx context.Context, token, certificateID string) (wire.CSRWork, error)
	SubmitCSR(ctx context.Context, token, certificateID, csrPEM string) error
}

var _ API = (*serverapi.Client)(nil)

// generateKey and loadKey are keystore.Generate and keystore.Load, indirected
// only so tests can supply in-memory keys: both require root and a real
// filesystem. CSR building stays the real keystore code either way.
var (
	generateKey = keystore.Generate
	loadKey     = keystore.Load
)

// New returns the handler for wire.CommandRequestCSR.
func New(api API, token string, logger *slog.Logger) commands.Handler {
	return func(ctx context.Context, cmd wire.Command) error {
		work, err := api.CSRWork(ctx, token, cmd.RefID)
		if err != nil {
			var apiErr *serverapi.APIError
			if errors.As(err, &apiErr) && apiErr.Code == wire.CodeCertificateNotFound {
				// Not this Agent's, or gone, which no retry changes: a stale
				// instruction, discarded and acked. Only this code says so; any other
				// 404, such as a proxy's, is retried.
				logger.Warn("csr work not found; discarding command", "certificate", cmd.RefID)
				return nil
			}
			return err // transport or Server trouble: leave pending, retry later
		}
		if !wire.ValidKeyType(work.KeyType) {
			return fmt.Errorf("csr: key type %q: %w", work.KeyType, commands.ErrUnsupported)
		}
		if len(work.Domains) == 0 {
			return fmt.Errorf("csr: the work names no domains: %w", commands.ErrUnsupported)
		}

		key, err := keyFor(work)
		if err != nil {
			// Keystore refusals are environmental (permissions, inconsistent state, a
			// named key this host does not hold) and worth retrying only until the
			// command expires, which fails the certificate naming this Agent. A key that
			// is not here is never replaced by a fresh one: the Server named it because
			// a certificate is to be issued from it, and a CSR from any other key would
			// be rejected anyway.
			logger.Error("csr work cannot be answered", "certificate", cmd.RefID, "err", err)
			return fmt.Errorf("csr: %w", err)
		}
		csrPEM, err := buildPEM(key, work.Domains)
		if err != nil {
			return err
		}

		err = api.SubmitCSR(ctx, token, cmd.RefID, csrPEM)
		var apiErr *serverapi.APIError
		switch {
		case err == nil:
			logger.Info("csr submitted", "certificate", cmd.RefID)
			return nil
		case errors.As(err, &apiErr) && apiErr.Code == wire.CodeCSRAlreadySubmitted:
			// Success from an earlier run this Agent cannot recognize
			// byte-wise; the work named the stored CSR's key, so this build
			// was from the same key and there is nothing left to do.
			logger.Info("csr already submitted", "certificate", cmd.RefID)
			return nil
		case errors.As(err, &apiErr) && apiErr.Code == wire.CodeNotAwaitingCSR:
			logger.Warn("certificate no longer awaiting a csr; discarding command", "certificate", cmd.RefID)
			return nil
		case errors.As(err, &apiErr) && apiErr.Code == wire.CodeCSRMismatch:
			// The Server rejected what this Agent built and failed the certificate,
			// naming this Agent. Retrying the same build cannot help, so the command is
			// acked.
			logger.Error("server rejected the csr", "certificate", cmd.RefID, "err", err)
			return nil
		default:
			return err // transport or Server trouble: leave pending, retry later
		}
	}
}

// keyFor returns the key the work names, or a fresh one when it names none.
func keyFor(work wire.CSRWork) (crypto.Signer, error) {
	if work.KeySPKISHA256 != "" {
		return loadKey(work.KeySPKISHA256)
	}
	_, key, err := generateKey(work.KeyType)
	return key, err
}

// buildPEM builds the CSR (keystore.CSR: SANs only, no Common Name) and
// PEM-encodes it for the wire.
func buildPEM(key crypto.Signer, domains []string) (string, error) {
	der, err := keystore.CSR(key, domains)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}
