// Package keystore holds this Agent's private keys.
//
// Keys are stored unencrypted. Filesystem permissions are the whole of their
// protection, so anyone who is root on this host, or who holds a backup or disk
// image of it, holds the keys. That limit is stated rather than left implied by
// the word "keystore": encryption in easySSL exists to hand the Server a copy it
// cannot read, and never to protect local disk, because an Agent renews and
// deploys unattended and any key that unlocked its own keystore would have to
// sit on the same disk.
//
// Nothing here removes key material. There is no Delete, no Purge and no
// pruning, so the keystore only grows and reclaiming it is an operator's manual
// act. Deleting a key is the one operation with no recovery, which is why the
// code to do it is absent rather than guarded by a flag.
//
// A key is named by its own public-key fingerprint, and that is the whole of
// what the keystore holds:
//
//	<base>/keys/<fingerprint>.key    PKCS#8 PEM, any wire.KeyTypes type
//
// Which certificate uses which key is the Server's record, taken from the
// public key of each CSR it accepts, and every command that touches a key
// names it by fingerprint. A copy of that link on the host would be Server
// state cached where it goes stale. Naming the key after itself is what lets
// one key serve several certificates without the secret being copied, and it
// makes the directory self-checking, since a key file's name is derivable from
// its contents.
package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/easyssl-io/easyssl-agent/internal/identity"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// baseDir is where the keystore lives. A variable rather than a constant only so
// tests can point it at a temporary directory; nothing else reassigns it.
var baseDir = identity.BaseDir

// dirMode and fileMode are the whole of the at-rest protection, so they are
// named once here and passed explicitly wherever something is created. Nothing
// in this package relies on a default mode from elsewhere: a permission a
// requirement depends on should be visible in the code that applies it.
const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

func keysDir() string { return filepath.Join(baseDir, "keys") }

// log is where this package writes. SetLogger points it at the Agent's own
// handler so keystore lines match every other line the service emits; until
// then it is the default, which keeps a package used before wiring from being
// silent.
var log = slog.Default()

// SetLogger routes this package's output through the caller's logger.
func SetLogger(l *slog.Logger) {
	if l != nil {
		log = l
	}
}

func logger() *slog.Logger { return log }

// requireRoot refuses a caller that cannot own what it is about to write.
//
// The permissions in this package are the whole of the at-rest protection, and
// they only mean anything if root owns the files: a key written by some other
// user is 0600 to that user, which is not the guarantee documented to operators.
// Checking here rather than only in the install and uninstall commands matters
// because the long-running service does not check, and that is the path the
// Server's requests arrive on.
// euid is os.Geteuid, indirected only so the tests can exercise both sides of
// the check without running as root.
var euid = os.Geteuid

func requireRoot() error {
	if euid() != 0 {
		return msg.Err.T("keystore.not_root", "keystore: must run as root: private keys are stored root-only, and a key written by another user would not have the protection this Agent documents")
	}
	return nil
}

// Generate creates a fresh key, stores it, and returns it with its fingerprint,
// which is the name the Server will know it by.
//
// Nothing here is idempotent per certificate, and nothing here knows what a
// certificate is: a request that names no key gets a new one on every run. An
// Agent that generated a key, died before the CSR reached the Server, and is
// handed the same request again therefore generates afresh, and the first key
// is an orphan. That is accepted: nothing was signed with it, it costs one
// file on a host that keeps every key anyway, and the host inventory lists it
// as a key no certificate names. Once a CSR is stored the Server names its key
// on every re-run, so a key that was used is never generated past.
func Generate(keyType string) (string, crypto.Signer, error) {
	if err := requireRoot(); err != nil {
		return "", nil, err
	}
	key, err := newKey(keyType)
	if err != nil {
		return "", nil, fmt.Errorf("keystore: generating key: %w", err)
	}
	fp, err := fingerprint(key.Public())
	if err != nil {
		return "", nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", nil, fmt.Errorf("keystore: encoding key: %w", err)
	}
	// Durable before it is returned: the caller builds a CSR from it next,
	// and a CSR the Server has for a key a power loss took is a certificate
	// this host can never install.
	if err := writeFile(keysDir(), fp+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return "", nil, err
	}
	logger().Info("private key generated", "key", fp)
	return fp, key, nil
}

// newKey generates a key of one of wire.KeyTypes.
func newKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case wire.KeyTypeECP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case wire.KeyTypeECP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case wire.KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case wire.KeyTypeRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case wire.KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("keystore: key type %q is not one this Agent generates", keyType)
}

// signatureAlgorithm is what a CSR from key is signed with: SHA-384 for P-384,
// whose strength SHA-256 would undercut, and SHA-256 otherwise.
func signatureAlgorithm(key crypto.Signer) x509.SignatureAlgorithm {
	switch wire.KeyTypeOf(key.Public()) {
	case wire.KeyTypeECP256:
		return x509.ECDSAWithSHA256
	case wire.KeyTypeECP384:
		return x509.ECDSAWithSHA384
	}
	return x509.SHA256WithRSA
}

// CSR builds a certificate signing request from key, for the domains it is
// given. It never chooses them: the caller is told what to sign.
//
// Built on each call and never stored, so it cannot come to disagree with the
// key it belongs to.
//
// No Subject Common Name is set, deliberately. An ACME client reads the names to
// order from the CSR, taking the Common Name first and then every SAN, so a
// Common Name is either a duplicate of a SAN or a name nobody asked for, and the
// second of those would put an unrequested name on the certificate.
func CSR(key crypto.Signer, domains []string) ([]byte, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames:           domains,
		SignatureAlgorithm: signatureAlgorithm(key),
	}, key)
	if err != nil {
		return nil, fmt.Errorf("keystore: building CSR: %w", err)
	}
	return csr, nil
}

// Dir names where key material lives, for messages that have to tell an operator
// what is on their host. It survives an uninstall.
func Dir() string { return keysDir() }

// Count reports how many keys this host holds, for the uninstall notice.
func Count() (int, error) {
	entries, err := os.ReadDir(keysDir())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".key" {
			n++
		}
	}
	return n, nil
}

// List reports every key this host holds, by its public half, for the host
// inventory: fingerprint, algorithm and when the file was created. Never the
// key. A file that does not parse or whose content does not match its name is
// logged and left out rather than listed as usable, since the inventory is
// what the Server offers for reuse; a directory that cannot be read at all is
// an error, so the caller sends no inventory rather than one saying the host
// holds nothing.
func List() ([]wire.KeyInfo, error) {
	if err := requireRoot(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(keysDir())
	if errors.Is(err, os.ErrNotExist) {
		return []wire.KeyInfo{}, nil
	}
	if err != nil {
		return nil, msg.Err.T("keystore.list_failed", "keystore: listing keys: {err}", "err", err)
	}
	keys := make([]wire.KeyInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".key" {
			continue
		}
		fp := strings.TrimSuffix(e.Name(), ".key")
		key, err := loadKey(fp)
		if err != nil {
			logger().Warn("key left out of the inventory", "file", e.Name(), "err", err)
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("keystore: %s: %w", e.Name(), err)
		}
		// Never modified after creation (a key is written once), so the
		// modification time is the creation time on every filesystem.
		keys = append(keys, wire.KeyInfo{Fingerprint: fp, Algorithm: wire.KeyTypeOf(key.Public()), CreatedAt: info.ModTime().UTC()})
	}
	return keys, nil
}

// loadKey reads the key with the given fingerprint and checks that it is in fact
// that key.
//
// A missing file is ErrNoKey and never a reason to generate a replacement.
// Nothing in this package removes a key, so the file is absent because
// something outside it did, or because this host never held it, and either is
// a fact to report: a key generated in its place would not match whatever the
// Server named it for.
func loadKey(fp string) (crypto.Signer, error) {
	if err := validateKeyID(fp); err != nil {
		return nil, err
	}
	path := filepath.Join(keysDir(), fp+".key")
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("keystore: %s: %w", path, ErrNoKey)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("keystore: %s is not a PKCS#8 PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keystore: %s cannot be parsed: %w", path, err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok || wire.KeyTypeOf(key.Public()) == "" {
		return nil, fmt.Errorf("keystore: %s holds a %T, not a key of any type a Certificate uses", path, parsed)
	}
	got, err := fingerprint(key.Public())
	if err != nil {
		return nil, err
	}
	if got != fp {
		return nil, fmt.Errorf("keystore: %s holds the key for %s; the file has been replaced or misnamed", path, got)
	}
	return key, nil
}

// fingerprint is a key's name on disk: the SHA-256 of its DER
// SubjectPublicKeyInfo, which is the standard public-key pin, is derivable from
// the file, and is public, so the Server can record which key a certificate uses
// without ever seeing key material.
func fingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("keystore: encoding public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// writeFile puts data at dir/name so that a reader sees either nothing or a
// complete file, and so that a crash cannot lose what a CSR was built from.
//
// The temporary file is created inside the destination directory, and at its
// final permissions rather than adjusted afterwards, which would leave a window
// in which the file is readable by others. It is opened with O_EXCL under a
// random name, so it cannot collide with or reuse anything already there. Both
// syncs are required rather than cautious: the rename is what makes the write
// atomic, and the two flushes are what make it survive a power loss.
func writeFile(dir, name string, data []byte) error {
	if err := mkdirAllSynced(dir); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // a no-op once the rename below has succeeded

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}

// mkdirAllSynced creates dir, and makes every directory it had to create durable
// by syncing the parent that now holds that entry.
//
// Syncing a directory makes the entries inside it durable, not the directory
// itself, so creating <base>/keys and then syncing only <base>/keys leaves the
// "keys" entry in <base> unflushed. A power loss in that window can take the
// whole directory while the record naming a key inside it survives, which is
// the dangling reference the key-before-record ordering exists to prevent. That
// window is narrow, since it is only the first write after an install, but it
// is exactly the state this package refuses to repair.
//
// A directory that already exists needs nothing: its entry was made durable
// when it was created, or it predates this Agent.
func mkdirAllSynced(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := mkdirAllSynced(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, dirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return syncDir(parent)
}

// syncDir flushes a directory entry, so the renamed file is still there after a
// power loss rather than only its contents having been written.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// validateKeyID accepts a key fingerprint: 64 lowercase hex characters.
//
// This runs before the value reaches a path, and it is a security control
// rather than input hygiene: the fingerprint arrives from the Server in a
// request_csr or a Deployment, filepath.Join resolves ".." instead of refusing
// it, and this process runs as root, so an unchecked value would let whoever
// sent it choose which file is read as a private key. The exact shape is
// enforced, not merely "no path characters", because a looser check invites
// two spellings of one key, and the name on disk has exactly one.
func validateKeyID(fp string) error {
	if len(fp) != sha256.Size*2 {
		return fmt.Errorf("keystore: key id %q is not a SHA-256 fingerprint", fp)
	}
	for i := 0; i < len(fp); i++ {
		if !isHex(fp[i]) || fp[i] != lower(fp[i]) {
			return fmt.Errorf("keystore: key id %q is not a SHA-256 fingerprint", fp)
		}
	}
	return nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// ErrNoKey reports that this host holds no key under the named fingerprint. It
// is a distinct error because every caller has to answer it the same way,
// by reporting rather than generating: the Server named that key because a
// certificate was, or is to be, issued from it, and a key generated in its
// place would match nothing.
var ErrNoKey = errors.New("keystore: this host holds no key under that fingerprint")

// Load returns the key the Server named, or ErrNoKey when this host has none
// under that fingerprint. It never generates.
func Load(fingerprint string) (crypto.Signer, error) {
	if err := validateKeyID(fingerprint); err != nil {
		return nil, err
	}
	if err := requireRoot(); err != nil {
		return nil, err
	}
	return loadKey(fingerprint)
}

// EncodePrivateKeyPEM renders a key as PKCS#8 PEM, the form a Plugin receives
// it in. It never touches disk: the material goes over a pipe to the Plugin,
// which writes it where it needs to and removes it.
func EncodePrivateKeyPEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("keystore: encoding key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
