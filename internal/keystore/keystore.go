// Package keystore holds this Client's private keys.
//
// Keys are stored unencrypted. Filesystem permissions are the whole of their
// protection, so anyone who is root on this host, or who holds a backup or disk
// image of it, holds the keys. That limit is stated rather than left implied by
// the word "keystore": encryption in easySSL exists to hand the Server a copy it
// cannot read, and never to protect local disk, because a Client renews and
// deploys unattended and any key that unlocked its own keystore would have to
// sit on the same disk.
//
// Nothing here removes key material. There is no Delete, no Purge and no
// pruning, so the keystore only grows and reclaiming it is an operator's manual
// act. Deleting a key is the one operation with no recovery, which is why the
// code to do it is absent rather than guarded by a flag.
//
// A key is named by its own public-key fingerprint and each certificate gets a
// small record naming the key it uses:
//
//	<base>/keys/<fingerprint>.key    PKCS#8 PEM, ECDSA P-256
//	<base>/certs/<certificate>.json  names the key that certificate uses
//
// Naming the key after itself rather than after a certificate is what lets one
// key serve several certificates later without the secret being copied, and it
// makes the directory self-checking, since a key file's name is derivable from
// its contents.
package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/easyssl-io/easyssl-client/internal/identity"
)

// baseDir is where the keystore lives. A variable rather than a constant only so
// tests can point it at a temporary directory; nothing else reassigns it.
var baseDir = identity.BaseDir

// dirMode and keyMode are the whole of the at-rest protection, so they are
// written once here and never recomputed at a call site.
const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

func keysDir() string  { return filepath.Join(baseDir, "keys") }
func certsDir() string { return filepath.Join(baseDir, "certs") }

// log is where this package writes. SetLogger points it at the Client's own
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
		return errors.New("keystore: must run as root: private keys are stored root-only, and a key written by another user would not have the protection this Client documents")
	}
	return nil
}

// record is what a certificate stores about the key it uses.
//
// CertificateID repeats the filename deliberately. It costs one field and turns
// a record that was moved, restored from the wrong backup, or crossed with
// another certificate's, from a silent mix-up into a detectable one. The
// filename is authoritative and a disagreement is refused rather than resolved.
type record struct {
	CertificateID  string    `json:"certificateId"`
	KeyFingerprint string    `json:"keyFingerprint"`
	CreatedAt      time.Time `json:"createdAt"`
}

// Ensure returns the key certificateID uses, generating and recording one if
// this host has none for it yet.
//
// Calling it again for the same certificate returns the same key. That is the
// requirement rather than an optimization: the Server delivers a command at
// least once, so a Client that built a CSR and died before acknowledging it will
// be handed the same request again. Generating afresh on the second run would
// leave the Server holding a CSR for a key that no longer exists, and the
// certificate issued from it would be unusable by the host that asked for it.
//
// A fresh key per renewal falls out of the same design rather than from separate
// code, because a renewal is a different certificate record and therefore an id
// this host holds no key for.
func Ensure(certificateID string) (*ecdsa.PrivateKey, error) {
	id, err := canonicalCertificateID(certificateID)
	if err != nil {
		return nil, err
	}
	if err := requireRoot(); err != nil {
		return nil, err
	}

	rec, found, err := readRecord(id)
	if err != nil {
		return nil, err
	}
	if found {
		return loadKey(rec.KeyFingerprint)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keystore: generating key: %w", err)
	}
	fp, err := fingerprint(key.Public())
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("keystore: encoding key: %w", err)
	}

	// The key becomes durable before the record that names it. The failure
	// between the two has to be the harmless one: a key nothing refers to costs
	// a file on a host that keeps every key anyway, while a record naming a key
	// that does not exist is a dangling reference this Client cannot repair,
	// because it cannot know whether the missing key was already used for a CSR.
	if err := writeFile(keysDir(), fp+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(record{CertificateID: id, KeyFingerprint: fp, CreatedAt: time.Now().UTC()}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFile(certsDir(), id+".json", append(body, '\n')); err != nil {
		return nil, err
	}

	logger().Info("private key generated", "certificate", id, "key", fp)
	return key, nil
}

// CSR builds a certificate signing request from key.
//
// Built on each call and never stored, so it cannot come to disagree with the
// key it belongs to.
func CSR(key *ecdsa.PrivateKey, primaryName string, domains []string) ([]byte, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: primaryName},
		DNSNames:           domains,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("keystore: building CSR: %w", err)
	}
	return csr, nil
}

// Dir names where key material lives, for messages that have to tell an operator
// what is on their host. The keys are in it; the records naming them are beside
// it, and both survive an uninstall.
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

// readRecord returns the record for a certificate, or found=false when this host
// has none. A record that exists but disagrees with its own filename is an
// error: the two values are equally plausible, and choosing either one would
// return a key belonging to some other certificate.
func readRecord(id string) (record, bool, error) {
	path := filepath.Join(certsDir(), id+".json")
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return record{}, false, nil
	}
	if err != nil {
		return record{}, false, err
	}
	var rec record
	if err := json.Unmarshal(body, &rec); err != nil {
		return record{}, false, fmt.Errorf("keystore: %s is not readable: %w", path, err)
	}
	if rec.CertificateID != id {
		return record{}, false, fmt.Errorf(
			"keystore: %s records certificate %q; the two disagree and neither can be assumed correct", path, rec.CertificateID)
	}
	if err := validateKeyID(rec.KeyFingerprint); err != nil {
		return record{}, false, fmt.Errorf("keystore: %s: %w", path, err)
	}
	return rec, true, nil
}

// loadKey reads the key with the given fingerprint and checks that it is in fact
// that key.
//
// A missing file is an error and never a reason to generate a replacement.
// Nothing in this package removes a key, so the file is absent because something
// outside it did, which an operator needs to know; and if the missing key had
// already been used for a CSR, generating another would leave the issued
// certificate matching a key this host no longer has.
func loadKey(fp string) (*ecdsa.PrivateKey, error) {
	if err := validateKeyID(fp); err != nil {
		return nil, err
	}
	path := filepath.Join(keysDir(), fp+".key")
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("keystore: %s is named by a certificate record but does not exist", path)
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
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keystore: %s holds a %T, not an ECDSA key", path, parsed)
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
// The temporary file is created inside the destination directory with its final
// permissions, because os.CreateTemp opens at 0600 and setting the mode
// afterwards would leave a window in which the file is readable by others. Both
// syncs are required rather than cautious: the rename is what makes the write
// atomic, and the two flushes are what make it survive a power loss.
func writeFile(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
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

// canonicalCertificateID accepts a UUID and returns it in lowercase.
//
// This runs before the value reaches a path, and it is a security control
// rather than input hygiene: the id arrives from the Server, filepath.Join
// resolves ".." instead of refusing it, and this process runs as root, so an
// unchecked value would let whoever sent it choose where a private key is
// written. Lowercasing matters separately, because two spellings of one id would
// otherwise produce two records and two keys for a single certificate.
func canonicalCertificateID(id string) (string, error) {
	const layout = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	if len(id) != len(layout) {
		return "", fmt.Errorf("keystore: certificate id %q is not a UUID", id)
	}
	out := make([]byte, len(id))
	for i := 0; i < len(id); i++ {
		c := lower(id[i])
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "", fmt.Errorf("keystore: certificate id %q is not a UUID", id)
			}
		default:
			if !isHex(c) {
				return "", fmt.Errorf("keystore: certificate id %q is not a UUID", id)
			}
		}
		out[i] = c
	}
	return string(out), nil
}

// validateKeyID accepts a key fingerprint: 64 lowercase hex characters. It reads
// values out of files on disk rather than off the wire, and checks them for the
// same reason as above, since a file is no more trustworthy than the thing that
// last wrote it.
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
