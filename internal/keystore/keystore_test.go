// These tests are in the keystore package rather than beside it so they can
// point baseDir at a temporary directory. They run unprivileged, which is the
// one thing they cannot check: the files must also be root-owned, and only a run
// on a real host can confirm that.
package keystore

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	certA = "9f1c8e2a-4b73-4d51-9a0e-6c2f1b8d7e35"
	certB = "2d5a7c11-8e42-4f09-b6c3-a71e05d94f88"
)

// withTempBase points the keystore at a directory this test owns, and reports
// the process as root. These tests run unprivileged, so the check has to be
// stood in for; TestNonRootIsRefused covers the other side of it.
func withTempBase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldBase, oldEuid := baseDir, euid
	baseDir, euid = dir, func() int { return 0 }
	t.Cleanup(func() { baseDir, euid = oldBase, oldEuid })
	return dir
}

// TestNonRootIsRefused: the permissions are the whole of the at-rest
// protection, and they mean nothing unless root owns the files, since a key
// written by another user is 0600 to that user. The service does not check
// euid, so this is the only check on the path the Server's requests arrive on.
func TestNonRootIsRefused(t *testing.T) {
	base := withTempBase(t)
	euid = func() int { return 1000 }

	if _, err := Ensure(certA); err == nil {
		t.Fatal("a non-root caller was allowed to write a private key")
	}
	if n := countFiles(t, filepath.Join(base, "keys")); n != 0 {
		t.Error("a key was written despite the caller not being root")
	}
}

// TestLayoutAndPermissions: the permissions are the entire at-rest protection,
// so they are asserted rather than assumed, and a key file's name is
// checked against its own contents, which is what makes the directory
// self-verifying.
func TestLayoutAndPermissions(t *testing.T) {
	base := withTempBase(t)

	key, err := Ensure(certA)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	for _, dir := range []string{filepath.Join(base, "keys"), filepath.Join(base, "certs")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s mode = %o, want 700", dir, got)
		}
	}

	want, err := fingerprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(base, "keys", want+".key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("the key is not named after its own public key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("%s mode = %o, want 600", keyPath, got)
	}

	// The name must be derivable from the contents, not merely consistent with
	// whatever the writer chose to call it.
	body, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fingerprintOfPEM(t, body); got != want {
		t.Errorf("key file contents hash to %s but the file is named %s", got, want)
	}

	var rec record
	readJSON(t, filepath.Join(base, "certs", certA+".json"), &rec)
	if rec.CertificateID != certA {
		t.Errorf("record certificateId = %q, want %q", rec.CertificateID, certA)
	}
	if rec.KeyFingerprint != want {
		t.Errorf("record keyFingerprint = %q, want %q", rec.KeyFingerprint, want)
	}
	if rec.CreatedAt.IsZero() {
		t.Error("record createdAt is unset")
	}
}

// TestEnsureIsIdempotentAndPerCertificate covers both halves of the identity
// rule. Asking twice for one certificate must return one key, which is
// what stops a re-delivered request from leaving a certificate matched to a key
// the host no longer has. Asking for a different certificate must produce a
// different key, and since a renewal is a new certificate record, this is the
// only check that a renewal gets a fresh key.
func TestEnsureIsIdempotentAndPerCertificate(t *testing.T) {
	base := withTempBase(t)

	first, err := Ensure(certA)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	again, err := Ensure(certA)
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if !first.Equal(again) {
		t.Error("asking twice for one certificate returned two different keys")
	}
	if n := countFiles(t, filepath.Join(base, "keys")); n != 1 {
		t.Errorf("keys after two calls for one certificate = %d, want 1", n)
	}
	if n := countFiles(t, filepath.Join(base, "certs")); n != 1 {
		t.Errorf("records after two calls for one certificate = %d, want 1", n)
	}

	other, err := Ensure(certB)
	if err != nil {
		t.Fatalf("Ensure other: %v", err)
	}
	if first.Equal(other) {
		t.Error("a second certificate reused the first certificate's key")
	}
	if n := countFiles(t, filepath.Join(base, "keys")); n != 2 {
		t.Errorf("keys after a second certificate = %d, want 2", n)
	}

	// Case is not a second identity: ids are canonicalized, so the uppercase
	// spelling must find the key the lowercase one created rather than make one.
	upper, err := Ensure(strings.ToUpper(certA))
	if err != nil {
		t.Fatalf("Ensure uppercase: %v", err)
	}
	if !first.Equal(upper) {
		t.Error("an uppercase certificate id produced a second key")
	}
}

// TestCSRMatchesStoredKey: a CSR that merely parses shows only that it is
// internally consistent. What matters is that it belongs to the key on this
// host, because a mismatch yields a certificate its own host cannot serve.
func TestCSRMatchesStoredKey(t *testing.T) {
	withTempBase(t)

	key, err := Ensure(certA)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	der, err := CSR(key, "example.test", []string{"example.test", "www.example.test"})
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CSR carries a %T, not an ECDSA public key", csr.PublicKey)
	}
	if !key.PublicKey.Equal(pub) {
		t.Error("the CSR does not carry the stored key's public half")
	}
	if csr.Subject.CommonName != "example.test" {
		t.Errorf("CSR subject CN = %q, want example.test", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("CSR DNS names = %v, want both domains", csr.DNSNames)
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("CSR signature algorithm = %v, want ECDSAWithSHA256", csr.SignatureAlgorithm)
	}
}

// TestMalformedIdentifierIsRefused: the id arrives from the Server and
// filepath.Join resolves ".." rather than refusing it, so without the check a
// Server could choose where this root process writes key material.
func TestMalformedIdentifierIsRefused(t *testing.T) {
	base := withTempBase(t)

	for _, id := range []string{
		"../../etc/passwd",
		"../" + certA,
		certA + "/../../escape",
		"",
		"not-a-uuid",
		certA + "extra",
		"9f1c8e2a4b734d519a0e6c2f1b8d7e35",     // right characters, no dashes
		"9f1c8e2g-4b73-4d51-9a0e-6c2f1b8d7e35", // 'g' is not hex
	} {
		if _, err := Ensure(id); err == nil {
			t.Errorf("Ensure(%q) was accepted; it must be refused", id)
		}
	}

	// Nothing may have been written anywhere under the root, not even an empty
	// directory: the refusal has to come before the filesystem is touched.
	var found []string
	_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err == nil && path != base {
			found = append(found, path)
		}
		return nil
	})
	if len(found) != 0 {
		t.Errorf("refused identifiers still created %v", found)
	}
}

// TestInconsistentStateIsRefused covers the three ways the two records can
// disagree. Each must be reported: every way of continuing would use
// or create key material on an assumption already known to be false, and the
// failure would otherwise be silent.
func TestInconsistentStateIsRefused(t *testing.T) {
	t.Run("record naming an absent key", func(t *testing.T) {
		base := withTempBase(t)
		key, err := Ensure(certA)
		if err != nil {
			t.Fatal(err)
		}
		fp, _ := fingerprint(key.Public())
		if err := os.Remove(filepath.Join(base, "keys", fp+".key")); err != nil {
			t.Fatal(err)
		}
		_, err = Ensure(certA)
		if err == nil {
			t.Fatal("a record naming a missing key was accepted")
		}
		if n := countFiles(t, filepath.Join(base, "keys")); n != 0 {
			t.Error("a replacement key was generated; the absence must be reported instead")
		}
	})

	t.Run("key file that does not parse", func(t *testing.T) {
		base := withTempBase(t)
		key, err := Ensure(certA)
		if err != nil {
			t.Fatal(err)
		}
		fp, _ := fingerprint(key.Public())
		path := filepath.Join(base, "keys", fp+".key")
		if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Ensure(certA); err == nil {
			t.Fatal("an unparseable key file was accepted")
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "not a key\n" {
			t.Error("the unparseable file was overwritten; it may be the only copy of something recoverable")
		}
	})

	t.Run("key whose contents do not match its name", func(t *testing.T) {
		base := withTempBase(t)
		key, err := Ensure(certA)
		if err != nil {
			t.Fatal(err)
		}
		fp, _ := fingerprint(key.Public())

		// Put a different, perfectly valid key under the first key's name.
		other, err := Ensure(certB)
		if err != nil {
			t.Fatal(err)
		}
		otherFP, _ := fingerprint(other.Public())
		body, err := os.ReadFile(filepath.Join(base, "keys", otherFP+".key"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "keys", fp+".key"), body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Ensure(certA); err == nil {
			t.Fatal("a key filed under another key's name was accepted")
		}
	})

	t.Run("record disagreeing with its own filename", func(t *testing.T) {
		base := withTempBase(t)
		if _, err := Ensure(certA); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(base, "certs", certA+".json")
		var rec record
		readJSON(t, path, &rec)
		rec.CertificateID = certB
		body, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Ensure(certA); err == nil {
			t.Fatal("a record disagreeing with its filename was accepted; neither value may be chosen")
		}
	})
}

// TestCreatesMissingDirectories: the first write after an install creates the
// whole tree, several levels of it when the base does not exist either. Each
// level must end up present and 0700, since a level that is missing or wrong is
// how the durability and permission guarantees both fail on exactly the run
// that matters most, the first one.
func TestCreatesMissingDirectories(t *testing.T) {
	root := t.TempDir()
	oldBase, oldEuid := baseDir, euid
	baseDir, euid = filepath.Join(root, "deep", "etc", "easyssl"), func() int { return 0 }
	t.Cleanup(func() { baseDir, euid = oldBase, oldEuid })

	if _, err := Ensure(certA); err != nil {
		t.Fatalf("Ensure into a tree that does not exist yet: %v", err)
	}
	for _, dir := range []string{
		filepath.Join(root, "deep"),
		filepath.Join(root, "deep", "etc"),
		baseDir,
		filepath.Join(baseDir, "keys"),
		filepath.Join(baseDir, "certs"),
	} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s mode = %o, want 700", dir, got)
		}
	}
}

func TestCountReportsKeys(t *testing.T) {
	withTempBase(t)

	if n, err := Count(); err != nil || n != 0 {
		t.Fatalf("Count on an empty host = %d, %v; want 0, nil", n, err)
	}
	if _, err := Ensure(certA); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(certB); err != nil {
		t.Fatal(err)
	}
	if n, err := Count(); err != nil || n != 2 {
		t.Fatalf("Count = %d, %v; want 2, nil", n, err)
	}
}

func fingerprintOfPEM(t *testing.T, body []byte) string {
	t.Helper()
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatal("key file is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("key file is not PKCS#8: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(parsed.(*ecdsa.PrivateKey).Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read %s: %v", dir, err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			n++
		}
	}
	return n
}
