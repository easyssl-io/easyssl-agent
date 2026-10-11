// These tests are inside the keystore package so they can point baseDir at a
// temporary directory. They run unprivileged, so they cannot check that the
// files are root-owned; only a run on a real host can.
package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/wire"
)

// generate is Generate with the fingerprint checked against the key, so a
// test reads one return value and knows the other agrees with it.
func generate(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	fp, signer, err := Generate(wire.KeyTypeECP256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	key := signer.(*ecdsa.PrivateKey)
	if want, _ := fingerprint(key.Public()); fp != want {
		t.Fatalf("Generate returned fingerprint %s for a key hashing to %s", fp, want)
	}
	return fp, key
}

// withTempBase points the keystore at a directory this test owns, and reports
// the process as root, since these tests run unprivileged. TestNonRootIsRefused
// covers the other side.
func withTempBase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldBase, oldEuid := baseDir, euid
	baseDir, euid = dir, func() int { return 0 }
	t.Cleanup(func() { baseDir, euid = oldBase, oldEuid })
	return dir
}

// The permissions mean nothing unless root owns the files, since a key written
// by another user is 0600 to that user. The service does not check euid, so
// this is the only check on the path the Server's requests arrive on.
func TestNonRootIsRefused(t *testing.T) {
	base := withTempBase(t)
	euid = func() int { return 1000 }

	if _, _, err := Generate(wire.KeyTypeECP256); err == nil {
		t.Fatal("a non-root caller was allowed to write a private key")
	}
	if n := countFiles(t, filepath.Join(base, "keys")); n != 0 {
		t.Error("a key was written despite the caller not being root")
	}
}

// The permissions are the entire at-rest protection, so they are asserted
// rather than assumed, and a key file's name is checked against its own
// contents, which is what makes the directory self-verifying.
func TestLayoutAndPermissions(t *testing.T) {
	base := withTempBase(t)

	want, _ := generate(t)

	info, err := os.Stat(filepath.Join(base, "keys"))
	if err != nil {
		t.Fatalf("stat keys: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("keys mode = %o, want 700", got)
	}

	keyPath := filepath.Join(base, "keys", want+".key")
	info, err = os.Stat(keyPath)
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
	// Nothing beside the key: the link to a certificate is the Server's.
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "keys" {
		t.Errorf("keystore base holds %v, want only keys/", entries)
	}
}

// The keystore knows nothing of certificates, so it cannot return "the key for
// this one" and must not try. Two calls are two keys, both kept, which makes a
// renewal's key fresh and an interrupted request's first key an orphan rather
// than a silent reuse.
func TestGenerateIsFreshEveryCall(t *testing.T) {
	base := withTempBase(t)

	firstFP, first := generate(t)
	secondFP, second := generate(t)
	if first.Equal(second) || firstFP == secondFP {
		t.Error("two calls returned one key")
	}
	if n := countFiles(t, filepath.Join(base, "keys")); n != 2 {
		t.Errorf("keys after two calls = %d, want 2", n)
	}
}

// A CSR that merely parses is only internally consistent. It must belong to the
// key on this host, because a mismatch yields a certificate its own host cannot
// serve.
func TestCSRMatchesStoredKey(t *testing.T) {
	withTempBase(t)

	_, key := generate(t)
	der, err := CSR(key, []string{"example.test", "www.example.test"})
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
	// No Common Name: an ACME client would order it as a name in its own right,
	// so an unrequested one there becomes an unrequested name on the certificate.
	if csr.Subject.CommonName != "" {
		t.Errorf("CSR carries Common Name %q; it must carry none", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("CSR DNS names = %v, want both domains", csr.DNSNames)
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("CSR signature algorithm = %v, want ECDSAWithSHA256", csr.SignatureAlgorithm)
	}
}

// The fingerprint arrives from the Server and filepath.Join resolves ".."
// rather than refusing it, so without the check a Server could choose which
// file this root process reads as a private key.
func TestMalformedIdentifierIsRefused(t *testing.T) {
	base := withTempBase(t)

	valid := strings.Repeat("ab", 32)
	for _, id := range []string{
		"../../etc/passwd",
		"../" + valid,
		valid + "/../../escape",
		"",
		"not-a-fingerprint",
		valid + "ab",                     // too long
		valid[:62],                       // too short
		strings.ToUpper(valid),           // one spelling only
		strings.Repeat("g", 64),          // not hex
		strings.Repeat("a", 63) + "\x00", // not printable
	} {
		if _, err := Load(id); err == nil || errors.Is(err, ErrNoKey) {
			t.Errorf("Load(%q) = %v; it must be refused before the filesystem is touched", id, err)
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

// Each way a named key can fail to be what its name says must be reported:
// continuing would use or create key material on an assumption already known to
// be false, and the failure would otherwise be silent.
func TestInconsistentStateIsRefused(t *testing.T) {
	t.Run("named key that is absent", func(t *testing.T) {
		base := withTempBase(t)
		fp, _ := generate(t)
		if err := os.Remove(filepath.Join(base, "keys", fp+".key")); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(fp); !errors.Is(err, ErrNoKey) {
			t.Fatalf("Load of a removed key = %v, want ErrNoKey", err)
		}
		if n := countFiles(t, filepath.Join(base, "keys")); n != 0 {
			t.Error("a replacement key was generated; the absence must be reported instead")
		}
	})

	t.Run("key file that does not parse", func(t *testing.T) {
		base := withTempBase(t)
		fp, _ := generate(t)
		path := filepath.Join(base, "keys", fp+".key")
		if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(fp); err == nil || errors.Is(err, ErrNoKey) {
			t.Fatalf("an unparseable key file: Load = %v, want an error that is not ErrNoKey", err)
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
		fp, _ := generate(t)
		// Put a different, perfectly valid key under the first key's name.
		otherFP, _ := generate(t)
		body, err := os.ReadFile(filepath.Join(base, "keys", otherFP+".key"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "keys", fp+".key"), body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(fp); err == nil || errors.Is(err, ErrNoKey) {
			t.Fatalf("a key filed under another key's name: Load = %v, want a mismatch error", err)
		}
	})
}

// The first write after an install creates the whole tree, several levels when
// the base does not exist either. Each level must end up present and 0700, or
// the durability and permission guarantees both fail on the first run.
func TestCreatesMissingDirectories(t *testing.T) {
	root := t.TempDir()
	oldBase, oldEuid := baseDir, euid
	baseDir, euid = filepath.Join(root, "deep", "etc", "easyssl"), func() int { return 0 }
	t.Cleanup(func() { baseDir, euid = oldBase, oldEuid })

	if _, _, err := Generate(wire.KeyTypeECP256); err != nil {
		t.Fatalf("Generate into a tree that does not exist yet: %v", err)
	}
	for _, dir := range []string{
		filepath.Join(root, "deep"),
		filepath.Join(root, "deep", "etc"),
		baseDir,
		filepath.Join(baseDir, "keys"),
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
	generate(t)
	generate(t)
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

// Load is how a key leaves this package for a CSR or a Plugin. It returns the
// key Generate stored under that name, so a Deployment installs the key the
// certificate was issued against. It reports ErrNoKey rather than generating,
// because no generated key can match an already-issued certificate. And it
// refuses a non-root caller like every other entry point, since the file
// permissions are the whole of the at-rest protection.
func TestLoadReturnsTheNamedKeyAndRefusesWhenThereIsNone(t *testing.T) {
	withTempBase(t)

	absent := strings.Repeat("0", 64)
	if _, err := Load(absent); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Load on a host holding no key: want ErrNoKey, got %v", err)
	}

	fp, stored := generate(t)
	loaded, err := Load(fp)
	if err != nil {
		t.Fatalf("Load after Generate: %v", err)
	}
	if !loaded.(*ecdsa.PrivateKey).Equal(stored) {
		t.Error("Load returned a different key from the one Generate stored")
	}

	// Another name is another key, so Load must not fall back to whatever
	// key happens to be on the host.
	if _, err := Load(absent); !errors.Is(err, ErrNoKey) {
		t.Errorf("Load for an unheld fingerprint: want ErrNoKey, got %v", err)
	}

	euid = func() int { return 1000 }
	if _, err := Load(fp); err == nil {
		t.Error("a non-root caller was allowed to read a private key out")
	}
}

// The Plugin receives this string and writes it where the Target needs it, so a
// wrong encoding is a Deployment that installs an unusable key, and the failure
// would surface on the host rather than here.
func TestEncodePrivateKeyPEMRoundTrips(t *testing.T) {
	withTempBase(t)

	_, key := generate(t)
	encoded, err := EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}

	block, rest := pem.Decode([]byte(encoded))
	if block == nil {
		t.Fatal("EncodePrivateKeyPEM did not produce a PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("PEM type = %q, want PRIVATE KEY (PKCS#8)", block.Type)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		t.Error("EncodePrivateKeyPEM produced trailing data after the block")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("the encoded key does not parse as PKCS#8: %v", err)
	}
	back, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("decoded key is %T, want *ecdsa.PrivateKey", parsed)
	}
	if !back.Equal(key) {
		t.Error("the key did not survive the encode/decode round trip")
	}
}

func TestListReportsUsableKeysOnly(t *testing.T) {
	dir := t.TempDir()
	oldBase, oldEuid := baseDir, euid
	baseDir, euid = dir, func() int { return 0 }
	t.Cleanup(func() { baseDir, euid = oldBase, oldEuid })

	if keys, err := List(); err != nil || len(keys) != 0 {
		t.Fatalf("empty keystore: %v, %v", keys, err)
	}
	fp, _ := generate(t)
	// A misnamed key, which must be left out rather than reported as the key
	// its name claims.
	if err := os.WriteFile(filepath.Join(keysDir(), strings.Repeat("f", 64)+".key"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Fingerprint != fp || keys[0].Algorithm != "ec_p256" || keys[0].CreatedAt.IsZero() {
		t.Fatalf("List() = %+v, want the one usable key %s", keys, fp)
	}
}

// Each key type's CSR carries a key of that type signed with the matching
// algorithm, Load reads it back as the same key, and the inventory names its
// type.
func TestEveryKeyTypeRoundTrips(t *testing.T) {
	withTempBase(t)
	want := map[string]x509.SignatureAlgorithm{
		wire.KeyTypeECP256:  x509.ECDSAWithSHA256,
		wire.KeyTypeECP384:  x509.ECDSAWithSHA384,
		wire.KeyTypeRSA2048: x509.SHA256WithRSA,
		wire.KeyTypeRSA3072: x509.SHA256WithRSA,
		wire.KeyTypeRSA4096: x509.SHA256WithRSA,
	}
	fps := map[string]string{}
	for _, kt := range wire.KeyTypes {
		fp, key, err := Generate(kt)
		if err != nil {
			t.Fatalf("Generate(%s): %v", kt, err)
		}
		fps[fp] = kt
		der, err := CSR(key, []string{"a.example.test"})
		if err != nil {
			t.Fatalf("CSR(%s): %v", kt, err)
		}
		req, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		if got := wire.KeyTypeOf(req.PublicKey); got != kt || req.SignatureAlgorithm != want[kt] {
			t.Fatalf("%s: CSR key %s signed %s, want %s", kt, got, req.SignatureAlgorithm, want[kt])
		}
		loaded, err := Load(fp)
		if err != nil || wire.KeyTypeOf(loaded.Public()) != kt {
			t.Fatalf("Load(%s) = %v, %v", kt, loaded, err)
		}
	}
	if _, _, err := Generate("ec_p521"); err == nil {
		t.Fatal("Generate accepted a type outside wire.KeyTypes")
	}
	keys, err := List()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Algorithm != fps[k.Fingerprint] {
			t.Fatalf("inventory names %s as %s, want %s", k.Fingerprint, k.Algorithm, fps[k.Fingerprint])
		}
	}
	if len(keys) != len(wire.KeyTypes) {
		t.Fatalf("inventory lists %d keys, want %d", len(keys), len(wire.KeyTypes))
	}
}
