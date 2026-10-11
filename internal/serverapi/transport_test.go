package serverapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/wire"
)

func TestCheckBaseURLRefusesAnythingButHTTPSAndLoopback(t *testing.T) {
	allowed := []string{
		"https://server.example.com",
		"https://server.example.com:8443",
		"https://server.example.com/",
		// The loopback exception, in the three spellings a developer uses.
		"http://localhost:8080",
		"http://LocalHost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		// The whole of 127.0.0.0/8 is loopback, not just .0.1.
		"http://127.9.9.9:8080",
	}
	for _, raw := range allowed {
		if err := CheckBaseURL(raw); err != nil {
			t.Errorf("CheckBaseURL(%q) = %v, want nil", raw, err)
		}
	}

	refused := []string{
		// The one that matters: a real host over plaintext.
		"http://server.example.com",
		"http://server.example.com:8080",
		// A name that merely starts like a loopback one is not one. Without
		// this, "localhost.evil.com" resolves wherever its owner says and the
		// exception has been handed to them.
		"http://localhost.evil.com",
		"http://127.0.0.1.evil.com",
		// A public address is not loopback however it is written.
		"http://93.184.216.34",
		// Not http at all.
		"ftp://server.example.com",
		"file:///etc/passwd",
		// What a missing prefix parses to. Both are the ordinary typo.
		"server.example.com",
		"server.example.com:8080",
		"",
		// A scheme with no host is not a Server.
		"https://",
	}
	for _, raw := range refused {
		if err := CheckBaseURL(raw); err == nil {
			t.Errorf("CheckBaseURL(%q) = nil, want an error", raw)
		}
	}
}

// The message is the whole value of the check for whoever mistyped the flag, so
// it says what will leak rather than that a string failed to validate.
func TestCheckBaseURLSaysWhatIsAtStake(t *testing.T) {
	err := CheckBaseURL("http://server.example.com")
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"not encrypted", "registration key", "private key", "https://server.example.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not mention %q", err.Error(), want)
		}
	}
}

func TestNewRefusesAURLItWillNotTalkTo(t *testing.T) {
	if _, err := New("http://server.example.com"); err == nil {
		t.Fatal("New accepted a plaintext URL to a real host")
	}
	c, err := New("https://server.example.com/")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.baseURL != "https://server.example.com" {
		t.Errorf("baseURL = %q, want the trailing slash trimmed", c.baseURL)
	}
}

// A redirect that changes the scheme is refused, and the bearer token is what
// makes it matter: Go strips Authorization across hosts but not across schemes,
// so without this the token would go out in the clear on the second hop.
func TestARedirectMayNotChangeTheScheme(t *testing.T) {
	var sawToken string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawToken = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"active"}`))
	}))
	defer plain.Close()

	// Stands in for a Server answering a redirect to the same host over http: any
	// scheme change is refused, and https is what the test client cannot serve.
	from := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	defer from.Close()

	c := &Client{
		baseURL: from.URL,
		// The TLS server uses a certificate no root pool trusts, so the
		// transport comes from httptest's own client. Only CheckRedirect is
		// under test, and it is set exactly as New sets it.
		http: &http.Client{Transport: from.Client().Transport, CheckRedirect: noSchemeChange},
	}
	err := c.do(context.Background(), http.MethodGet, wire.RouteRegistration, "esat_secret", nil, new(wire.RegistrationStatus))
	if err == nil {
		t.Fatal("the client followed a redirect that downgraded the scheme")
	}
	if !strings.Contains(err.Error(), "changes the scheme") {
		t.Errorf("error = %v, want it to name the scheme change", err)
	}
	if sawToken != "" {
		t.Errorf("the bearer token reached the plaintext server as %q", sawToken)
	}
}

// The scenario test above builds its client by hand, so it proves only that
// noSchemeChange works, not that anything uses it. These two run through the
// real constructors, because dropping CheckRedirect from either is otherwise
// silent: every other test keeps passing while the Agent follows a downgrade
// carrying its bearer token.
//
// The redirect goes the other way here, loopback http to https, because a test
// cannot serve an https URL the Agent's own client would trust. The rule is the
// same: the scheme changed.
func TestNewWiresTheRedirectPolicyIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example.com"+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.RegistrationStatus(context.Background(), "esat_secret")
	if err == nil || !strings.Contains(err.Error(), "changes the scheme") {
		t.Fatalf("RegistrationStatus error = %v, want a refused scheme change", err)
	}
}

func TestTheEventStreamWiresItInToo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example.com"+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = c.SubscribeCommands(context.Background(), "esat_secret", nil, func() {})
	if err == nil || !strings.Contains(err.Error(), "changes the scheme") {
		t.Fatalf("SubscribeCommands error = %v, want a refused scheme change", err)
	}
}

// A redirect within one scheme is ordinary and still works, so the rule above
// is about the downgrade rather than about redirects.
func TestARedirectWithinTheSameSchemeIsFollowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"active"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc(wire.RouteRegistration, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/moved", http.StatusFound)
	})

	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var out wire.RegistrationStatus
	if err := c.do(context.Background(), http.MethodGet, wire.RouteRegistration, "esat_secret", nil, &out); err != nil {
		t.Fatalf("do: %v", err)
	}
	if out.Status != wire.StatusActive {
		t.Errorf("status = %q, want %q", out.Status, wire.StatusActive)
	}
}
