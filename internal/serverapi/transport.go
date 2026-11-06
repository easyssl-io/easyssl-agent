package serverapi

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
)

// Everything this Agent sends the Server is either a credential or something
// only that Server should see: the Organization's registration key and the bearer
// token that stands for this host from then on. TLS keeps all of it off the wire in the clear,
// and nothing in this package weakens it: there is no tls.Config here, so Go's
// defaults apply whole (the system root pool, hostname verification, TLS 1.2 as
// the floor).
//
// What the defaults do not do is insist on TLS at all, which is what this file
// is for. Both halves are needed: a base URL is checked once, and a redirect
// can change the scheme afterwards.

// CheckBaseURL rejects a Server base URL this Agent must not talk to.
//
// It is called by New, so no path can build a Client around a URL that was
// never checked, a hand-edited configuration included. At registration the
// check happens before the Server issues a token, so a mistyped --server fails
// while there is still nothing to leak.
//
// http is allowed to a loopback host and nowhere else. A developer running a
// Server on their own machine has no certificate for it and no attacker on the
// path, so requiring https there would only teach people to want a way around
// it. Restricting it to loopback means a real host can never be reached this
// way, so the exception cannot be widened by a typo or by copying a working
// command from a laptop to a server.
//
// The name "localhost" is accepted alongside the literal addresses: RFC 6761
// reserves it for this, and resolving it elsewhere takes an edit to /etc/hosts
// or the resolver, both of which need the root this Agent already runs as.
// NormalizeURL is a Server URL in one spelling: scheme and host in lower case,
// no default port and no trailing slash, so two spellings of one Server compare
// equal. A URL that does not parse is returned as given.
func NormalizeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	return u.String()
}

func CheckBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return msg.Err.T("server_url.unparsable", "\"{url}\" is not a URL: {err}", "url", raw, "err", err)
	}
	switch {
	case u.Scheme == "https":
		if u.Host == "" {
			return msg.Err.T("server_url.no_host", "\"{url}\" names no host; the Server URL looks like https://server.example.com", "url", raw)
		}
		return nil
	case u.Scheme == "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
		return msg.Err.T("server_url.not_encrypted", "\"{url}\" is not encrypted, and this Agent would send the registration key, "+
			"its bearer token and every private key it installs over it in the clear; "+
			"use https://{host} (http is allowed only to localhost, for a Server running on this machine)",
			"url", raw, "host", u.Host)
	default:
		// Includes the empty scheme, which is what "server.example.com" and
		// "server.example.com:8080" parse to. Say the whole shape rather than
		// "invalid scheme": the mistake is almost always a missing prefix.
		return msg.Err.T("server_url.no_scheme", "\"{url}\" is not a Server URL; it must start with https://, as in https://server.example.com", "url", raw)
	}
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	// Hostname() has already stripped the port and the brackets around an IPv6
	// literal, so this covers ::1 and the whole of 127.0.0.0/8.
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// noSchemeChange refuses a redirect that moves to a different scheme than the
// one the request started on.
//
// Go strips the Authorization header when a redirect crosses to an unrelated
// host, but it does not look at the scheme: shouldCopyHeaderOnRedirect compares
// hostnames only, so https://server → http://server is same-host, keeps the
// bearer token, and sends it in the clear. Exploiting that takes a compromised
// Server or a network attacker who can inject a 302, which are precisely the
// two the encryption is there for.
//
// A redirect the other way, http → https, is refused too, because it means the
// configured URL is wrong: silently upgrading would leave the first request of
// every future call going out in the clear, with nothing on screen saying so.
func noSchemeChange(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if from := via[0].URL.Scheme; req.URL.Scheme != from {
		return msg.Err.T("server.redirect.scheme_change", "refusing a redirect from {from} to {to}: it changes the scheme to {scheme}",
			"from", via[0].URL.Redacted(), "to", req.URL.Redacted(), "scheme", req.URL.Scheme)
	}
	// Go's own limit still applies on top of this one.
	if len(via) >= 10 {
		return msg.Err.T("server.redirect.too_many", "stopped after {count} redirects", "count", len(via))
	}
	return nil
}
