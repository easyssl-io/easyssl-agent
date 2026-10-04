// Package serverapi is the Agent's HTTP wrapper, and where a Server call
// belongs. Routing Server interactions through one place is what will let a
// future audit mode record every request with no unaudited paths, so new Server
// calls go here rather than into ad-hoc HTTP code.
//
// It is not yet every call. pluginmgr.HTTPCatalog makes two kinds of request
// without coming through here, fetching the Marketplace catalog and downloading
// a Plugin artifact, issued from three call sites. Both of its construction
// sites in cmd/easyssl-agent leave the HTTP field unset, so those requests run
// on the process-wide http.DefaultClient and carry no timeout, and they would
// go unrecorded. The wrapper cannot be described as complete until those three
// call sites move here. Standard library only, so
// the Agent stays small and auditable.
//
// Those three call sites now miss something else as well: the transport policy
// in transport.go, which is what requires TLS and refuses a redirect that drops
// it. They carry no bearer token, so the downgrade matters less there than it
// does here, and a Plugin artifact is checked against the catalog's digest
// afterwards. It is still one more reason for them to move.
package serverapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Client talks to one easySSL Server base URL.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client for the given Server base URL (e.g. https://server:8080),
// or fails if that URL is one this Agent must not talk to. CheckBaseURL in
// transport.go says which those are and why; the check lives here, on the only
// constructor, so no caller can hold a Client that skipped it.
func New(baseURL string) (*Client, error) {
	if err := CheckBaseURL(baseURL); err != nil {
		return nil, err
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: noSchemeChange,
		},
	}, nil
}

// APIError is a non-2xx Server response. Code is the wire error code (e.g.
// wire.CodeAgentIDTaken) when the body carried one, so callers can branch on
// it rather than parsing prose.
type APIError struct {
	Status  int
	Code    string
	Message string
}

// Error words a refusal for a person. A code this Agent knows gets the
// Agent's own message, which is the one that can be read in the host's
// language; the Server's text is English whoever reads it, so it is shown
// only for a code this Agent has no message for, as a newer Server may send.
func (e *APIError) Error() string {
	switch e.Code {
	case wire.CodeUnknownToken:
		return msg.T("server.refused.unknown_token", "the Server does not accept this host's token: the Agent was deactivated or removed, or its registration was rejected")
	case wire.CodeInvalidRegistrationKey:
		return msg.T("server.refused.registration_key", "the Server did not accept the registration key")
	case wire.CodeInvalidReactivationToken:
		return msg.T("server.refused.reactivation_token", "the Server did not accept the reactivation token: it is unknown, expired or already used")
	}
	if e.Message != "" {
		return msg.T("server.refused.other", "the Server responded {status} ({code}): {message}", "status", e.Status, "code", e.Code, "message", e.Message)
	}
	return msg.T("server.refused.no_text", "the Server responded {status} ({code})", "status", e.Status, "code", e.Code)
}

// Register performs the first check-in that creates a pending Agent and returns
// the one-time bearer token.
func (c *Client) Register(ctx context.Context, req wire.RegistrationRequest) (wire.RegistrationResponse, error) {
	var out wire.RegistrationResponse
	err := c.do(ctx, http.MethodPost, wire.RouteRegistrations, "", req, &out)
	return out, err
}

// Checkin performs an authenticated poll with the bearer token.
func (c *Client) Checkin(ctx context.Context, token string, req wire.CheckinRequest) (wire.CheckinResponse, error) {
	var out wire.CheckinResponse
	err := c.do(ctx, http.MethodPost, wire.RouteCheckin, token, req, &out)
	return out, err
}

// RegistrationStatus asks what the Server currently considers this Agent to be.
// It is a plain read, so unlike Checkin it does not refresh the Agent's
// last-seen.
func (c *Client) RegistrationStatus(ctx context.Context, token string) (wire.RegistrationStatus, error) {
	var out wire.RegistrationStatus
	err := c.do(ctx, http.MethodGet, wire.RouteRegistration, token, nil, &out)
	return out, err
}

// ReportInventory PUTs the whole host inventory, replacing what the Server
// holds for this Agent. Called only when a check-in answered ReportInventory.
func (c *Client) ReportInventory(ctx context.Context, token string, inv wire.Inventory) error {
	return c.do(ctx, http.MethodPut, wire.RouteAgentInventory, token, inv, nil)
}

// Unregister removes this Agent from its Organization, so an uninstalled host
// disappears from the Server without the operator also removing it there.
func (c *Client) Unregister(ctx context.Context, token string) error {
	return c.do(ctx, http.MethodDelete, wire.RouteRegistration, token, nil, nil)
}

// do is the single request path: marshal body, set the bearer token if given,
// and decode either the success body or a wire.ErrorResponse.
func (c *Client) do(ctx context.Context, method, path, token string, body, out any) error {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, buf)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		if out == nil {
			return nil
		}
		return json.NewDecoder(res.Body).Decode(out)
	}

	return decodeAPIError(res)
}

// decodeAPIError turns a non-2xx response into an APIError, keeping the wire
// error code when the body carried one so callers can branch on it.
func decodeAPIError(res *http.Response) error {
	apiErr := &APIError{Status: res.StatusCode}
	var e wire.ErrorResponse
	if json.NewDecoder(res.Body).Decode(&e) == nil {
		apiErr.Code = e.Code
		apiErr.Message = e.Message
	}
	return apiErr
}

// PendingCommands lists the commands the Server is still waiting for this
// Agent to finish. This is what actually delivers work: the event stream below
// only makes it prompt, so this runs on every poll whether or not a stream is
// open.
func (c *Client) PendingCommands(ctx context.Context, token string) ([]wire.Command, error) {
	var out wire.CommandsResponse
	if err := c.do(ctx, http.MethodGet, wire.RouteCommands+"?status=pending", token, nil, &out); err != nil {
		return nil, err
	}
	return out.Commands, nil
}

// AckCommand reports that this Agent has finished with a command: it acted
// (however that turned out), or it does not recognize the type.
//
// Sent after any outcome has been recorded on the resource the command refers
// to, never before. A repeat is fine and expected: an Agent that recorded an
// outcome and then died is handed the command again and acks a second time.
func (c *Client) AckCommand(ctx context.Context, token, commandID, status string) error {
	path := wire.RouteCommands + "/" + url.PathEscape(commandID) + "/ack"
	return c.do(ctx, http.MethodPost, path, token, wire.AckRequest{Status: status}, nil)
}

// SubscribeCommands opens the long-lived event stream and calls onCommand every
// time the Server says something is waiting, until the context is canceled or
// the stream drops. The event carries nothing, and could not usefully: what is
// waiting is read over REST, which is also what delivers whatever arrived while
// this Agent was disconnected. It returns nil when the stream simply ended, which is ordinary
// rather than an error: the caller reconnects and keeps polling meanwhile.
//
// onConnect fires once the Server has accepted the stream. The caller cannot
// infer that moment from the return value, which arrives only after the
// connection is already over, so without this there is no way to tell a stream
// that never opened from one that stayed up for hours.
//
// Deliberately built on net/http and bufio rather than an SSE library. The
// grammar this needs is two field names, and everything shipped to a host that
// handles someone's private keys has to earn its place.
func (c *Client) SubscribeCommands(ctx context.Context, token string, onConnect func(), onCommand func()) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+wire.RouteEvents, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)

	// No timeout on this one: the stream is meant to stay open, so the shared
	// 30s client would sever it on schedule. Everything else about it matches,
	// the redirect policy above all: this request carries the bearer token like
	// any other, and a client built bare here would be the one path that
	// followed a downgrade with it.
	res, err := (&http.Client{CheckRedirect: noSchemeChange}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return decodeAPIError(res)
	}
	if onConnect != nil {
		onConnect()
	}

	scanner := bufio.NewScanner(res.Body)
	var event string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			event = "" // dispatch boundary
		case strings.HasPrefix(line, ":"):
			// Keepalive comment; the Server sends these so intermediaries do
			// not reap an idle stream.
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			// The line's content is not read. The event carries no body, and
			// this arm exists because SSE dispatches an event only when a data
			// field arrives, so this is where a complete event lands.
			if event != wire.EventCommand {
				continue // unknown event name: ignore, same as an unknown command type
			}
			onCommand()
		}
	}
	return scanner.Err()
}

// CSRWork reads the signing work behind a request_csr command: the domain set
// the certificate fixed at request time. Only the Agent named on the
// certificate gets an answer; anyone else gets the same 404 a nonexistent
// certificate would.
func (c *Client) CSRWork(ctx context.Context, token, certificateID string) (wire.CSRWork, error) {
	var out wire.CSRWork
	path := "/api/v1/agent/certificates/" + url.PathEscape(certificateID)
	if err := c.do(ctx, http.MethodGet, path, token, nil, &out); err != nil {
		return wire.CSRWork{}, err
	}
	return out, nil
}

// SubmitCSR hands the built CSR back. The Server verifies it against the
// request before storing it write-once; the terminal refusals
// (csr_already_submitted, not_awaiting_csr, csr_mismatch) come back as
// *APIError with those codes.
func (c *Client) SubmitCSR(ctx context.Context, token, certificateID, csrPEM string) error {
	path := "/api/v1/agent/certificates/" + url.PathEscape(certificateID) + "/csr"
	return c.do(ctx, http.MethodPost, path, token, wire.CSRSubmission{CSR: csrPEM}, nil)
}

// DeploymentWork reads what a deploy command refers to: the certificate, the
// chain and the resolved settings. Never the private key — that is already on
// this host, which is why only this Agent can carry the Deployment out.
func (c *Client) DeploymentWork(ctx context.Context, token, deploymentID string) (wire.DeploymentWork, error) {
	var out wire.DeploymentWork
	err := c.do(ctx, http.MethodGet, "/api/v1/agent/deployments/"+deploymentID, token, nil, &out)
	return out, err
}

// ReportDeploymentResult sends the terminal outcome. Write-once on the Server:
// a second report answers deployment_finished, which the Agent treats as done.
func (c *Client) ReportDeploymentResult(ctx context.Context, token, deploymentID string, res wire.DeploymentResult) error {
	return c.do(ctx, http.MethodPost, "/api/v1/agent/deployments/"+deploymentID+"/result", token, res, nil)
}
