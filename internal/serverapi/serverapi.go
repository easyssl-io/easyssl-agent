// Package serverapi is the Client's single HTTP wrapper for every Server call.
// Routing all Server interactions through one place is what will let a future
// audit mode record every request with no unaudited paths, so new Server calls
// belong here rather than in ad-hoc HTTP code. Standard library only, so the
// Client stays small and auditable.
package serverapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-contract/wire"
)

// Client talks to one easySSL Server base URL.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client for the given Server base URL (e.g. https://server:8080).
func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError is a non-2xx Server response. Code is the wire error code (e.g.
// wire.CodeInstanceIDTaken) when the body carried one, so callers can branch on
// it rather than parsing prose.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("server responded %d (%s): %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("server responded %d (%s)", e.Status, e.Code)
}

// Register performs the first check-in that creates a pending Client and returns
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

// RegistrationStatus asks what the Server currently considers this Client to be.
// It is a plain read, so unlike Checkin it does not refresh the Client's
// last-seen.
func (c *Client) RegistrationStatus(ctx context.Context, token string) (wire.RegistrationStatus, error) {
	var out wire.RegistrationStatus
	err := c.do(ctx, http.MethodGet, wire.RouteRegistration, token, nil, &out)
	return out, err
}

// Unregister removes this Client from its organization, so an uninstalled host
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
// Client to finish. This is what actually delivers work: the event stream below
// only makes it prompt, so this runs on every poll whether or not a stream is
// open.
func (c *Client) PendingCommands(ctx context.Context, token string) ([]wire.Command, error) {
	var out wire.CommandsResponse
	if err := c.do(ctx, http.MethodGet, wire.RouteCommands+"?status=pending", token, nil, &out); err != nil {
		return nil, err
	}
	return out.Commands, nil
}

// AckCommand reports that this Client has finished with a command: it acted
// (however that turned out), or it does not recognize the type.
//
// Sent after any outcome has been recorded on the resource the command refers
// to, never before. A repeat is fine and expected: a Client that recorded an
// outcome and then died is handed the command again and acks a second time.
func (c *Client) AckCommand(ctx context.Context, token, commandID, status string) error {
	path := wire.RouteCommands + "/" + url.PathEscape(commandID) + "/ack"
	return c.do(ctx, http.MethodPost, path, token, wire.AckRequest{Status: status}, nil)
}

// SubscribeCommands opens the long-lived event stream and calls onCommand for
// every command id the Server pushes, until the context is canceled or the
// stream drops. It returns nil when the stream simply ended, which is ordinary
// rather than an error: the caller reconnects and keeps polling meanwhile.
//
// Deliberately built on net/http and bufio rather than an SSE library. The
// grammar this needs is two field names, and everything shipped to a host that
// handles someone's private keys has to earn its place.
func (c *Client) SubscribeCommands(ctx context.Context, token string, onCommand func(commandID string)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+wire.RouteEvents, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)

	// No timeout on this one: the stream is meant to stay open, so the shared
	// 30s client would sever it on schedule.
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return decodeAPIError(res)
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
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if event != wire.EventCommand {
				continue // unknown event name: ignore, same as an unknown command type
			}
			var ev wire.CommandEvent
			if err := json.Unmarshal([]byte(data), &ev); err != nil {
				continue // malformed: the poll will find the work anyway
			}
			if ev.CommandID != "" {
				onCommand(ev.CommandID)
			}
		}
	}
	return scanner.Err()
}
