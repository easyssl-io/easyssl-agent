// Package serverapi is the Client's single HTTP wrapper for every Server call.
// Routing all Server interactions through one place is what will let a future
// audit mode record every request with no unaudited paths, so new Server calls
// belong here rather than in ad-hoc HTTP code. Standard library only, so the
// Client stays small and auditable.
package serverapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	apiErr := &APIError{Status: res.StatusCode}
	var e wire.ErrorResponse
	if json.NewDecoder(res.Body).Decode(&e) == nil {
		apiErr.Code = e.Code
		apiErr.Message = e.Message
	}
	return apiErr
}
