// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johnnycube/kasapi/kasapitest"
)

func newTestClient(t *testing.T, f *kasapitest.Server) *Client {
	c, err := New(Config{
		Login:        "w0123456",
		Password:     "secret",
		AuthType:     AuthSHA1,
		APIEndpoint:  f.APIURL(),
		AuthEndpoint: f.AuthURL(),
		HTTPClient:   f.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestExec_AuthenticatesOnceAndReusesSession(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	for i := 0; i < 3; i++ {
		if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
			t.Fatalf("Exec %d: %v", i, err)
		}
	}
	if got := f.AuthCalls.Load(); got != 1 {
		t.Fatalf("expected 1 auth call, got %d", got)
	}
	if got := f.APICalls.Load(); got != 3 {
		t.Fatalf("expected 3 api calls, got %d", got)
	}
}

func TestExec_FaultBecomesAPIError(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return "", "zone_not_found"
	})
	c := newTestClient(t, f)

	_, err := c.Exec(context.Background(), "get_dns_settings", map[string]any{"zone_host": "x.de."})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "zone_not_found" {
		t.Fatalf("expected APIError zone_not_found, got %v", err)
	}
}

func TestExec_RetriesOnFloodProtection(t *testing.T) {
	first := true
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		if first {
			first = false
			return "", "flood_protection"
		}
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	start := time.Now()
	if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if got := f.APICalls.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
	if elapsed := time.Since(start); elapsed < 1900*time.Millisecond {
		t.Fatalf("expected backoff before retry, elapsed only %v", elapsed)
	}
}

func TestExec_ReauthenticatesOnExpiredSession(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	// Corrupt the cached token; the server answers session_expired and the
	// client must re-auth transparently.
	c.mu.Lock()
	c.token = "stale-token"
	c.mu.Unlock()

	if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("Exec after expiry: %v", err)
	}
	if got := f.AuthCalls.Load(); got != 2 {
		t.Fatalf("expected re-auth (2 auth calls), got %d", got)
	}
}

func TestExec_EmptyActionAndCancelledContext(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	if _, err := c.Exec(context.Background(), "", nil); err == nil {
		t.Fatal("empty action must fail")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Exec(ctx, "noop", nil); err == nil {
		t.Fatal("cancelled context must fail")
	}
}

func TestExec_ConcurrentUseIsSerializedAndSafe(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return kasapitest.MapItem("ok", "1"), ""
	})
	c := newTestClient(t, f)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
				t.Errorf("concurrent Exec: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := f.AuthCalls.Load(); got != 1 {
		t.Fatalf("expected a single shared auth, got %d", got)
	}
	if got := f.APICalls.Load(); got != 8 {
		t.Fatalf("expected 8 api calls, got %d", got)
	}
}

func TestNew_Validation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for missing credentials")
	}
	if _, err := New(Config{Login: "w1", Password: "p", AuthType: "md5"}); err == nil {
		t.Fatal("expected error for unsupported auth type")
	}
	c, err := New(Config{Login: "w1", Password: "p", SessionLifetime: 99999})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.cfg.SessionLifetime != MaxSessionLifetime {
		t.Fatalf("session lifetime not clamped: %d", c.cfg.SessionLifetime)
	}
}

// rawServer answers KasAuth and KasApi with fixed bodies.
func rawServer(t *testing.T, authBody string, apiStatus int, apiBody string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "KasAuth") {
			fmt.Fprint(w, authBody)
			return
		}
		w.WriteHeader(apiStatus)
		fmt.Fprint(w, apiBody)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{
		Login: "w0123456", Password: "secret",
		APIEndpoint: srv.URL + "/KasApi.php", AuthEndpoint: srv.URL + "/KasAuth.php",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

const tokenBody = `<r><return>tok</return></r>`

func TestAPIError_Error(t *testing.T) {
	err := &APIError{Code: "zone_not_found"}
	if err.Error() != "kasapi: zone_not_found" {
		t.Fatalf("Error(): %q", err.Error())
	}
}

func TestNew_Defaults(t *testing.T) {
	c, err := New(Config{Login: "w1", Password: "p"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.cfg.AuthType != AuthSHA1 || c.cfg.SessionLifetime != 1800 || c.cfg.UserAgent != "kasapi-go" {
		t.Fatalf("unexpected defaults: %+v", c.cfg)
	}
	if c.cfg.APIEndpoint != DefaultAPIEndpoint || c.cfg.AuthEndpoint != DefaultAuthEndpoint {
		t.Fatalf("unexpected endpoints: %+v", c.cfg)
	}
	if c.http == nil || c.http.Timeout != 60*time.Second {
		t.Fatalf("unexpected default HTTP client: %+v", c.http)
	}
	for name, svc := range map[string]any{
		"DNS": c.DNS, "Mail": c.Mail, "Subdomains": c.Subdomains, "Domains": c.Domains,
		"TLS": c.TLS, "FTP": c.FTP, "Databases": c.Databases, "Cronjobs": c.Cronjobs, "DDNS": c.DDNS,
	} {
		if reflect.ValueOf(svc).IsNil() {
			t.Errorf("service %s is not wired", name)
		}
	}

	// Negative lifetimes fall back to the default; valid ones are kept.
	c, _ = New(Config{Login: "w1", Password: "p", SessionLifetime: -5})
	if c.cfg.SessionLifetime != 1800 {
		t.Fatalf("negative lifetime: %d", c.cfg.SessionLifetime)
	}
	c, _ = New(Config{Login: "w1", Password: "p", SessionLifetime: 7200, AuthType: AuthPlain})
	if c.cfg.SessionLifetime != 7200 || c.cfg.AuthType != AuthPlain {
		t.Fatalf("explicit settings not kept: %+v", c.cfg)
	}
}

func TestExec_MalformedResponses(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"scalar return":      {200, `<r><return>oops</return></r>`, "malformed response"},
		"no Response":        {200, `<r><return><item><key>Other</key><value>x</value></item></return></r>`, "malformed response"},
		"ReturnString FALSE": {200, `<r><return><item><key>Response</key><value><item><key>ReturnString</key><value>FALSE</value></item></value></item></return></r>`, `ReturnString="FALSE"`},
		"no return element":  {200, `<r><other/></r>`, "no <return> element"},
		"HTTP error":         {502, `<html>bad gateway</html>`, "unexpected HTTP status 502"},
		"broken XML":         {200, `<r><return>`, "parsing SOAP response"},
	} {
		c := rawServer(t, tokenBody, tc.status, tc.body)
		_, err := c.Exec(ctx, "noop", nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
}

func TestExec_FaultCodeFallback(t *testing.T) {
	// A fault without faultstring falls back to its faultcode.
	body := `<e><Body><Fault><faultcode>SOAP-ENV:Server</faultcode></Fault></Body></e>`
	c := rawServer(t, tokenBody, 500, body)
	_, err := c.Exec(context.Background(), "noop", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "SOAP-ENV:Server" {
		t.Fatalf("expected the faultcode, got %v", err)
	}
}

func TestExec_TransportErrors(t *testing.T) {
	ctx := context.Background()

	// A server that is gone.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, _ := New(Config{Login: "w1", Password: "p", APIEndpoint: url, AuthEndpoint: url})
	if _, err := c.Exec(ctx, "noop", nil); err == nil || !strings.Contains(err.Error(), "performing request") {
		t.Fatalf("expected a request error, got %v", err)
	}

	// An endpoint that is not a URL.
	c, _ = New(Config{Login: "w1", Password: "p", APIEndpoint: "://", AuthEndpoint: "://"})
	if _, err := c.Exec(ctx, "noop", nil); err == nil || !strings.Contains(err.Error(), "building request") {
		t.Fatalf("expected a build error, got %v", err)
	}

	// Parameters that cannot be encoded.
	f := kasapitest.New(t, func(string, map[string]any) (string, string) { return "TRUE", "" })
	c = newTestClient(t, f)
	if _, err := c.Exec(ctx, "noop", map[string]any{"bad": make(chan int)}); err == nil ||
		!strings.Contains(err.Error(), "encoding request") {
		t.Fatalf("expected an encoding error, got %v", err)
	}
}

func TestExec_FloodRetriesAreBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the flood backoff")
	}
	f := kasapitest.New(t, func(string, map[string]any) (string, string) { return "", "flood_protection" })
	c := newTestClient(t, f)
	_, err := c.Exec(context.Background(), "noop", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "flood_protection" {
		t.Fatalf("expected flood_protection after the retries, got %v", err)
	}
	if got := f.APICalls.Load(); got != 4 {
		t.Fatalf("expected 1 attempt and 3 retries, got %d calls", got)
	}
}

func TestExec_FloodRetryStopsOnCancel(t *testing.T) {
	f := kasapitest.New(t, func(string, map[string]any) (string, string) { return "", "flood_protection" })
	c := newTestClient(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Exec(ctx, "noop", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the context error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("a cancelled context must end the backoff, took %v", elapsed)
	}
}

func TestExec_SessionErrorTwiceIsReturned(t *testing.T) {
	// The server rejects every token: one re-authentication, then the error.
	f := kasapitest.New(t, func(string, map[string]any) (string, string) { return "", "session_expired" })
	c := newTestClient(t, f)
	_, err := c.Exec(context.Background(), "noop", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "session_expired" {
		t.Fatalf("expected session_expired, got %v", err)
	}
	if got := f.AuthCalls.Load(); got != 2 {
		t.Fatalf("expected exactly one re-authentication, auth calls: %d", got)
	}
}

func TestExec_TruncatedBody(t *testing.T) {
	// A connection that dies mid-body is a read error, not a parse result.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		fmt.Fprint(w, "<r><return>tok")
	}))
	t.Cleanup(srv.Close)
	c, _ := New(Config{Login: "w1", Password: "p", APIEndpoint: srv.URL, AuthEndpoint: srv.URL, HTTPClient: srv.Client()})
	if _, err := c.Exec(context.Background(), "noop", nil); err == nil || !strings.Contains(err.Error(), "reading response") {
		t.Fatalf("expected a read error, got %v", err)
	}
}
