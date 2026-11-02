// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johnnycube/kasapi/kasapitest"
)

// realResponse renders a KasApi answer in the layout KAS uses: the request
// echoed first, the flood delay inside Response.
func realResponse(action, floodDelay, returnInfo string, params ...string) string {
	echo := ""
	for i := 0; i+1 < len(params); i += 2 {
		echo += kasapitest.MapItem(params[i], params[i+1])
	}
	return kasapitest.Envelope(`<return>` +
		kasapitest.MapItem("Request", kasapitest.MapItem("KasRequestType", action)+kasapitest.MapItem("KasRequestParams", echo)) +
		kasapitest.MapItem("Response", kasapitest.MapItem("KasFloodDelay", floodDelay)+
			kasapitest.MapItem("ReturnString", "TRUE")+kasapitest.MapItem("ReturnInfo", returnInfo)) +
		`</return>`)
}

func TestExec_FloodDelayComesFromResponse(t *testing.T) {
	c := rawServer(t, tokenBody, 200, realResponse("get_domains", "0.05", "TRUE"))
	start := time.Now()
	if _, err := c.Exec(context.Background(), "get_domains", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if d := c.notBefore.Sub(start); d < 30*time.Millisecond || d > 200*time.Millisecond {
		t.Fatalf("KasFloodDelay of 0.05 inside Response applied as %v", d)
	}
}

func TestExec_MalformedResponseNamesTheShapeOnly(t *testing.T) {
	// A response without Response still echoes the request, password included.
	body := kasapitest.Envelope(`<return>` +
		kasapitest.MapItem("Request", kasapitest.MapItem("KasRequestParams", kasapitest.MapItem("ftp_password", "S3cret!"))) +
		`</return>`)
	c := rawServer(t, tokenBody, 200, body)
	_, err := c.FTP.Create(context.Background(), FTPUser{Comment: "x"}, "S3cret!")
	if err == nil || strings.Contains(err.Error(), "S3cret!") {
		t.Fatalf("the error must not echo the request: %v", err)
	}
	if !strings.Contains(err.Error(), "malformed response: a map with keys Request") {
		t.Fatalf("the error must name the shape: %v", err)
	}
	for _, tc := range []struct {
		in   any
		want string
	}{
		{nil, "nothing"}, {"x", "a string"}, {[]any{"a", "b"}, "a list of 2"}, {7, "int"},
	} {
		if got := shapeOf(tc.in); got != tc.want {
			t.Errorf("shapeOf(%#v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExec_DoesNotFollowRedirects(t *testing.T) {
	received := false
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(sink.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)

	c, err := New(Config{Login: "w1", Password: "p", APIEndpoint: redirect.URL, AuthEndpoint: redirect.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Exec(context.Background(), "noop", nil)
	if err == nil || !strings.Contains(err.Error(), "unexpected HTTP status 307") {
		t.Fatalf("a redirect must be an error, got %v", err)
	}
	if received {
		t.Fatal("the credentials were posted to the redirect target")
	}
}

func TestNew_RequiresHTTPS(t *testing.T) {
	for _, endpoint := range []string{"http://kasapi.kasserver.com/soap/KasApi.php", "ftp://127.0.0.1/x", "https://", "://"} {
		_, err := New(Config{Login: "w1", Password: "p", APIEndpoint: endpoint})
		if err == nil || !strings.Contains(err.Error(), "API endpoint") {
			t.Errorf("endpoint %q: expected an error, got %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"https://kasapi.kasserver.com/soap/KasApi.php", "http://127.0.0.1:1/x", "http://[::1]:1/x", "http://localhost/x"} {
		if _, err := New(Config{Login: "w1", Password: "p", AuthEndpoint: endpoint}); err != nil {
			t.Errorf("endpoint %q: %v", endpoint, err)
		}
	}
}

func TestExec_FailedHandshakeIsNotRetried(t *testing.T) {
	// KasAuth itself rejects the credentials with a code the API also uses
	// for a rejected session: one attempt, no second login with the same data.
	authCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		authCalls++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<e><Body><Fault><faultstring>kas_auth_data_incorrect</faultstring></Fault></Body></e>`))
	}))
	t.Cleanup(srv.Close)
	c, _ := New(Config{Login: "w1", Password: "p", APIEndpoint: srv.URL, AuthEndpoint: srv.URL})
	_, err := c.Exec(context.Background(), "noop", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "kas_auth_data_incorrect" || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected the handshake fault, got %v", err)
	}
	if authCalls != 1 {
		t.Fatalf("expected one handshake, got %d", authCalls)
	}
}

func TestSession_LifetimeAndRefresh(t *testing.T) {
	for lifetime, want := range map[int]time.Duration{1800: 29 * time.Minute, 120: time.Minute, 30: 15 * time.Second, 1: 500 * time.Millisecond} {
		c, _ := New(Config{Login: "w1", Password: "p", SessionLifetime: lifetime})
		if got := c.sessionTTL(); got != want {
			t.Errorf("sessionTTL(%d) = %v, want %v", lifetime, got, want)
		}
	}

	// Every successful call extends the session, as KAS does on its side.
	srv := kasapitest.New(t, func(string, map[string]any) (string, string) { return "TRUE", "" })
	c := newTestClient(t, srv)
	if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	first := c.tokenExp
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Exec(context.Background(), "noop", nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !c.tokenExp.After(first) {
		t.Fatal("a call must extend the session")
	}
	if got := srv.AuthCalls.Load(); got != 1 {
		t.Fatalf("expected one login, got %d", got)
	}
}

func TestExec_WaitingForTheLockHonoursContext(t *testing.T) {
	srv := kasapitest.New(t, func(string, map[string]any) (string, string) { return "TRUE", "" })
	c := newTestClient(t, srv)
	// Another call holds the client.
	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Exec(ctx, "noop", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the context error, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the caller must not wait for the lock past its deadline")
	}
	if err := c.Logout(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Logout must give up as well, got %v", err)
	}
	if srv.APICalls.Load() != 0 {
		t.Fatal("no request may leave while waiting")
	}
}
