// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapitest

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// post sends params as a SOAP request and returns status and body.
func post(t *testing.T, url string, params map[string]any) (int, string) {
	t.Helper()
	doc, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("encoding params: %v", err)
	}
	escaped := strings.NewReplacer("&", "&amp;", `"`, "&#34;", "<", "&lt;", ">", "&gt;").Replace(string(doc))
	body := `<Envelope><Body><KasApi><Params xsi:type="xsd:string">` + escaped + `</Params></KasApi></Body></Envelope>`
	resp, err := http.Post(url, "text/xml", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func echo(action string, params map[string]any) (string, string) {
	if action == "fail" {
		return "", "zone_not_found"
	}
	return MapItem("action", action) + MapItem("zone", params["zone_host"].(string)), ""
}

func TestServer_Endpoints(t *testing.T) {
	s := New(t, echo)
	if !strings.HasSuffix(s.AuthURL(), "/KasAuth.php") || !strings.HasSuffix(s.APIURL(), "/KasApi.php") {
		t.Fatalf("endpoints: %s %s", s.AuthURL(), s.APIURL())
	}
	if s.Password != "secret" || s.Token != "session-token-1" || s.OTP != "" {
		t.Fatalf("defaults: %+v", s)
	}
}

func TestServer_Auth(t *testing.T) {
	s := New(t, echo)

	for name, req := range map[string]map[string]any{
		"sha1":  {"kas_auth_type": "sha1", "kas_auth_data": sha1Hex("secret"), "session_lifetime": 900},
		"plain": {"kas_auth_type": "plain", "kas_auth_data": "secret"},
	} {
		status, body := post(t, s.AuthURL(), req)
		if status != http.StatusOK || !strings.Contains(body, ">session-token-1</return>") {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}
	if got := s.SessionLifetime.Load(); got != 900 {
		t.Fatalf("session lifetime recorded as %d", got)
	}

	for name, req := range map[string]map[string]any{
		"wrong password":    {"kas_auth_type": "plain", "kas_auth_data": "nope"},
		"plain as sha1":     {"kas_auth_type": "sha1", "kas_auth_data": "secret"},
		"unknown auth type": {"kas_auth_type": "md5", "kas_auth_data": "secret"},
		"no credentials":    {},
	} {
		status, body := post(t, s.AuthURL(), req)
		if status != http.StatusInternalServerError || !strings.Contains(body, "<faultstring>kas_login_incorrect</faultstring>") {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}
	if got := s.AuthCalls.Load(); got != 6 {
		t.Fatalf("auth calls: %d", got)
	}
	if got := s.APICalls.Load(); got != 0 {
		t.Fatalf("api calls: %d", got)
	}

	// Custom credentials.
	s.Password, s.Token = "other", "tok-2"
	_, body := post(t, s.AuthURL(), map[string]any{"kas_auth_type": "plain", "kas_auth_data": "other"})
	if !strings.Contains(body, ">tok-2</return>") {
		t.Fatalf("custom token: %s", body)
	}
}

func TestServer_OTP(t *testing.T) {
	s := New(t, echo)
	s.OTP = "123456"
	base := map[string]any{"kas_auth_type": "plain", "kas_auth_data": "secret"}

	_, body := post(t, s.AuthURL(), base)
	if !strings.Contains(body, "kas_2fa_incorrect") {
		t.Fatalf("missing PIN: %s", body)
	}
	_, body = post(t, s.AuthURL(), map[string]any{"kas_auth_type": "plain", "kas_auth_data": "secret", "session_2fa": "000000"})
	if !strings.Contains(body, "kas_2fa_incorrect") {
		t.Fatalf("wrong PIN: %s", body)
	}
	status, body := post(t, s.AuthURL(), map[string]any{"kas_auth_type": "plain", "kas_auth_data": "secret", "session_2fa": "123456"})
	if status != http.StatusOK || !strings.Contains(body, "session-token-1") {
		t.Fatalf("right PIN: %d %s", status, body)
	}
	// A wrong password is reported before the PIN is looked at.
	_, body = post(t, s.AuthURL(), map[string]any{"kas_auth_type": "plain", "kas_auth_data": "nope", "session_2fa": "123456"})
	if !strings.Contains(body, "kas_login_incorrect") {
		t.Fatalf("wrong password with PIN: %s", body)
	}
}

func TestServer_API(t *testing.T) {
	s := New(t, echo)

	status, body := post(t, s.APIURL(), map[string]any{
		"kas_auth_data": "session-token-1", "kas_action": "get_dns_settings",
		"KasRequestParams": map[string]any{"zone_host": "a&b <x>"},
	})
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	for _, want := range []string{
		"<key>ReturnString</key><value>TRUE</value>",
		"<key>action</key><value>get_dns_settings</value>",
		// Escaped parameters arrive decoded at the handler.
		"<key>zone</key><value>a&b <x></value>",
		"<key>KasFloodDelay</key>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response lacks %q:\n%s", want, body)
		}
	}

	status, body = post(t, s.APIURL(), map[string]any{"kas_auth_data": "session-token-1", "kas_action": "fail"})
	if status != http.StatusInternalServerError || !strings.Contains(body, "<faultstring>zone_not_found</faultstring>") {
		t.Fatalf("handler fault: %d %s", status, body)
	}

	status, body = post(t, s.APIURL(), map[string]any{"kas_auth_data": "stale", "kas_action": "get_dns_settings"})
	if status != http.StatusInternalServerError || !strings.Contains(body, "session_expired") {
		t.Fatalf("stale token: %d %s", status, body)
	}
	if got := s.APICalls.Load(); got != 3 {
		t.Fatalf("api calls: %d", got)
	}
}

func TestServer_MalformedRequests(t *testing.T) {
	s := New(t, echo)

	resp, err := http.Post(s.APIURL(), "text/xml", strings.NewReader("<Envelope/>"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a request without Params must be rejected, got %d", resp.StatusCode)
	}

	resp, err = http.Post(s.APIURL(), "text/xml", strings.NewReader("<Params>{not json</Params>"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a request without JSON must be rejected, got %d", resp.StatusCode)
	}
	if s.APICalls.Load() != 0 || s.AuthCalls.Load() != 0 {
		t.Fatal("malformed requests must not count as calls")
	}
}

func TestHelpers(t *testing.T) {
	if got := MapItem("k", "v"); got != "<item><key>k</key><value>v</value></item>" {
		t.Fatalf("MapItem: %s", got)
	}
	env := Envelope("<return>x</return>")
	if !strings.HasPrefix(env, `<?xml version="1.0"?>`) || !strings.Contains(env, "<return>x</return>") ||
		!strings.Contains(env, "SOAP-ENV:Body") {
		t.Fatalf("Envelope: %s", env)
	}
	for in, want := range map[string]string{
		"&quot;a&quot;": `"a"`,
		"&#34;a&#34;":   `"a"`,
		"&apos;&#39;":   "''",
		"&lt;b&gt;":     "<b>",
		"a &amp; b":     "a & b",
		"&amp;lt;":      "&lt;",
		"plain":         "plain",
	} {
		if got := xmlUnescape(in); got != want {
			t.Errorf("xmlUnescape(%q) = %q, want %q", in, got, want)
		}
	}
}
