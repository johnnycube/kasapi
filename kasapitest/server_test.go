// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapitest

import (
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

func echo(action string, params map[string]any) (string, string) {
	if action == "fail" {
		return "", "zone_not_found"
	}
	return MapItem("action", action) + MapItem("zone", params["zone_host"].(string)), ""
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
