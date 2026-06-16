// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

// Package kasapitest provides an in-process fake of the KAS SOAP API for tests.
// KasAuth issues a session token (verifying sha1/plain credentials); KasApi
// validates the token and delegates to a per-action handler. Point a client at
// it via KAS_API_ENDPOINT / KAS_AUTH_ENDPOINT to run without real credentials.
package kasapitest

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// Handler returns the ReturnInfo XML fragment (apache Map / SOAP-ENC notation)
// for an action, or a non-empty fault code to send a SOAP fault instead.
type Handler func(action string, params map[string]any) (returnInfoXML, faultCode string)

// Server is a fake KAS API listening on a local httptest server.
type Server struct {
	*httptest.Server

	// Password is the plaintext password the server expects (default
	// "secret"); sha1 auth is verified against its digest.
	Password string
	// Token is the session token issued by KasAuth (default "session-token-1").
	Token string

	AuthCalls atomic.Int64
	APICalls  atomic.Int64

	handler Handler
}

var paramsRe = regexp.MustCompile(`(?s)<Params[^>]*>(.*?)</Params>`)

// New starts a fake KAS server; it is closed automatically via t.Cleanup.
func New(t testing.TB, handler Handler) *Server {
	s := &Server{Password: "secret", Token: "session-token-1", handler: handler}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Server.Close)
	return s
}

// AuthURL returns the KasAuth endpoint of the fake server.
func (s *Server) AuthURL() string { return s.URL + "/KasAuth.php" }

// APIURL returns the KasApi endpoint of the fake server.
func (s *Server) APIURL() string { return s.URL + "/KasApi.php" }

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m := paramsRe.FindSubmatch(body)
	if m == nil {
		http.Error(w, "no Params", http.StatusBadRequest)
		return
	}

	var req map[string]any
	if err := json.Unmarshal([]byte(xmlUnescape(string(m[1]))), &req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")

	if strings.Contains(r.URL.Path, "KasAuth") {
		s.AuthCalls.Add(1)
		ok := false
		switch req["kas_auth_type"] {
		case "sha1":
			sum := sha1.Sum([]byte(s.Password))
			ok = req["kas_auth_data"] == hex.EncodeToString(sum[:])
		case "plain":
			ok = req["kas_auth_data"] == s.Password
		}
		if !ok {
			s.WriteFault(w, "kas_login_incorrect")
			return
		}
		fmt.Fprint(w, Envelope(`<return xsi:type="xsd:string">`+s.Token+`</return>`))
		return
	}

	s.APICalls.Add(1)
	if req["kas_auth_data"] != s.Token {
		s.WriteFault(w, "session_expired")
		return
	}

	action, _ := req["kas_action"].(string)
	params, _ := req["KasRequestParams"].(map[string]any)

	info, fault := s.handler(action, params)
	if fault != "" {
		s.WriteFault(w, fault)
		return
	}
	fmt.Fprint(w, Envelope(`<return>
  <item><key>Request</key><value></value></item>
  <item><key>Response</key><value>
    <item><key>ReturnString</key><value>TRUE</value></item>
    <item><key>ReturnInfo</key><value>`+info+`</value></item>
  </value></item>
  <item><key>KasFloodDelay</key><value>0.01</value></item>
</return>`))
}

// Envelope wraps inner XML in a minimal SOAP envelope.
func Envelope(inner string) string {
	return `<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema">
 <SOAP-ENV:Body><ns1:Response xmlns:ns1="urn:test">` + inner + `</ns1:Response></SOAP-ENV:Body>
</SOAP-ENV:Envelope>`
}

// WriteFault writes a SOAP fault with the given symbolic code.
func (s *Server) WriteFault(w http.ResponseWriter, code string) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, `<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
 <SOAP-ENV:Body><SOAP-ENV:Fault>
  <faultcode>SOAP-ENV:Server</faultcode>
  <faultstring>`+code+`</faultstring>
 </SOAP-ENV:Fault></SOAP-ENV:Body>
</SOAP-ENV:Envelope>`)
}

// MapItem renders one <item><key>k</key><value>v</value></item> pair.
func MapItem(key, value string) string {
	return "<item><key>" + key + "</key><value>" + value + "</value></item>"
}

func xmlUnescape(s string) string {
	r := strings.NewReplacer("&quot;", `"`, "&apos;", "'", "&lt;", "<", "&gt;", ">", "&#34;", `"`, "&#39;", "'", "&amp;", "&")
	return r.Replace(s)
}
