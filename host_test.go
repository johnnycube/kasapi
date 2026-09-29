// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"reflect"
	"strings"
	"testing"
)

func TestHostSettings_IsZeroAndValidate(t *testing.T) {
	if !(HostSettings{}).isZero() {
		t.Fatal("empty settings must be zero")
	}
	for _, hs := range []HostSettings{
		{Path: "/x/"}, {RedirectStatus: new(0)}, {PHPVersion: "8.4"}, {Active: new(false)},
	} {
		if hs.isZero() {
			t.Errorf("%+v must not be zero", hs)
		}
	}

	for _, status := range []int{0, 301, 302, 307} {
		hs := HostSettings{Path: "https://example.org", RedirectStatus: new(status)}
		if err := hs.validate(); err != nil {
			t.Errorf("status %d: %v", status, err)
		}
	}
	for _, status := range []int{-1, 200, 303, 308, 404} {
		hs := HostSettings{Path: "https://example.org", RedirectStatus: new(status)}
		if err := hs.validate(); err == nil {
			t.Errorf("status %d must be rejected", status)
		}
	}
	// A redirect needs its target; switching the redirect off does not.
	if err := (HostSettings{RedirectStatus: new(301)}).validate(); err == nil ||
		!strings.Contains(err.Error(), "redirect target") {
		t.Fatalf("redirect without target: %v", err)
	}
	if err := (HostSettings{RedirectStatus: new(0)}).validate(); err != nil {
		t.Fatalf("status 0 without path: %v", err)
	}
	if err := (HostSettings{}).validate(); err != nil {
		t.Fatalf("empty settings: %v", err)
	}
}

func TestHostSettings_Params(t *testing.T) {
	params := map[string]any{"subdomain_name": "blog.example.com"}
	HostSettings{
		Path: "https://example.org", RedirectStatus: new(301),
		PHPVersion: "8.4", Active: new(false),
	}.params(params, "subdomain_path")
	want := map[string]any{
		"subdomain_name":  "blog.example.com",
		"subdomain_path":  "https://example.org",
		"redirect_status": 301,
		"php_version":     "8.4",
		"is_active":       "N",
	}
	if !reflect.DeepEqual(params, want) {
		t.Fatalf("got %#v, want %#v", params, want)
	}

	// Unset fields are not sent; the path key follows the caller.
	params = map[string]any{}
	HostSettings{Path: "/web/", Active: new(true)}.params(params, "domain_path")
	want = map[string]any{"domain_path": "/web/", "is_active": "Y"}
	if !reflect.DeepEqual(params, want) {
		t.Fatalf("got %#v, want %#v", params, want)
	}
	params = map[string]any{}
	HostSettings{}.params(params, "domain_path")
	if len(params) != 0 {
		t.Fatalf("empty settings must send nothing, got %#v", params)
	}
}

func TestHostTLSFrom(t *testing.T) {
	got := hostTLSFrom(map[string]any{
		"ssl_certificate_sni_is_active":    "j",
		"ssl_certificate_sni_type":         "LE90D",
		"ssl_certificate_sni_force_https":  "Y",
		"ssl_certificate_sni_hsts_max_age": "31536000",
		"ssl_certificate_sni_crt":          "CRT",
		"ssl_certificate_sni_bundle":       "BUNDLE",
		"ssl_certificate_sni_key":          "PRIVATE",
	})
	want := HostTLS{
		Active: true, Type: "LE90D", ForceHTTPS: true, HSTSMaxAge: 31536000,
		Certificate: "CRT", Bundle: "BUNDLE",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// The private key of the response must not surface anywhere.
	if v := reflect.ValueOf(got); v.NumField() != 6 {
		t.Fatalf("HostTLS grew a field; check that it is not the private key: %+v", got)
	}

	// Unset fields: HSTS off is -1, not 0.
	got = hostTLSFrom(map[string]any{
		"ssl_certificate_sni_is_active":    "",
		"ssl_certificate_sni_hsts_max_age": "",
	})
	if got.Active || got.ForceHTTPS || got.HSTSMaxAge != -1 {
		t.Fatalf("unset fields: %+v", got)
	}
	got = hostTLSFrom(map[string]any{"ssl_certificate_sni_hsts_max_age": "-1"})
	if got.HSTSMaxAge != -1 {
		t.Fatalf("explicit -1: %+v", got)
	}
	got = hostTLSFrom(map[string]any{"ssl_certificate_sni_hsts_max_age": "0"})
	if got.HSTSMaxAge != 0 {
		t.Fatalf("explicit 0: %+v", got)
	}
}

func TestHostTLS_LetsEncrypt(t *testing.T) {
	for typ, want := range map[string]bool{
		"LE90D": true, "le90d": true, "unknown": false, "": false, "custom": false,
	} {
		if got := (HostTLS{Type: typ}).LetsEncrypt(); got != want {
			t.Errorf("LetsEncrypt(%q) = %v, want %v", typ, got, want)
		}
	}
}
