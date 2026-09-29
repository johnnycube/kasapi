// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCert returns a self-signed certificate and its key, PEM-encoded.
func testCert(t *testing.T, hosts ...string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func TestTLS_UpdateInstallsCertificate(t *testing.T) {
	cert, key := testCert(t, "example.com", "www.example.com")
	bundle, _ := testCert(t, "Intermediate CA")
	c, rec := newFake(t, map[string]string{"update_ssl": "TRUE"})

	err := c.TLS.Update(context.Background(), "www.example.com", TLSUpdate{
		Certificate: cert, Key: key, Bundle: bundle, CSR: "CSR",
		Active: new(true), ForceHTTPS: new(true), HSTSMaxAge: new(31536000),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	wantParams(t, rec.last(t, "update_ssl"), map[string]string{
		"hostname":                     "www.example.com",
		"ssl_certificate_sni_crt":      cert,
		"ssl_certificate_sni_key":      key,
		"ssl_certificate_sni_bundle":   bundle,
		"ssl_certificate_sni_csr":      "CSR",
		"ssl_certificate_is_active":    "Y",
		"ssl_certificate_force_https":  "Y",
		"ssl_certificate_hsts_max_age": "31536000",
	})
}

func TestTLS_UpdateSettingsOnly(t *testing.T) {
	c, rec := newFake(t, map[string]string{"update_ssl": "TRUE"})
	err := c.TLS.Update(context.Background(), "example.com", TLSUpdate{
		ForceHTTPS: new(false), HSTSMaxAge: new(-1),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := rec.last(t, "update_ssl")
	wantParams(t, got, map[string]string{
		"hostname": "example.com", "ssl_certificate_force_https": "N", "ssl_certificate_hsts_max_age": "-1",
	})
	wantAbsent(t, got, "ssl_certificate_sni_crt", "ssl_certificate_sni_key",
		"ssl_certificate_sni_bundle", "ssl_certificate_sni_csr", "ssl_certificate_is_active")
}

func TestTLS_UpdateHasNoACMEParameter(t *testing.T) {
	cert, key := testCert(t, "example.com")
	c, rec := newFake(t, map[string]string{"update_ssl": "TRUE"})
	if err := c.TLS.Update(context.Background(), "example.com", TLSUpdate{Certificate: cert, Key: key}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	for k := range rec.last(t, "update_ssl") {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "acme") || strings.Contains(lower, "letsencrypt") || strings.Contains(lower, "lets_encrypt") {
			t.Fatalf("unexpected parameter %q", k)
		}
	}
}

func TestTLS_UpdateValidation(t *testing.T) {
	ctx := context.Background()
	cert, key := testCert(t, "example.com")
	otherCert, otherKey := testCert(t, "example.com")
	c, rec := newFake(t, map[string]string{"update_ssl": "TRUE"})

	for name, tc := range map[string]struct {
		host string
		u    TLSUpdate
		want string
	}{
		"no hostname":         {"", TLSUpdate{Active: new(true)}, "hostname must not be empty"},
		"nothing to update":   {"example.com", TLSUpdate{}, "no TLS setting"},
		"certificate alone":   {"example.com", TLSUpdate{Certificate: cert}, "set together"},
		"key alone":           {"example.com", TLSUpdate{Key: key}, "set together"},
		"key of another cert": {"example.com", TLSUpdate{Certificate: cert, Key: otherKey}, "do not form a pair"},
		"cert of another key": {"example.com", TLSUpdate{Certificate: otherCert, Key: key}, "do not form a pair"},
		"not PEM":             {"example.com", TLSUpdate{Certificate: "junk", Key: "junk"}, "do not form a pair"},
		"wrong host":          {"shop.example.com", TLSUpdate{Certificate: cert, Key: key}, "does not cover shop.example.com"},
		"HSTS below -1":       {"example.com", TLSUpdate{HSTSMaxAge: new(-2)}, "HSTS max-age"},
		"bundle not PEM":      {"example.com", TLSUpdate{Certificate: cert, Key: key, Bundle: "junk"}, "bundle"},
		"bundle holds a key":  {"example.com", TLSUpdate{Certificate: cert, Key: key, Bundle: key}, "unexpected PEM block"},
	} {
		err := c.TLS.Update(ctx, tc.host, tc.u)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
	if rec.count("update_ssl") != 0 {
		t.Fatal("invalid input must not reach the API — the private key would travel with it")
	}
}

func TestValidateCertificates(t *testing.T) {
	one, key := testCert(t, "a.example.com")
	two, _ := testCert(t, "b.example.com")
	if err := validateCertificates(one + two); err != nil {
		t.Fatalf("two certificates: %v", err)
	}
	if err := validateCertificates(""); err == nil {
		t.Fatal("empty input must fail")
	}
	if err := validateCertificates(one + key); err == nil {
		t.Fatal("a key inside the bundle must fail")
	}
	broken := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}))
	if err := validateCertificates(broken); err == nil {
		t.Fatal("a certificate block without a certificate must fail")
	}
}

func TestTLS_UpdateFaults(t *testing.T) {
	ctx := context.Background()
	u := TLSUpdate{ForceHTTPS: new(true)}

	c, _ := newFake(t, map[string]string{"update_ssl": "!nothing_to_do"})
	if err := c.TLS.Update(ctx, "example.com", u); err != nil {
		t.Fatalf("nothing_to_do must be success, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"update_ssl": "!ssl_certificate_hostname_not_in_crt"})
	err := c.TLS.Update(ctx, "example.com", u)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !strings.Contains(err.Error(), "updating TLS of example.com") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestTLS_Get(t *testing.T) {
	ctx := context.Background()

	// A domain answers on the first lookup.
	c, rec := newFake(t, map[string]string{
		"get_domains":    domainEntry("example.com"),
		"get_subdomains": subdomainEntry("blog.example.com"),
	})
	state, err := c.TLS.Get(ctx, "example.com")
	if err != nil || !state.Active || state.LetsEncrypt() {
		t.Fatalf("domain: %+v %v", state, err)
	}
	if rec.count("get_subdomains") != 0 {
		t.Fatal("a domain hit must not query subdomains")
	}

	// A subdomain is found on the second.
	state, err = c.TLS.Get(ctx, "blog.example.com")
	if err != nil || !state.LetsEncrypt() || state.HSTSMaxAge != 300 {
		t.Fatalf("subdomain: %+v %v", state, err)
	}

	if _, err := c.TLS.Get(ctx, "missing.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.TLS.Get(ctx, ""); err == nil {
		t.Fatal("Get without hostname must fail")
	}

	// A fault on the domain lookup is not mistaken for "not a domain".
	c, rec = newFake(t, map[string]string{"get_domains": "!kas_error", "get_subdomains": subdomainEntry("x.example.com")})
	if _, err := c.TLS.Get(ctx, "x.example.com"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the fault, got %v", err)
	}
	if rec.count("get_subdomains") != 0 {
		t.Fatal("a failed domain lookup must not fall through to subdomains")
	}
}
