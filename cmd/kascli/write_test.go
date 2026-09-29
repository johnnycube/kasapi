// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCLI_CreateDNSRecord(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_dns_settings": "4711"})
	out := capture(t, "create", "dns", "--zone", "example.com", "--name", "www", "--type", "a", "--data", "203.0.113.1", "--aux", "5")
	if strings.TrimSpace(out) != "dnsrecord/4711 created" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "add_dns_settings"), map[string]string{
		"zone_host": "example.com.", "record_name": "www", "record_type": "A",
		"record_data": "203.0.113.1", "record_aux": "5",
	})

	// The canonical and plural names work as well.
	capture(t, "create", "dnsrecord", "-z", "example.com", "--type", "TXT", "--data", "v=spf1 -all")
	capture(t, "create", "dnsrecords", "-z", "example.com", "--type", "TXT", "--data", "x")

	before := rec.total()
	wantErr(t, "--zone, --type and --data are required", "create", "dns", "--zone", "example.com")
	wantErr(t, "--zone, --type and --data are required", "create", "dns", "--type", "A", "--data", "x")
	if rec.total() != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestCLI_CreateMailAccount(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_mailaccount": "m7654321"})
	setStdin(t, "S3cure!pass\n")
	out := capture(t, "create", "ma", "--address", "info@example.com", "--password-stdin",
		"--copy", "a@example.org,b@example.org", "--sender-alias", "alias@example.com", "--allow-net", "webmail")
	if strings.TrimSpace(out) != "mailaccount/m7654321 created" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "add_mailaccount"), map[string]string{
		"local_part": "info", "domain_part": "example.com", "mail_password": "S3cure!pass",
		"copy_adress": "a@example.org,b@example.org", "mail_sender_alias": "alias@example.com",
		"mail_allow_nets": "webmail",
	})

	// Without --password-stdin the prompt reads the next line.
	setStdin(t, "prompted-pass\n")
	capture(t, "create", "mailaccount", "--address", "two@example.com")
	wantParams(t, rec.last(t, "add_mailaccount"), map[string]string{"mail_password": "prompted-pass"})

	before := rec.total()
	wantErr(t, "--address", "create", "ma", "--address", "no-at-sign", "--password-stdin")
	wantErr(t, "--address", "create", "ma", "--password-stdin")
	setStdin(t, "")
	wantErr(t, "reading input", "create", "ma", "--address", "info@example.com", "--password-stdin")
	setStdin(t, "\n")
	wantErr(t, "empty input", "create", "ma", "--address", "info@example.com", "--password-stdin")
	if rec.total() != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestCLI_PasswordsAreNotFlags(t *testing.T) {
	// No create or update command may take a secret as a flag value.
	root := newRootCmd()
	for _, verb := range []string{"create", "update"} {
		parent, _, _ := root.Find([]string{verb})
		for _, sub := range parent.Commands() {
			for _, name := range []string{"password", "http-password", "otp-secret"} {
				if f := sub.Flags().Lookup(name); f != nil {
					t.Errorf("%s %s offers --%s", verb, sub.Name(), name)
				}
			}
		}
	}
}

func TestCLI_CreateMailForward(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_mailforward": "TRUE"})
	out := capture(t, "create", "mf", "--source", "sales@example.com", "--target", "a@example.org", "--target", "b@example.org")
	if strings.TrimSpace(out) != "mailforward/sales@example.com created" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "add_mailforward"), map[string]string{
		"local_part": "sales", "domain_part": "example.com",
		"target_0": "a@example.org", "target_1": "b@example.org",
	})
	wantErr(t, "--source", "create", "mf", "--source", "sales", "--target", "a@example.org")
	wantErr(t, "at least one forward target", "create", "mf", "--source", "sales@example.com")
}

func TestCLI_CreateSubdomain(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_subdomain": "go.example.com"})
	out := capture(t, "create", "sub", "--name", "go", "--domain", "example.com",
		"--path", "https://example.org", "--redirect", "301", "--php", "8.4")
	if strings.TrimSpace(out) != "subdomain/go.example.com created" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "add_subdomain"), map[string]string{
		"subdomain_name": "go", "domain_name": "example.com",
		"subdomain_path": "https://example.org", "redirect_status": "301", "php_version": "8.4",
	})

	// Flags that are not given are not sent.
	capture(t, "create", "subdomain", "--name", "plain", "--domain", "example.com")
	wantAbsent(t, rec.last(t, "add_subdomain"), "subdomain_path", "redirect_status", "php_version", "is_active")

	wantErr(t, "--name and --domain are required", "create", "sub", "--name", "go")
	wantErr(t, "redirect status must be", "create", "sub", "--name", "go", "--domain", "example.com", "--path", "x", "--redirect", "303")
	// KAS takes the active flag on updates only, so create does not offer it.
	wantErr(t, "unknown flag", "create", "sub", "--name", "go", "--domain", "example.com", "--active=false")
}

func TestCLI_CreateFTPUser(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_ftpuser": "f0000004"})
	setStdin(t, "S3cure!pass\n")
	out := capture(t, "create", "ftp", "--path", "/logs/", "--comment", "log reader", "--write=false", "--password-stdin")
	if strings.TrimSpace(out) != "ftpuser/f0000004 created" {
		t.Fatalf("output: %q", out)
	}
	// The flag defaults grant everything.
	wantParams(t, rec.last(t, "add_ftpuser"), map[string]string{
		"ftp_password": "S3cure!pass", "ftp_path": "/logs/", "ftp_comment": "log reader",
		"ftp_permission_read": "Y", "ftp_permission_write": "N", "ftp_permission_list": "Y",
		"ftp_virus_clamav": "Y",
	})
	wantErr(t, "--comment is required", "create", "ftp", "--password-stdin")
}

func TestCLI_CreateDatabase(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_database": "d0123460"})
	setStdin(t, "S3cure!pass\n")
	out := capture(t, "create", "db", "--comment", "shop", "--allowed-host", "203.0.113.7", "--allowed-host", "203.0.113.0/24", "--password-stdin")
	if strings.TrimSpace(out) != "database/d0123460 created" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "add_database"), map[string]string{
		"database_password": "S3cure!pass", "database_comment": "shop",
		"database_allowed_hosts": "203.0.113.7,203.0.113.0/24",
	})
	wantErr(t, "--comment is required", "create", "db", "--password-stdin")
}

func TestCLI_CreateCronjob(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_cronjob": "324700"})
	setStdin(t, "basic-auth-pass\n")
	out := capture(t, "create", "cj", "--url", "example.com/cron.php", "--comment", "nightly",
		"--minute", "30", "--hour", "3", "--mail", "ops@example.com", "--mail-subject", "comment",
		"--http-user", "cron", "--http-password-stdin")
	if strings.TrimSpace(out) != "cronjob/324700 created" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "add_cronjob"), map[string]string{
		"protocol": "https", "http_url": "example.com/cron.php", "cronjob_comment": "nightly",
		"minute": "30", "hour": "3", "day_of_month": "*", "month": "*", "day_of_week": "*",
		"mail_address": "ops@example.com", "mail_subject": "comment",
		"http_user": "cron", "http_password": "basic-auth-pass",
		// A job created from the command line runs unless told otherwise.
		"is_active": "Y",
	})

	capture(t, "create", "cronjob", "--url", "example.com/x", "--comment", "paused", "--active=false", "--protocol", "http")
	got := rec.last(t, "add_cronjob")
	wantParams(t, got, map[string]string{"is_active": "N", "protocol": "http"})
	wantAbsent(t, got, "http_user", "http_password", "mail_address")

	wantErr(t, "--url and --comment are required", "create", "cj", "--url", "example.com/x")
	wantErr(t, "must not carry a protocol", "create", "cj", "--url", "https://example.com/x", "--comment", "c")
	wantErr(t, "HTTP user needs an HTTP password", "create", "cj", "--url", "example.com/x", "--comment", "c", "--http-user", "cron")
}

func TestCLI_CreateDDNSUser(t *testing.T) {
	rec := setupFake(t, map[string]string{"add_ddnsuser": "dyn0000001"})
	setStdin(t, "S3cure!pass\n")
	out := capture(t, "create", "ddns", "--zone", "example.org", "--label", "home",
		"--target-ip", "203.0.113.4", "--comment", "at home", "--dual-stack", "--password-stdin")
	if strings.TrimSpace(out) != "ddnsuser/dyn0000001 created" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "add_ddnsuser"), map[string]string{
		"dyndns_zone": "example.org", "dyndns_label": "home", "dyndns_target_ip": "203.0.113.4",
		"dyndns_comment": "at home", "dyndns_password": "S3cure!pass", "dyndns_dual_stack": "Y",
	})
	wantErr(t, "are required", "create", "ddns", "--zone", "example.org", "--label", "home", "--password-stdin")
}

func TestCLI_CreateAndUpdateUsage(t *testing.T) {
	rec := setupFake(t, map[string]string{})
	wantErr(t, "usage: kascli create", "create")
	wantErr(t, `cannot create "pods"`, "create", "pods")
	wantErr(t, `cannot create "domain"`, "create", "domain")
	wantErr(t, `cannot create "tls"`, "create", "tls")
	wantErr(t, "usage: kascli update", "update")
	wantErr(t, `cannot update "pods"`, "update", "pods")
	wantErr(t, `cannot update "mailfilters"`, "update", "mailfilters")
	wantErr(t, "accepts 1 arg(s)", "update", "sub")
	wantErr(t, "unknown command", "create", "dns", "stray")
	for _, res := range []string{"domain", "sub", "tls", "ma", "ftp", "db", "cj", "ddns"} {
		wantErr(t, "nothing to update", "update", res, "x")
		// A global flag is not a change.
		wantErr(t, "nothing to update", "--context", "test", "update", res, "x", "-o", "json")
	}
	if rec.total() != 0 {
		t.Fatalf("usage errors must not reach the API, got %d calls", rec.total())
	}
}

func TestCLI_UpdateDNSRecord(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"get_dns_settings": entry("record_id", "11", "record_name", "www", "record_type", "A",
			"record_data", "203.0.113.10", "record_aux", "0", "record_changeable", "Y"),
		"update_dns_settings": "TRUE",
	})
	out := capture(t, "update", "dns", "11", "--zone", "example.com", "--data", "203.0.113.99")
	if strings.TrimSpace(out) != "dnsrecord/11 updated" {
		t.Fatalf("output: %q", out)
	}
	// The record is read first: name and aux keep their values.
	wantParams(t, rec.last(t, "update_dns_settings"), map[string]string{
		"record_id": "11", "record_name": "www", "record_data": "203.0.113.99", "record_aux": "0",
	})

	capture(t, "update", "dns", "11", "-z", "example.com", "--name", "", "--aux", "10")
	got := rec.last(t, "update_dns_settings")
	wantParams(t, got, map[string]string{"record_data": "203.0.113.10", "record_aux": "10"})
	if got["record_name"] != "" {
		t.Fatalf("--name \"\" must move the record to the apex, got %v", got)
	}

	before := rec.count("update_dns_settings")
	wantErr(t, "--zone is required", "update", "dns", "11", "--data", "x")
	wantErr(t, "give --name, --data or --aux", "update", "dns", "11", "--zone", "example.com")
	wantErr(t, "not found", "update", "dns", "12", "--zone", "example.com", "--data", "x")
	if rec.count("update_dns_settings") != before {
		t.Fatal("a failed update must not write")
	}
}

func TestCLI_UpdateHosts(t *testing.T) {
	rec := setupFake(t, map[string]string{"update_domain": "TRUE", "update_subdomain": "!nothing_to_do"})

	out := capture(t, "update", "domain", "example.com", "--php", "8.4", "--active=false")
	if strings.TrimSpace(out) != "domain/example.com updated" {
		t.Fatalf("output: %q", out)
	}
	got := rec.last(t, "update_domain")
	wantParams(t, got, map[string]string{"domain_name": "example.com", "php_version": "8.4", "is_active": "N"})
	wantAbsent(t, got, "domain_path", "redirect_status")

	// Switching a redirect off is a change of its own.
	capture(t, "update", "do", "example.com", "--redirect", "0")
	got = rec.last(t, "update_domain")
	wantParams(t, got, map[string]string{"redirect_status": "0"})
	wantAbsent(t, got, "is_active", "php_version")

	// nothing_to_do is success.
	out = capture(t, "update", "sub", "blog.example.com", "--path", "https://example.org", "--redirect", "302")
	if strings.TrimSpace(out) != "subdomain/blog.example.com updated" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "update_subdomain"), map[string]string{
		"subdomain_name": "blog.example.com", "subdomain_path": "https://example.org", "redirect_status": "302",
	})
	wantErr(t, "redirect status must be", "update", "sub", "blog.example.com", "--redirect", "308")
	wantErr(t, "needs the redirect target", "update", "domain", "example.com", "--redirect", "301")
}

// writeCert writes a self-signed certificate and its key as PEM files.
func writeCert(t *testing.T, dir, host string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	certFile = filepath.Join(dir, host+".crt")
	keyFile = filepath.Join(dir, host+".key")
	for path, block := range map[string]*pem.Block{
		certFile: {Type: "CERTIFICATE", Bytes: der},
		keyFile:  {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	return certFile, keyFile
}

func TestCLI_UpdateTLS(t *testing.T) {
	rec := setupFake(t, map[string]string{"update_ssl": "TRUE"})
	dir := t.TempDir()
	cert, key := writeCert(t, dir, "example.com")
	bundle, _ := writeCert(t, dir, "intermediate.example")

	out := capture(t, "update", "tls", "example.com", "--cert", cert, "--key", key, "--bundle", bundle,
		"--force-https", "--hsts-max-age", "31536000")
	if strings.TrimSpace(out) != "tls/example.com updated" {
		t.Fatalf("output: %q", out)
	}
	got := rec.last(t, "update_ssl")
	wantParams(t, got, map[string]string{
		"hostname": "example.com", "ssl_certificate_force_https": "Y", "ssl_certificate_hsts_max_age": "31536000",
	})
	certPEM, _ := os.ReadFile(cert)
	keyPEM, _ := os.ReadFile(key)
	if got["ssl_certificate_sni_crt"] != string(certPEM) || got["ssl_certificate_sni_key"] != string(keyPEM) {
		t.Fatal("certificate and key must be sent as read")
	}
	wantAbsent(t, got, "ssl_certificate_is_active", "ssl_certificate_sni_csr")

	// Settings alone.
	capture(t, "update", "tls", "example.com", "--active=false", "--hsts-max-age", "-1")
	got = rec.last(t, "update_ssl")
	wantParams(t, got, map[string]string{"ssl_certificate_is_active": "N", "ssl_certificate_hsts_max_age": "-1"})
	wantAbsent(t, got, "ssl_certificate_sni_crt", "ssl_certificate_sni_key", "ssl_certificate_force_https")

	before := rec.total()
	wantErr(t, "--cert", "update", "tls", "example.com", "--cert", filepath.Join(dir, "missing.crt"), "--key", key)
	wantErr(t, "set together", "update", "tls", "example.com", "--cert", cert)
	wantErr(t, "does not cover shop.example.com", "update", "tls", "shop.example.com", "--cert", cert, "--key", key)
	if rec.total() != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestCLI_UpdateTLSHelpNamesTheACMELimit(t *testing.T) {
	out := capture(t, "update", "tls", "--help")
	for _, want := range []string{"cannot request a Let's Encrypt", "KAS panel"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q:\n%s", want, out)
		}
	}
	root := newRootCmd()
	cmd, _, _ := root.Find([]string{"update", "tls"})
	for _, name := range []string{"acme", "letsencrypt", "lets-encrypt"} {
		if cmd.Flags().Lookup(name) != nil {
			t.Errorf("update tls offers --%s, which the API cannot do", name)
		}
	}
}

func TestCLI_UpdateMailAccount(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"update_mailaccount": "TRUE", "add_mailstandardfilter": "TRUE", "delete_mailstandardfilter": "TRUE",
	})

	setStdin(t, "N3w!pass\n")
	out := capture(t, "update", "ma", "m1", "--password-stdin", "--copy", "a@example.org",
		"--sender-alias", "alias@example.com", "--allow-net", "203.0.113.0/24,webmail",
		"--state", "receive-disabled", "--webmail-autologin=false",
		"--responder", "on", "--responder-text", "Away.", "--responder-type", "html", "--responder-name", "Jo",
		"--responder-from", "2026-01-01T00:00:00Z", "--responder-until", "2026-02-01T00:00:00Z",
		"--filter", "spamc_move:move=Junk", "--filter", "greyl")
	if strings.TrimSpace(out) != "mailaccount/m1 updated" {
		t.Fatalf("output: %q", out)
	}
	// One request per aspect, each for the right mailbox.
	if n := rec.count("update_mailaccount"); n != 7 {
		t.Fatalf("expected 7 update_mailaccount calls, got %d", n)
	}
	sent := map[string]any{}
	rec.mu.Lock()
	for _, call := range rec.seen["update_mailaccount"] {
		if call["mail_login"] != "m1" {
			t.Errorf("call for the wrong mailbox: %v", call)
		}
		for k, v := range call {
			sent[k] = v
		}
	}
	rec.mu.Unlock()
	wantParams(t, sent, map[string]string{
		"mail_new_password": "N3w!pass", "copy_adress": "a@example.org", "mail_sender_alias": "alias@example.com",
		"mail_allow_nets": "203.0.113.0/24,webmail", "is_active": "N", "webmail_autologin": "N",
		"responder": "1767225600|1769904000", "responder_text": "Away.",
		"mail_responder_content_type": "html", "mail_responder_displayname": "Jo",
	})
	wantParams(t, rec.last(t, "add_mailstandardfilter"), map[string]string{
		"mail_login": "m1", "filter": "spamc_move:move=Junk;greyl",
	})

	// Clearing lists and switching things off.
	capture(t, "update", "ma", "m1", "--copy", "", "--filter", "", "--responder", "off", "--state", "active")
	if rec.count("delete_mailstandardfilter") != 1 {
		t.Fatal(`--filter "" must remove the filters`)
	}
	cleared := false
	rec.mu.Lock()
	for _, call := range rec.seen["update_mailaccount"][7:] {
		if v, ok := call["copy_adress"]; ok && v == "" {
			cleared = true
		}
		if v, ok := call["responder"]; ok && v != "N" {
			t.Errorf("--responder off sent %v", v)
		}
		if _, ok := call["responder_text"]; ok {
			t.Errorf("--responder off must not send a text: %v", call)
		}
	}
	rec.mu.Unlock()
	if !cleared {
		t.Fatal(`--copy "" must clear the copy addresses`)
	}
}

func TestCLI_UpdateMailAccountValidatesBeforeWriting(t *testing.T) {
	rec := setupFake(t, map[string]string{"update_mailaccount": "TRUE"})
	for want, args := range map[string][]string{
		"--state must be":        {"--copy", "a@example.org", "--state", "off"},
		"--responder must be on": {"--copy", "a@example.org", "--responder", "maybe"},
		"need --responder on":    {"--copy", "a@example.org", "--responder-text", "Away."},
		"--responder-from":       {"--responder", "on", "--responder-text", "x", "--responder-from", "tomorrow"},
		"--responder-until":      {"--responder", "on", "--responder-text", "x", "--responder-until", "31.12."},
		"reading input":          {"--copy", "a@example.org", "--password-stdin"},
	} {
		setStdin(t, "")
		wantErr(t, want, append([]string{"update", "ma", "m1"}, args...)...)
	}
	if rec.total() != 0 {
		t.Fatalf("a rejected flag must leave the mailbox untouched, got %d calls", rec.total())
	}

	// Errors of the library surface as they are.
	wantErr(t, "an active responder needs a text", "update", "ma", "m1", "--responder", "on")
	wantErr(t, "invalid copy address", "update", "ma", "m1", "--copy", "nope")
}

func TestCLI_UpdateMailAccountStopsAtTheFirstFault(t *testing.T) {
	rec := setupFake(t, map[string]string{"update_mailaccount": "!mail_login_not_found"})
	wantErr(t, "not found", "update", "ma", "m9", "--state", "active", "--webmail-autologin=true")
	if n := rec.count("update_mailaccount"); n != 1 {
		t.Fatalf("expected the command to stop after the first fault, got %d calls", n)
	}
}

func TestResponderFromFlags(t *testing.T) {
	r, err := responderFromFlags("off", "ignored", "html", "Jo", "2026-01-01", "2026-02-01")
	if err != nil || r.Active || r.Text != "" || !r.Start.IsZero() {
		t.Fatalf("off: %+v %v", r, err)
	}
	r, err = responderFromFlags("on", "Away.", "", "", "", "")
	if err != nil || !r.Active || r.Text != "Away." || !r.Start.IsZero() {
		t.Fatalf("on: %+v %v", r, err)
	}
	r, err = responderFromFlags("on", "Away.", "text", "Jo", "2026-01-01", "2026-02-01T12:00:00+01:00")
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.Local); !r.Start.Equal(want) {
		t.Fatalf("a plain date is local midnight: got %v, want %v", r.Start, want)
	}
	if want := time.Date(2026, 2, 1, 11, 0, 0, 0, time.UTC); !r.End.Equal(want) {
		t.Fatalf("RFC 3339 keeps its offset: got %v, want %v", r.End, want)
	}
	if _, err := responderFromFlags("", "x", "", "", "", ""); err == nil {
		t.Fatal("an empty mode must fail")
	}
}

func TestParseTime(t *testing.T) {
	for _, in := range []string{"2026-01-01", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00+02:00"} {
		if _, err := parseTime(in); err != nil {
			t.Errorf("parseTime(%q): %v", in, err)
		}
	}
	for _, in := range []string{"", "01.01.2026", "2026-13-01", "10:00", "2026-01-01 10:00"} {
		if _, err := parseTime(in); err == nil {
			t.Errorf("parseTime(%q) must fail", in)
		}
	}
}

func TestCLI_UpdateMailForward(t *testing.T) {
	rec := setupFake(t, map[string]string{"update_mailforward": "TRUE"})
	out := capture(t, "update", "mf", "sales@example.com", "--target", "a@example.org,b@example.org")
	if strings.TrimSpace(out) != "mailforward/sales@example.com updated" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "update_mailforward"), map[string]string{
		"mail_forward": "sales@example.com", "target_0": "a@example.org", "target_1": "b@example.org",
	})
	wantErr(t, "--target is required", "update", "mf", "sales@example.com")
	wantErr(t, "--target is required", "update", "mf", "sales@example.com", "--target", "")
	wantErr(t, "expected local@domain", "update", "mf", "sales", "--target", "a@example.org")
}

func TestCLI_UpdateFTPUser(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"get_ftpusers": entry("ftp_login", "f0000001", "ftp_path", "/logs/", "ftp_comment", "log reader",
			"ftp_permission_read", "Y", "ftp_permission_write", "N", "ftp_permission_list", "Y",
			"ftp_virus_clamav", "Y"),
		"update_ftpuser": "TRUE",
	})

	out := capture(t, "update", "ftp", "f0000001", "--write", "--comment", "deploy")
	if strings.TrimSpace(out) != "ftpuser/f0000001 updated" {
		t.Fatalf("output: %q", out)
	}
	// The user is read first: what no flag names keeps its value.
	got := rec.last(t, "update_ftpuser")
	wantParams(t, got, map[string]string{
		"ftp_login": "f0000001", "ftp_comment": "deploy", "ftp_path": "/logs/",
		"ftp_permission_read": "Y", "ftp_permission_write": "Y", "ftp_permission_list": "Y",
		"ftp_virus_clamav": "Y",
	})
	wantAbsent(t, got, "ftp_new_password")

	capture(t, "update", "ftp", "f0000001", "--read=false", "--list=false", "--virus-scan=false", "--path", "/web/")
	wantParams(t, rec.last(t, "update_ftpuser"), map[string]string{
		"ftp_path": "/web/", "ftp_comment": "log reader",
		"ftp_permission_read": "N", "ftp_permission_write": "N", "ftp_permission_list": "N",
		"ftp_virus_clamav": "N",
	})

	// A password change alone does not read or rewrite the settings.
	gets, updates := rec.count("get_ftpusers"), rec.count("update_ftpuser")
	setStdin(t, "N3w!pass\n")
	capture(t, "update", "ftp", "f0000001", "--password-stdin")
	if rec.count("get_ftpusers") != gets || rec.count("update_ftpuser") != updates+1 {
		t.Fatal("a password change must be one request")
	}
	got = rec.last(t, "update_ftpuser")
	wantParams(t, got, map[string]string{"ftp_login": "f0000001", "ftp_new_password": "N3w!pass"})
	wantAbsent(t, got, "ftp_comment", "ftp_permission_read")

	// Settings and password together.
	setStdin(t, "N3w!pass\n")
	updates = rec.count("update_ftpuser")
	capture(t, "update", "ftp", "f0000001", "--comment", "both", "--password-stdin")
	if rec.count("update_ftpuser") != updates+2 {
		t.Fatal("settings and password are two requests")
	}

	wantErr(t, "not found", "update", "ftp", "f0000009", "--comment", "x")
	setStdin(t, "")
	wantErr(t, "reading input", "update", "ftp", "f0000001", "--password-stdin")
}

func TestCLI_UpdateDatabase(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"get_databases": entry("database_name", "d0123460", "database_login", "d0123460",
			"database_comment", "shop", "database_allowed_hosts", "203.0.113.7"),
		"update_database": "TRUE",
	})

	out := capture(t, "update", "db", "d0123460", "--comment", "shop v2")
	if strings.TrimSpace(out) != "database/d0123460 updated" {
		t.Fatalf("output: %q", out)
	}
	wantParams(t, rec.last(t, "update_database"), map[string]string{
		"database_login": "d0123460", "database_comment": "shop v2", "database_allowed_hosts": "203.0.113.7",
	})

	capture(t, "update", "db", "d0123460", "--allowed-host", "")
	got := rec.last(t, "update_database")
	wantParams(t, got, map[string]string{"database_comment": "shop"})
	if v, ok := got["database_allowed_hosts"]; !ok || v != "" {
		t.Fatalf(`--allowed-host "" must close external access, got %v`, got)
	}

	gets := rec.count("get_databases")
	setStdin(t, "N3w!pass\n")
	capture(t, "update", "db", "d0123460", "--password-stdin")
	if rec.count("get_databases") != gets {
		t.Fatal("a password change must not read the database")
	}
	got = rec.last(t, "update_database")
	wantParams(t, got, map[string]string{"database_login": "d0123460", "database_new_password": "N3w!pass"})
	wantAbsent(t, got, "database_comment", "database_allowed_hosts")

	setStdin(t, "N3w!pass\n")
	capture(t, "update", "db", "d0123460", "--comment", "both", "--password-stdin")

	wantErr(t, "not found", "update", "db", "d0000000", "--comment", "x")
	setStdin(t, "")
	wantErr(t, "reading input", "update", "db", "d0123460", "--password-stdin")
}

func TestCLI_UpdateCronjob(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"get_cronjobs": entry("cronjob_id", "325208", "cronjob_comment", "hourly", "protocol", "https",
			"http_url", "example.com/cron.php", "http_user", "cron", "http_password", "stored",
			"minute", "59", "hour", "*/1", "day_of_month", "*", "month", "*", "day_of_week", "*",
			"mail_adress", "ops@example.com", "mail_condition", "OK", "mail_subject", "comment",
			"is_active", "Y"),
		"update_cronjob": "TRUE",
	})

	out := capture(t, "update", "cj", "325208", "--active=false")
	if strings.TrimSpace(out) != "cronjob/325208 updated" {
		t.Fatalf("output: %q", out)
	}
	// Flag defaults must not overwrite the job.
	got := rec.last(t, "update_cronjob")
	wantParams(t, got, map[string]string{
		"cronjob_id": "325208", "is_active": "N", "minute": "59", "hour": "*/1",
		"http_url": "example.com/cron.php", "cronjob_comment": "hourly",
		"mail_address": "ops@example.com", "mail_condition": "OK", "mail_subject": "comment",
	})
	wantAbsent(t, got, "http_user", "http_password")

	setStdin(t, "n3w-basic-auth\n")
	capture(t, "update", "cronjob", "325208", "--url", "example.com/new.php", "--protocol", "http",
		"--comment", "moved", "--minute", "0", "--hour", "4", "--day-of-month", "1", "--month", "6",
		"--day-of-week", "0", "--http-user", "bot", "--http-password-stdin",
		"--mail", "dev@example.com", "--mail-condition", "DONE", "--mail-subject", "default")
	wantParams(t, rec.last(t, "update_cronjob"), map[string]string{
		"http_url": "example.com/new.php", "protocol": "http", "cronjob_comment": "moved",
		"minute": "0", "hour": "4", "day_of_month": "1", "month": "6", "day_of_week": "0",
		"http_user": "bot", "http_password": "n3w-basic-auth",
		"mail_address": "dev@example.com", "mail_condition": "DONE", "mail_subject": "default",
		"is_active": "Y",
	})

	wantErr(t, "not found", "update", "cj", "1", "--active=false")
	setStdin(t, "")
	wantErr(t, "reading input", "update", "cj", "325208", "--http-password-stdin")
}

func TestCLI_UpdateDDNSUser(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"get_ddnsusers": entry("dyndns_login", "dyn0000002", "dyndns_comment", "at home",
			"dyndns_zone", "example.org", "dyndns_label", "home", "dyndns_dual_stack", "Y",
			"dyndns_target_ipv4", "203.0.113.255"),
		"update_ddnsuser": "TRUE",
	})

	out := capture(t, "update", "ddns", "dyn0000002", "--comment", "moved")
	if strings.TrimSpace(out) != "ddnsuser/dyn0000002 updated" {
		t.Fatalf("output: %q", out)
	}
	// Dual stack keeps its value: the flag default must not switch it off.
	wantParams(t, rec.last(t, "update_ddnsuser"), map[string]string{
		"dyndns_login": "dyn0000002", "dyndns_comment": "moved", "dyndns_dual_stack": "Y",
	})
	capture(t, "update", "ddns", "dyn0000002", "--dual-stack=false")
	wantParams(t, rec.last(t, "update_ddnsuser"), map[string]string{"dyndns_comment": "at home", "dyndns_dual_stack": "N"})

	gets := rec.count("get_ddnsusers")
	setStdin(t, "N3w!pass\n")
	capture(t, "update", "ddns", "dyn0000002", "--password-stdin")
	if rec.count("get_ddnsusers") != gets {
		t.Fatal("a password change must not read the user")
	}
	got := rec.last(t, "update_ddnsuser")
	wantParams(t, got, map[string]string{"dyndns_login": "dyn0000002", "dyndns_password": "N3w!pass"})
	wantAbsent(t, got, "dyndns_comment", "dyndns_dual_stack")

	setStdin(t, "N3w!pass\n")
	capture(t, "update", "ddns", "dyn0000002", "--comment", "both", "--password-stdin")

	wantErr(t, "not found", "update", "ddns", "dyn0000009", "--comment", "x")
	setStdin(t, "")
	wantErr(t, "reading input", "update", "ddns", "dyn0000002", "--password-stdin")
}

func TestCLI_WriteFaultsSurface(t *testing.T) {
	setupFake(t, map[string]string{
		"add_dns_settings": "!record_already_exists", "add_mailaccount": "!max_emails_reached",
		"add_mailforward": "!mail_loop_detected", "add_subdomain": "!max_subdomain_reached",
		"add_ftpuser": "!max_ftpuser_reached", "add_database": "!max_database_reached",
		"add_cronjob": "!max_cronjobs_reached", "add_ddnsuser": "!ddns_limit_reached",
		"update_domain": "!in_progress", "update_subdomain": "!in_progress", "update_ssl": "!in_progress",
		"update_mailforward": "!in_progress",
		"get_ftpusers":       entry("ftp_login", "f1", "ftp_comment", "c"), "update_ftpuser": "!in_progress",
		"get_databases": entry("database_login", "d1", "database_comment", "c"), "update_database": "!in_progress",
		"get_cronjobs": entry("cronjob_id", "1", "cronjob_comment", "c", "http_url", "example.com/x"), "update_cronjob": "!in_progress",
		"get_ddnsusers": entry("dyndns_login", "dyn1", "dyndns_comment", "c"), "update_ddnsuser": "!in_progress",
		"get_dns_settings": entry("record_id", "11", "record_name", "www"), "update_dns_settings": "!in_progress",
	})
	for fault, args := range map[string][]string{
		"record_already_exists": {"create", "dns", "-z", "example.com", "--type", "A", "--data", "x"},
		"max_emails_reached":    {"create", "ma", "--address", "a@example.com", "--password-stdin"},
		"mail_loop_detected":    {"create", "mf", "--source", "a@example.com", "--target", "b@example.org"},
		"max_subdomain_reached": {"create", "sub", "--name", "a", "--domain", "example.com"},
		"max_ftpuser_reached":   {"create", "ftp", "--comment", "c", "--password-stdin"},
		"max_database_reached":  {"create", "db", "--comment", "c", "--password-stdin"},
		"max_cronjobs_reached":  {"create", "cj", "--url", "example.com/x", "--comment", "c"},
		"ddns_limit_reached":    {"create", "ddns", "-z", "example.org", "--label", "h", "--target-ip", "203.0.113.1", "--comment", "c", "--password-stdin"},
	} {
		setStdin(t, "pw\n")
		wantErr(t, fault, args...)
	}
	for _, args := range [][]string{
		{"update", "domain", "example.com", "--php", "8.4"},
		{"update", "sub", "a.example.com", "--php", "8.4"},
		{"update", "tls", "example.com", "--force-https"},
		{"update", "mf", "a@example.com", "--target", "b@example.org"},
		{"update", "ftp", "f1", "--comment", "x"},
		{"update", "ftp", "f1", "--password-stdin"},
		{"update", "db", "d1", "--comment", "x"},
		{"update", "db", "d1", "--password-stdin"},
		{"update", "cj", "1", "--comment", "x"},
		{"update", "ddns", "dyn1", "--comment", "x"},
		{"update", "ddns", "dyn1", "--password-stdin"},
		{"update", "dns", "11", "-z", "example.com", "--data", "x"},
	} {
		setStdin(t, "pw\n")
		wantErr(t, "in_progress", args...)
	}
}

func TestWriteCommandsNeedCredentials(t *testing.T) {
	t.Setenv("KASCONFIG", filepath.Join(t.TempDir(), "config"))
	t.Setenv("KAS_LOGIN", "")
	t.Setenv("KAS_PASSWORD", "")
	for _, args := range [][]string{
		{"create", "dns", "-z", "example.com", "--type", "A", "--data", "x"},
		{"create", "ma", "--address", "a@example.com", "--password-stdin"},
		{"create", "mf", "--source", "a@example.com", "--target", "b@example.org"},
		{"create", "sub", "--name", "a", "--domain", "example.com"},
		{"create", "ftp", "--comment", "c", "--password-stdin"},
		{"create", "db", "--comment", "c", "--password-stdin"},
		{"create", "cj", "--url", "example.com/x", "--comment", "c"},
		{"create", "ddns", "-z", "example.org", "--label", "h", "--target-ip", "203.0.113.1", "--comment", "c", "--password-stdin"},
		{"update", "dns", "11", "-z", "example.com", "--data", "x"},
		{"update", "domain", "example.com", "--php", "8.4"},
		{"update", "sub", "a.example.com", "--php", "8.4"},
		{"update", "tls", "example.com", "--force-https"},
		{"update", "ma", "m1", "--state", "active"},
		{"update", "mf", "a@example.com", "--target", "b@example.org"},
		{"update", "ftp", "f1", "--comment", "x"},
		{"update", "db", "d1", "--comment", "x"},
		{"update", "cj", "1", "--comment", "x"},
		{"update", "ddns", "dyn1", "--comment", "x"},
		{"delete", "dns", "11"},
		{"exec", "get_domains"},
	} {
		setStdin(t, "pw\n")
		wantErr(t, "no credentials", args...)
	}
}

func TestHelpersOfWriteCommands(t *testing.T) {
	if got := nonEmpty([]string{" a ", "", "b", "  "}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("nonEmpty: %#v", got)
	}
	if got := nonEmpty(nil); len(got) != 0 {
		t.Fatalf("nonEmpty(nil): %#v", got)
	}
	local, domain, err := splitAddress("info@example.com")
	if err != nil || local != "info" || domain != "example.com" {
		t.Fatalf("splitAddress: %q %q %v", local, domain, err)
	}
	for _, bad := range []string{"", "info", "@example.com", "info@"} {
		if _, _, err := splitAddress(bad); err == nil {
			t.Errorf("splitAddress(%q) must fail", bad)
		}
	}
	if _, err := readPEM("cert", filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "--cert") {
		t.Fatalf("readPEM must name the flag, got %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("an unknown resource is a programming error and must panic")
		}
	}()
	resourceCmd("pods", "", false)
}

func TestNewSecret(t *testing.T) {
	setStdin(t, "from-prompt\n")
	if got, err := newSecret(false, "Password"); err != nil || got != "from-prompt" {
		t.Fatalf("newSecret by prompt: %q %v", got, err)
	}
	setStdin(t, "from-stdin\n")
	if got, err := newSecret(true, "unused"); err != nil || got != "from-stdin" {
		t.Fatalf("newSecret from stdin: %q %v", got, err)
	}
}
