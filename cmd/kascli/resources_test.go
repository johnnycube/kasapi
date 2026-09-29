// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	kasapi "github.com/johnnycube/kasapi"
)

func TestCanonicalResource(t *testing.T) {
	for in, want := range map[string]string{
		"dns": "dnsrecords", "DNSRecord": "dnsrecords", "dnsrecords": "dnsrecords",
		"do": "domains", "sub": "subdomains", "ma": "mailaccounts", "mf": "mailforwards",
		"mfi": "mailfilters", "ftp": "ftpusers", "ftpuser": "ftpusers", "db": "databases",
		"cj": "cronjobs", "cronjob": "cronjobs", "ddns": "ddnsusers", "tls": "tls",
	} {
		got, err := canonicalResource(in)
		if err != nil || got != want {
			t.Errorf("canonicalResource(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "pods", "certificate"} {
		if _, err := canonicalResource(in); err == nil || !strings.Contains(err.Error(), "available: cronjobs, databases") {
			t.Errorf("canonicalResource(%q): %v", in, err)
		}
	}
}

func TestResourceAliases(t *testing.T) {
	seen := map[string]string{}
	for _, r := range resources {
		for _, name := range append(r.aliases(), r.kind) {
			if other, dup := seen[name]; dup {
				t.Errorf("%q names both %s and %s", name, other, r.name)
			}
			seen[name] = r.name
		}
		for _, verb := range strings.Split(r.verbs, ",") {
			switch verb {
			case "get", "create", "update", "delete":
			default:
				t.Errorf("%s: unknown verb %q", r.name, verb)
			}
		}
	}
	// tls has neither plural nor short name.
	for _, r := range resources {
		if r.name == "tls" && len(r.aliases()) != 0 {
			t.Errorf("tls aliases: %v", r.aliases())
		}
	}
}

func TestCLI_APIResourcesMatchCommands(t *testing.T) {
	// Every verb api-resources advertises is a command that exists.
	root := newRootCmd()
	for _, r := range resources {
		for _, verb := range strings.Split(r.verbs, ",") {
			if verb == "get" || verb == "delete" {
				continue // dispatched by resource name, covered by their tests
			}
			cmd, _, err := root.Find([]string{verb, r.kind})
			if err != nil || cmd.Name() != r.kind {
				t.Errorf("%s %s: no such command (%v)", verb, r.kind, err)
			}
		}
	}
	// And no command exists that api-resources hides.
	for _, verb := range []string{"create", "update"} {
		parent, _, _ := root.Find([]string{verb})
		for _, sub := range parent.Commands() {
			name, err := canonicalResource(sub.Name())
			if err != nil {
				t.Errorf("%s %s: not a resource", verb, sub.Name())
				continue
			}
			for _, r := range resources {
				if r.name == name && !strings.Contains(","+r.verbs+",", ","+verb+",") {
					t.Errorf("%s %s exists but api-resources does not list the verb", verb, sub.Name())
				}
			}
		}
	}
}

func hostEntry(kind, name string) string {
	return entry(
		kind+"_name", name, kind+"_path", "/"+name+"/", kind+"_redirect_status", "301",
		"php_version", "8.4", "php_deprecated", "N", "is_active", "Y", "in_progress", "FALSE",
		"dkim_selector", "sel1",
		"ssl_certificate_sni_is_active", "j", "ssl_certificate_sni_type", "LE90D",
		"ssl_certificate_sni_force_https", "Y", "ssl_certificate_sni_hsts_max_age", "300",
		"ssl_certificate_sni_key", "PRIVATE-KEY-MATERIAL",
	)
}

func TestCLI_GetHostsWide(t *testing.T) {
	setupFake(t, map[string]string{
		"get_domains":    hostEntry("domain", "example.com"),
		"get_subdomains": hostEntry("subdomain", "blog.example.com"),
	})
	for _, res := range []string{"domains", "subdomains"} {
		out := capture(t, "get", res, "-o", "wide")
		for _, want := range []string{"REDIRECT", "PHP", "FORCE-HTTPS", "301", "8.4", "letsencrypt"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s wide lacks %q:\n%s", res, want, out)
			}
		}
		out = capture(t, "get", res)
		if strings.Contains(out, "REDIRECT") {
			t.Errorf("%s: wide column leaked into the default table:\n%s", res, out)
		}

		out = capture(t, "get", res, "-o", "json")
		if strings.Contains(out, "PRIVATE-KEY-MATERIAL") {
			t.Fatalf("%s: the private key must never be printed:\n%s", res, out)
		}
		var items []map[string]any
		if err := json.Unmarshal([]byte(out), &items); err != nil || len(items) != 1 {
			t.Fatalf("%s json: %v\n%s", res, err, out)
		}
		tls, _ := items[0]["tls"].(map[string]any)
		if items[0]["phpVersion"] != "8.4" || items[0]["redirectStatus"] != float64(301) ||
			items[0]["active"] != true || tls["letsEncrypt"] != true || tls["hstsMaxAge"] != float64(300) {
			t.Fatalf("%s json content: %#v", res, items[0])
		}
	}
}

func TestCLI_GetTLS(t *testing.T) {
	setupFake(t, map[string]string{
		"get_domains":    "!domain_not_found_in_kas",
		"get_subdomains": hostEntry("subdomain", "blog.example.com"),
	})
	out := capture(t, "get", "tls", "blog.example.com")
	for _, want := range []string{"HOST", "blog.example.com", "LE90D", "300"} {
		if !strings.Contains(out, want) {
			t.Errorf("tls table lacks %q:\n%s", want, out)
		}
	}
	out = capture(t, "get", "tls", "blog.example.com", "-o", "name")
	if strings.TrimSpace(out) != "tls/blog.example.com" {
		t.Fatalf("name output: %q", out)
	}
	out = capture(t, "get", "tls", "blog.example.com", "-o", "json")
	if !strings.Contains(out, `"letsEncrypt": true`) || !strings.Contains(out, `"host": "blog.example.com"`) {
		t.Fatalf("json output:\n%s", out)
	}
	wantErr(t, "a host name is required", "get", "tls")
	wantErr(t, "not found", "get", "tls", "missing.example.com")
}

func TestTLSWord(t *testing.T) {
	for want, state := range map[string]kasapi.HostTLS{
		"off":         {Type: "LE90D"},
		"letsencrypt": {Active: true, Type: "LE90D"},
		"custom":      {Active: true, Type: "custom"},
		"on":          {Active: true},
	} {
		if got := tlsWord(state); got != want {
			t.Errorf("tlsWord(%+v) = %q, want %q", state, got, want)
		}
	}
}

func TestCLI_GetMailAccountsShowsNewFields(t *testing.T) {
	setupFake(t, map[string]string{"get_mailaccounts": entry(
		"mail_login", "m1", "mail_adresses", "info@example.com",
		"mail_password", "PLAINTEXT-PASSWORD",
		"mail_responder", "1767225600|1769904000", "mail_responder_text", "Away.",
		"mail_is_active", "N", "mail_allow_nets", "203.0.113.0/24,webmail",
		"mail_spamfilter", "pdw,sf", "webmail_autologin", "Y",
	)})
	out := capture(t, "get", "ma", "-o", "wide")
	for _, want := range []string{"STATE", "ALLOW-NETS", "FILTERS", "receive-disabled", "203.0.113.0/24,webmail", "pdw,sf"} {
		if !strings.Contains(out, want) {
			t.Errorf("wide output lacks %q:\n%s", want, out)
		}
	}
	out = capture(t, "get", "ma", "-o", "yaml")
	if strings.Contains(out, "PLAINTEXT-PASSWORD") {
		t.Fatalf("the mailbox password must never be printed:\n%s", out)
	}
	for _, want := range []string{"state: receive-disabled", "start: \"2026-01-01T00:00:00Z\"", "text: Away.", "webmailAutologin: true"} {
		if !strings.Contains(out, want) {
			t.Errorf("yaml output lacks %q:\n%s", want, out)
		}
	}
}

func TestMailStateWordAndResponderObject(t *testing.T) {
	for state, want := range map[kasapi.MailState]string{
		kasapi.MailActive: "active", kasapi.MailReceiveDisabled: "receive-disabled",
		kasapi.MailForbidden: "forbidden", "odd": "odd",
	} {
		if got := mailStateWord(state); got != want {
			t.Errorf("mailStateWord(%q) = %q, want %q", state, got, want)
		}
	}
	obj := responderObject(kasapi.Responder{Active: true, Text: "x"})
	if _, ok := obj["start"]; ok {
		t.Fatalf("a responder without window must not print one: %#v", obj)
	}
}

func TestCLI_GetNewResources(t *testing.T) {
	setupFake(t, map[string]string{
		"get_ftpusers": entry("ftp_login", "f0000001", "ftp_path", "/logs/", "ftp_comment", "log reader",
			"ftp_password", "PLAINTEXT-PASSWORD",
			"ftp_permission_read", "Y", "ftp_permission_write", "N", "ftp_permission_list", "Y",
			"ftp_virus_clamav", "Y", "ftp_is_main_user", "N"),
		"get_databases": entry("database_name", "d0123460", "database_login", "d0123460",
			"database_password", "PLAINTEXT-PASSWORD", "database_comment", "shop",
			"database_allowed_hosts", "203.0.113.7", "used_database_space", "42"),
		"get_cronjobs": entry("cronjob_id", "325208", "cronjob_comment", "hourly", "protocol", "https",
			"http_url", "example.com/cron.php", "http_user", "cron", "http_password", "PLAINTEXT-PASSWORD",
			"minute", "59", "hour", "*/1", "day_of_month", "*", "month", "*", "day_of_week", "*",
			"mail_adress", "ops@example.com", "is_active", "Y"),
		"get_ddnsusers": entry("dyndns_login", "dyn0000002", "dyndns_comment", "at home",
			"dyndns_password", "PLAINTEXT-PASSWORD", "dyndns_zone", "example.org", "dyndns_label", "home",
			"dyndns_target_ipv4", "203.0.113.255", "dyndns_target_ipv6", "2001:db8::1", "dyndns_dual_stack", "Y"),
		"get_mailstandardfilter": entry("filter", "rspamd", "type", "rspamd", "title", "Rspam", "recommended", "Y"),
	})

	for res, tc := range map[string]struct {
		name string
		wide []string
	}{
		"ftp":  {"ftpuser/f0000001", []string{"PERMISSIONS", "r-l", "/logs/", "VIRUS-SCAN", "MAIN-USER"}},
		"db":   {"database/d0123460", []string{"ALLOWED-HOSTS", "203.0.113.7", "USED-SPACE", "42"}},
		"cj":   {"cronjob/325208", []string{"SCHEDULE", "59 */1 * * *", "https://example.com/cron.php", "ops@example.com", "HTTP-USER"}},
		"ddns": {"ddnsuser/dyn0000002", []string{"home.example.org", "203.0.113.255", "2001:db8::1", "DUAL-STACK"}},
		"mfi":  {"mailfilter/rspamd", []string{"RECOMMENDED", "Rspam"}},
	} {
		out := capture(t, "get", res, "-o", "name")
		if strings.TrimSpace(out) != tc.name {
			t.Errorf("%s name output: %q", res, out)
		}
		out = capture(t, "get", res, "-o", "wide")
		for _, want := range tc.wide {
			if !strings.Contains(out, want) {
				t.Errorf("%s wide lacks %q:\n%s", res, want, out)
			}
		}
		for _, format := range []string{"wide", "json", "yaml"} {
			if out := capture(t, "get", res, "-o", format); strings.Contains(out, "PLAINTEXT-PASSWORD") {
				t.Fatalf("%s -o %s prints a password:\n%s", res, format, out)
			}
		}
		var items []map[string]any
		if err := json.Unmarshal([]byte(capture(t, "get", res, "-o", "json")), &items); err != nil || len(items) != 1 {
			t.Errorf("%s json: %v", res, err)
		}
	}
}

func TestFTPPermissions(t *testing.T) {
	for want, u := range map[string]kasapi.FTPUser{
		"rwl": {Read: true, Write: true, List: true},
		"r-l": {Read: true, List: true},
		"-w-": {Write: true},
		"---": {},
	} {
		if got := ftpPermissions(u); got != want {
			t.Errorf("ftpPermissions(%+v) = %q, want %q", u, got, want)
		}
	}
}

func TestCLI_GetFaultsAndEmptyLists(t *testing.T) {
	setupFake(t, map[string]string{"get_ftpusers": "", "get_ddnsusers": "!empty_list"})
	for _, res := range []string{"ftp", "ddns"} {
		if out := capture(t, "get", res, "-o", "json"); strings.TrimSpace(out) != "[]" {
			t.Errorf("%s: an empty account must print an empty list, got %q", res, out)
		}
	}
	for _, res := range []string{"domains", "sub", "ma", "mf", "mfi", "db", "cj"} {
		wantErr(t, "unknown_action", "get", res)
	}
	wantErr(t, "unknown_action", "get", "dns", "--zone", "example.com")
	wantErr(t, "--zone is required", "get", "dns")
}

func TestCLI_DeleteNewResources(t *testing.T) {
	rec := setupFake(t, map[string]string{
		"delete_ftpuser": "TRUE", "delete_database": "TRUE", "delete_cronjob": "TRUE",
		"delete_ddnsuser": "TRUE", "delete_mailstandardfilter": "TRUE",
	})
	for _, tc := range []struct{ res, id, action, param, want string }{
		{"ftpuser", "f0000001", "delete_ftpuser", "ftp_login", "ftpuser/f0000001 deleted"},
		{"db", "d0123460", "delete_database", "database_login", "database/d0123460 deleted"},
		{"cronjobs", "325208", "delete_cronjob", "cronjob_id", "cronjob/325208 deleted"},
		{"ddns", "dyn0000002", "delete_ddnsuser", "dyndns_login", "ddnsuser/dyn0000002 deleted"},
		{"mailfilters", "m1", "delete_mailstandardfilter", "mail_login", "mailfilters of mailaccount/m1 deleted"},
	} {
		out := capture(t, "delete", tc.res, tc.id)
		if !strings.Contains(out, tc.want) {
			t.Errorf("delete %s: %q", tc.res, out)
		}
		wantParams(t, rec.last(t, tc.action), map[string]string{tc.param: tc.id})
	}

	before := rec.total()
	wantErr(t, "cannot be deleted", "delete", "domain", "example.com")
	wantErr(t, "update tls example.com --active=false", "delete", "tls", "example.com")
	wantErr(t, "resource type", "delete", "pods", "x")
	if rec.total() != before {
		t.Fatal("a refused delete must not reach the API")
	}
}

func TestCLI_DeleteFaults(t *testing.T) {
	setupFake(t, map[string]string{
		"delete_dns_settings": "!record_id_not_found", "delete_ftpuser": "!ftp_login_belongs_to_account",
	})
	wantErr(t, "not found", "delete", "dns", "11")
	wantErr(t, "ftp_login_belongs_to_account", "delete", "ftp", "w0123456")
	for _, res := range []string{"ma", "mf", "sub", "db", "cj", "ddns", "mfi"} {
		wantErr(t, "unknown_action", "delete", res, "x")
	}
}
