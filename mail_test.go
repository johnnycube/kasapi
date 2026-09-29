// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/johnnycube/kasapi/kasapitest"
)

func TestMail_ListAccountsAndForwards(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		switch action {
		case "get_mailaccounts":
			return `
 <item>
  <item><key>mail_login</key><value>m1234567</value></item>
  <item><key>mail_adresses</key><value>info@example.com;kontakt@example.com</value></item>
  <item><key>mail_responder</key><value>N</value></item>
  <item><key>mail_copy_adress</key><value>archive@example.org</value></item>
  <item><key>mail_sender_alias</key><value>alias@example.com,other@example.com</value></item>
 </item>`, ""
		case "get_mailforwards":
			return `
 <item>
  <item><key>mail_forward_adress</key><value>sales@example.com</value></item>
  <item><key>mail_forward_targets</key><value>a@example.org,b@example.org</value></item>
 </item>`, ""
		case "add_mailaccount":
			if params["mail_password"] != "S3cure!pass" {
				return "", "password_missing"
			}
			if params["copy_adress"] != "archive@example.org" {
				return "", "bad_copy_adress"
			}
			if params["mail_sender_alias"] != "alias@example.com,other@example.com" {
				return "", "bad_sender_alias"
			}
			return `m7654321`, ""
		}
		return "", "unknown_action"
	})
	c := newTestClient(t, f)

	accounts, err := c.Mail.ListAccounts(context.Background())
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accounts) != 1 || accounts[0].Login != "m1234567" {
		t.Fatalf("unexpected accounts: %+v", accounts)
	}
	if accounts[0].Address() != "info@example.com" {
		t.Fatalf("unexpected primary address: %q", accounts[0].Address())
	}
	if len(accounts[0].CopyAddresses) != 1 {
		t.Fatalf("unexpected copy addresses: %+v", accounts[0].CopyAddresses)
	}
	if len(accounts[0].SenderAliases) != 2 || accounts[0].SenderAliases[0] != "alias@example.com" {
		t.Fatalf("unexpected sender aliases: %+v", accounts[0].SenderAliases)
	}

	login, err := c.Mail.CreateAccount(context.Background(),
		MailAccount{
			LocalPart:     "neu",
			Domain:        "example.com",
			CopyAddresses: []string{"archive@example.org"},
			SenderAliases: []string{"alias@example.com", "other@example.com"},
		}, "S3cure!pass")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if login != "m7654321" {
		t.Fatalf("expected login m7654321, got %q", login)
	}

	forwards, err := c.Mail.ListForwards(context.Background())
	if err != nil {
		t.Fatalf("ListForwards: %v", err)
	}
	if len(forwards) != 1 || forwards[0].Source() != "sales@example.com" || len(forwards[0].Targets) != 2 {
		t.Fatalf("unexpected forwards: %+v", forwards)
	}
}

func TestMail_InputValidation(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		return "", "should_not_be_called"
	})
	c := newTestClient(t, f)
	ctx := context.Background()

	if _, err := c.Mail.CreateAccount(ctx, MailAccount{LocalPart: "x y", Domain: "example.com"}, "p"); err == nil {
		t.Fatal("expected validation error for invalid local part")
	}
	if _, err := c.Mail.CreateAccount(ctx, MailAccount{LocalPart: "ok", Domain: "example.com"}, ""); err == nil {
		t.Fatal("expected validation error for empty password")
	}
	if err := c.Mail.CreateForward(ctx, MailForward{LocalPart: "a", Domain: "example.com"}); err == nil {
		t.Fatal("expected validation error for missing targets")
	}
	tooMany := make([]string, 11)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("t%d@example.org", i)
	}
	if err := c.Mail.CreateForward(ctx, MailForward{LocalPart: "a", Domain: "example.com",
		Targets: tooMany}); err == nil {
		t.Fatal("expected validation error for more than 10 targets")
	}
	if _, err := c.Mail.CreateAccount(ctx, MailAccount{LocalPart: "ok", Domain: "example.com",
		SenderAliases: []string{"not an address"}}, "p"); err == nil {
		t.Fatal("expected validation error for invalid sender alias")
	}
	if err := c.Mail.UpdateSenderAliases(ctx, "m1", []string{"not an address"}); err == nil {
		t.Fatal("expected validation error for invalid sender alias")
	}
	if f.APICalls.Load() != 0 {
		t.Fatalf("validation failures must not reach the API, got %d calls", f.APICalls.Load())
	}
}

func TestMail_AccountUpdateDelete(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		switch action {
		case "get_mailaccounts":
			return `<item>` +
				kasapitest.MapItem("mail_login", "m1") +
				kasapitest.MapItem("mail_adresses", "info@example.com") +
				kasapitest.MapItem("mail_responder", "N") +
				`</item>`, ""
		case "update_mailaccount":
			if params["mail_login"] != "m1" {
				return "", "mail_login_not_found"
			}
			if v, ok := params["copy_adress"]; ok && v != "a@example.org" {
				return "", "bad_copy_adress"
			}
			if v, ok := params["mail_sender_alias"]; ok && v != "alias@example.com" && v != "" {
				return "", "bad_sender_alias"
			}
			return "TRUE", ""
		case "delete_mailaccount":
			if params["mail_login"] != "m1" {
				return "", "mail_login_not_found"
			}
			return "TRUE", ""
		}
		return "", "unknown_action"
	})
	c := newTestClient(t, f)
	ctx := context.Background()

	if _, err := c.Mail.GetAccount(ctx, "m1"); err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if _, err := c.Mail.GetAccount(ctx, "m9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	if err := c.Mail.UpdatePassword(ctx, "m1", "new-Passw0rd"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if err := c.Mail.UpdatePassword(ctx, "", "x"); err == nil {
		t.Fatal("UpdatePassword without login must fail")
	}
	if err := c.Mail.UpdatePassword(ctx, "m1", ""); err == nil {
		t.Fatal("UpdatePassword without password must fail")
	}

	if err := c.Mail.UpdateCopyAddresses(ctx, "m1", []string{"a@example.org"}); err != nil {
		t.Fatalf("UpdateCopyAddresses: %v", err)
	}
	if err := c.Mail.UpdateCopyAddresses(ctx, "", nil); err == nil {
		t.Fatal("UpdateCopyAddresses without login must fail")
	}

	if err := c.Mail.UpdateSenderAliases(ctx, "m1", []string{"alias@example.com"}); err != nil {
		t.Fatalf("UpdateSenderAliases: %v", err)
	}
	if err := c.Mail.UpdateSenderAliases(ctx, "m1", nil); err != nil {
		t.Fatalf("UpdateSenderAliases (clear): %v", err)
	}
	if err := c.Mail.UpdateSenderAliases(ctx, "", nil); err == nil {
		t.Fatal("UpdateSenderAliases without login must fail")
	}

	if err := c.Mail.DeleteAccount(ctx, "m1"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if err := c.Mail.DeleteAccount(ctx, ""); err == nil {
		t.Fatal("DeleteAccount without login must fail")
	}
	if err := c.Mail.DeleteAccount(ctx, "m9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMail_ForwardCRUD(t *testing.T) {
	f := kasapitest.New(t, func(action string, params map[string]any) (string, string) {
		switch action {
		case "get_mailforwards":
			return `<item>` +
				kasapitest.MapItem("mail_forward_adress", "sales@example.com") +
				kasapitest.MapItem("mail_forward_targets", "a@example.org") +
				`</item>`, ""
		case "add_mailforward":
			if params["target_0"] != "a@example.org" {
				return "", "missing_target"
			}
			return "TRUE", ""
		case "update_mailforward":
			if params["mail_forward"] != "sales@example.com" || params["target_1"] != "b@example.org" {
				return "", "bad_update"
			}
			return "TRUE", ""
		case "delete_mailforward":
			if params["mail_forward"] != "sales@example.com" {
				return "", "mail_forward_not_found"
			}
			return "TRUE", ""
		}
		return "", "unknown_action"
	})
	c := newTestClient(t, f)
	ctx := context.Background()

	if _, err := c.Mail.GetForward(ctx, "sales@example.com"); err != nil {
		t.Fatalf("GetForward: %v", err)
	}
	if _, err := c.Mail.GetForward(ctx, "nope@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	fw := MailForward{LocalPart: "sales", Domain: "example.com", Targets: []string{"a@example.org"}}
	if err := c.Mail.CreateForward(ctx, fw); err != nil {
		t.Fatalf("CreateForward: %v", err)
	}
	if err := c.Mail.CreateForward(ctx, MailForward{LocalPart: "x", Domain: "example.com",
		Targets: []string{"not an address"}}); err == nil {
		t.Fatal("invalid target must fail validation")
	}

	fw.Targets = []string{"a@example.org", "b@example.org"}
	if err := c.Mail.UpdateForward(ctx, fw); err != nil {
		t.Fatalf("UpdateForward: %v", err)
	}
	if err := c.Mail.UpdateForward(ctx, MailForward{LocalPart: "x", Domain: "example.com"}); err == nil {
		t.Fatal("UpdateForward without targets must fail")
	}

	if err := c.Mail.DeleteForward(ctx, "sales@example.com"); err != nil {
		t.Fatalf("DeleteForward: %v", err)
	}
	if err := c.Mail.DeleteForward(ctx, ""); err == nil {
		t.Fatal("DeleteForward without source must fail")
	}
	if err := c.Mail.DeleteForward(ctx, "nope@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// mailEntry is a get_mailaccounts entry as KAS sends it, password included.
func mailEntry(login, address string, extra ...string) string {
	kv := []string{
		"mail_login", login,
		"mail_password", "plaintext-password",
		"mail_adresses", address,
		"mail_responder", "N",
		"mail_responder_text", "",
		"mail_responder_displayname", "Info",
		"mail_responder_content_type", "text",
		"mail_copy_adress", "",
		"mail_sender_alias", "",
		"mail_spamfilter", "sf,ef,pdw,",
		"in_progress", "FALSE",
		"mail_is_active", "Y",
		"mail_allow_nets", "",
		"webmail_autologin", "Y",
	}
	return entry(append(kv, extra...)...)
}

func TestMail_AccountMapsAllFields(t *testing.T) {
	c, _ := newFake(t, map[string]string{"get_mailaccounts": mailEntry("m1", "info@example.com",
		"mail_responder", "1767225600|1769904000",
		"mail_responder_text", "Back in February.",
		"mail_responder_content_type", "html",
		"mail_is_active", "forbidden",
		"mail_allow_nets", "203.0.113.0/24,webmail",
		"webmail_autologin", "N",
		"in_progress", "TRUE",
	)})
	accounts, err := c.Mail.ListAccounts(context.Background())
	if err != nil || len(accounts) != 1 {
		t.Fatalf("ListAccounts: %v %v", accounts, err)
	}
	a := accounts[0]
	if a.Address() != "info@example.com" || a.State != MailForbidden || a.WebmailAutologin || !a.InProgress {
		t.Fatalf("unexpected account: %+v", a)
	}
	if !reflect.DeepEqual(a.AllowNets, []string{"203.0.113.0/24", "webmail"}) {
		t.Fatalf("allow nets: %#v", a.AllowNets)
	}
	if !reflect.DeepEqual(a.SpamFilters, []string{"sf", "ef", "pdw"}) {
		t.Fatalf("spam filters: %#v", a.SpamFilters)
	}
	wantResponder := Responder{
		Active: true,
		Start:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		End:    time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Text:   "Back in February.", ContentType: "html", DisplayName: "Info",
	}
	if !reflect.DeepEqual(a.Responder, wantResponder) || !a.ResponderActive {
		t.Fatalf("responder: got %+v, want %+v", a.Responder, wantResponder)
	}
}

func TestResponderFrom(t *testing.T) {
	for raw, want := range map[string]bool{"N": false, "Y": true, "": false, "n": false, "y": true} {
		if got := responderFrom(map[string]any{"mail_responder": raw}); got.Active != want || !got.Start.IsZero() {
			t.Errorf("mail_responder %q: %+v", raw, got)
		}
	}
	// A window that does not parse is not an active responder.
	for _, raw := range []string{"abc|def", "1767225600|", "|"} {
		if got := responderFrom(map[string]any{"mail_responder": raw}); got.Active || !got.Start.IsZero() {
			t.Errorf("mail_responder %q: %+v", raw, got)
		}
	}
}

func TestMailStateFrom(t *testing.T) {
	for raw, want := range map[any]MailState{
		"Y": MailActive, "y": MailActive, "": MailActive, nil: MailActive,
		"N": MailReceiveDisabled, "forbidden": MailForbidden, "FORBIDDEN": MailForbidden,
	} {
		if got := mailStateFrom(raw); got != want {
			t.Errorf("mailStateFrom(%#v) = %q, want %q", raw, got, want)
		}
	}
}

func TestMail_GetAccountFiltersOnTheServer(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_mailaccounts": mailEntry("m1", "info@example.com")})
	if _, err := c.Mail.GetAccount(ctx, "m1"); err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	wantParams(t, rec.last(t, "get_mailaccounts"), map[string]string{"mail_login": "m1"})
	if _, err := c.Mail.GetAccount(ctx, ""); err == nil {
		t.Fatal("GetAccount without login must fail")
	}

	c, _ = newFake(t, map[string]string{"get_mailaccounts": "!mail_login_not_found"})
	if _, err := c.Mail.GetAccount(ctx, "m9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_mailaccounts": "!kas_error"})
	if _, err := c.Mail.GetAccount(ctx, "m1"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading mail account m1") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
	if _, err := c.Mail.ListAccounts(ctx); err == nil || !strings.Contains(err.Error(), "listing mail accounts") {
		t.Fatalf("ListAccounts fault: %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_mailaccounts": "!empty_list"})
	if accounts, err := c.Mail.ListAccounts(ctx); err != nil || len(accounts) != 0 {
		t.Fatalf("empty list: %v %v", accounts, err)
	}
}

func TestMail_CreateAccountSendsResponderAndAllowNets(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_mailaccount": "m7654321"})

	login, err := c.Mail.CreateAccount(ctx, MailAccount{
		LocalPart: "info", Domain: "example.com",
		Responder: Responder{Active: true, Text: "Away.", DisplayName: "Info"},
		AllowNets: []string{"203.0.113.7", "webmail"},
	}, "S3cure!pass")
	if err != nil || login != "m7654321" {
		t.Fatalf("CreateAccount: %q %v", login, err)
	}
	got := rec.last(t, "add_mailaccount")
	wantParams(t, got, map[string]string{
		"local_part": "info", "domain_part": "example.com", "mail_password": "S3cure!pass",
		"responder": "Y", "responder_text": "Away.", "mail_responder_displayname": "Info",
		"mail_allow_nets": "203.0.113.7,webmail",
	})
	wantAbsent(t, got, "copy_adress", "mail_sender_alias", "mail_responder_content_type", "is_active")

	// A plain account sends none of the optional parameters.
	if _, err := c.Mail.CreateAccount(ctx, MailAccount{LocalPart: "plain", Domain: "example.com"}, "p"); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	wantAbsent(t, rec.last(t, "add_mailaccount"), "responder", "responder_text", "mail_allow_nets")

	before := rec.count("add_mailaccount")
	for name, a := range map[string]MailAccount{
		"responder without text": {LocalPart: "a", Domain: "example.com", Responder: Responder{Active: true}},
		"bad allow net":          {LocalPart: "a", Domain: "example.com", AllowNets: []string{"everyone"}},
		"bad copy address":       {LocalPart: "a", Domain: "example.com", CopyAddresses: []string{"nope"}},
		"no domain":              {LocalPart: "a"},
	} {
		if _, err := c.Mail.CreateAccount(ctx, a, "p"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if rec.count("add_mailaccount") != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestResponder_ValueAndValidate(t *testing.T) {
	start := time.Unix(1767225600, 0)
	end := time.Unix(1769904000, 0)
	for name, tc := range map[string]struct {
		r    Responder
		want string
	}{
		"off":             {Responder{}, "N"},
		"off with text":   {Responder{Text: "kept for later"}, "N"},
		"on":              {Responder{Active: true, Text: "x"}, "Y"},
		"window":          {Responder{Active: true, Text: "x", Start: start, End: end}, "1767225600|1769904000"},
		"off beats dates": {Responder{Start: start, End: end}, "N"},
	} {
		if got := tc.r.responderValue(); got != tc.want {
			t.Errorf("%s: responderValue() = %q, want %q", name, got, tc.want)
		}
	}

	valid := []Responder{
		{},
		{Start: end, End: start}, // an inactive responder is not validated
		{Active: true, Text: "x"},
		{Active: true, Text: "x", ContentType: "html"},
		{Active: true, Text: "x", ContentType: "text", Start: start, End: end},
	}
	for _, r := range valid {
		if err := r.validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	invalid := map[string]Responder{
		"no text":      {Active: true},
		"blank text":   {Active: true, Text: "  \n"},
		"start only":   {Active: true, Text: "x", Start: start},
		"end only":     {Active: true, Text: "x", End: end},
		"end before":   {Active: true, Text: "x", Start: end, End: start},
		"empty window": {Active: true, Text: "x", Start: start, End: start},
		"bad content":  {Active: true, Text: "x", ContentType: "markdown"},
	}
	for name, r := range invalid {
		if err := r.validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestMail_UpdateResponder(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_mailaccount": "TRUE"})

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	err := c.Mail.UpdateResponder(ctx, "m1", Responder{
		Active: true, Start: start, End: start.AddDate(0, 1, 0),
		Text: "<p>Away</p>", ContentType: "html", DisplayName: "Jo",
	})
	if err != nil {
		t.Fatalf("UpdateResponder: %v", err)
	}
	wantParams(t, rec.last(t, "update_mailaccount"), map[string]string{
		"mail_login": "m1", "responder": "1767225600|1769904000", "responder_text": "<p>Away</p>",
		"mail_responder_content_type": "html", "mail_responder_displayname": "Jo",
	})

	// Turning it off sends the switch alone: text and name stay stored.
	if err := c.Mail.UpdateResponder(ctx, "m1", Responder{Text: "ignored"}); err != nil {
		t.Fatalf("UpdateResponder off: %v", err)
	}
	got := rec.last(t, "update_mailaccount")
	wantParams(t, got, map[string]string{"mail_login": "m1", "responder": "N"})
	wantAbsent(t, got, "responder_text", "mail_responder_content_type", "mail_responder_displayname")

	before := rec.count("update_mailaccount")
	if err := c.Mail.UpdateResponder(ctx, "m1", Responder{Active: true}); err == nil {
		t.Error("an active responder without text must fail")
	}
	if err := c.Mail.UpdateResponder(ctx, "", Responder{}); err == nil {
		t.Error("UpdateResponder without login must fail")
	}
	if rec.count("update_mailaccount") != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestMail_UpdateState(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_mailaccount": "TRUE"})
	for state, want := range map[MailState]string{
		MailActive: "Y", MailReceiveDisabled: "N", MailForbidden: "forbidden",
	} {
		if err := c.Mail.UpdateState(ctx, "m1", state); err != nil {
			t.Fatalf("UpdateState(%s): %v", state, err)
		}
		wantParams(t, rec.last(t, "update_mailaccount"), map[string]string{"mail_login": "m1", "is_active": want})
	}
	before := rec.count("update_mailaccount")
	for _, state := range []MailState{"", "active", "y"} {
		if err := c.Mail.UpdateState(ctx, "m1", state); err == nil {
			t.Errorf("state %q must be rejected", state)
		}
	}
	if err := c.Mail.UpdateState(ctx, "", MailActive); err == nil {
		t.Error("UpdateState without login must fail")
	}
	if rec.count("update_mailaccount") != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestValidateAllowNets(t *testing.T) {
	if err := validateAllowNets([]string{"203.0.113.7", "2001:db8::1", "203.0.113.0/24", "2001:db8::/32", "webmail"}); err != nil {
		t.Fatalf("valid entries: %v", err)
	}
	if err := validateAllowNets(nil); err != nil {
		t.Fatalf("empty list: %v", err)
	}
	for _, bad := range []string{"", "Webmail", "example.com", "203.0.113.0/33", "203.0.113", "all"} {
		if err := validateAllowNets([]string{"webmail", bad}); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestMail_UpdateAllowNetsAndAutologin(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"update_mailaccount": "TRUE"})

	if err := c.Mail.UpdateAllowNets(ctx, "m1", []string{"203.0.113.0/24", "webmail"}); err != nil {
		t.Fatalf("UpdateAllowNets: %v", err)
	}
	wantParams(t, rec.last(t, "update_mailaccount"), map[string]string{"mail_login": "m1", "mail_allow_nets": "203.0.113.0/24,webmail"})

	// An empty list is sent as the empty string, which lifts the restriction.
	if err := c.Mail.UpdateAllowNets(ctx, "m1", nil); err != nil {
		t.Fatalf("UpdateAllowNets (clear): %v", err)
	}
	if v, ok := rec.last(t, "update_mailaccount")["mail_allow_nets"]; !ok || v != "" {
		t.Fatalf("clearing must send the empty value, got %v", rec.last(t, "update_mailaccount"))
	}
	if err := c.Mail.UpdateAllowNets(ctx, "m1", []string{"nope"}); err == nil {
		t.Error("an invalid client must fail")
	}
	if err := c.Mail.UpdateAllowNets(ctx, "", nil); err == nil {
		t.Error("UpdateAllowNets without login must fail")
	}

	for enabled, want := range map[bool]string{true: "Y", false: "N"} {
		if err := c.Mail.UpdateWebmailAutologin(ctx, "m1", enabled); err != nil {
			t.Fatalf("UpdateWebmailAutologin: %v", err)
		}
		wantParams(t, rec.last(t, "update_mailaccount"), map[string]string{"mail_login": "m1", "webmail_autologin": want})
	}
	if err := c.Mail.UpdateWebmailAutologin(ctx, "", true); err == nil {
		t.Error("UpdateWebmailAutologin without login must fail")
	}
}

// checkUpdateFaults runs each update against "nothing_to_do" and a real fault.
func checkUpdateFaults(t *testing.T, updates map[string]func(*Client) error) {
	t.Helper()
	for name, run := range updates {
		c, _ := newFake(t, map[string]string{"update_mailaccount": "!nothing_to_do"})
		if err := run(c); err != nil {
			t.Errorf("%s: nothing_to_do must be success, got %v", name, err)
		}
		c, _ = newFake(t, map[string]string{"update_mailaccount": "!in_progress"})
		err := run(c)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Code != "in_progress" || !strings.Contains(err.Error(), "mail account m1") {
			t.Errorf("%s: fault must be returned with context, got %v", name, err)
		}
	}
}

func TestMail_UpdateFaults(t *testing.T) {
	ctx := context.Background()
	checkUpdateFaults(t, map[string]func(*Client) error{
		"UpdatePassword":      func(c *Client) error { return c.Mail.UpdatePassword(ctx, "m1", "pw") },
		"UpdateCopyAddresses": func(c *Client) error { return c.Mail.UpdateCopyAddresses(ctx, "m1", []string{"a@example.org"}) },
		"UpdateSenderAliases": func(c *Client) error { return c.Mail.UpdateSenderAliases(ctx, "m1", nil) },
	})
}

func TestMail_SettingsUpdateFaults(t *testing.T) {
	ctx := context.Background()
	updates := map[string]func(*Client) error{
		"UpdateResponder":        func(c *Client) error { return c.Mail.UpdateResponder(ctx, "m1", Responder{}) },
		"UpdateState":            func(c *Client) error { return c.Mail.UpdateState(ctx, "m1", MailActive) },
		"UpdateAllowNets":        func(c *Client) error { return c.Mail.UpdateAllowNets(ctx, "m1", nil) },
		"UpdateWebmailAutologin": func(c *Client) error { return c.Mail.UpdateWebmailAutologin(ctx, "m1", true) },
	}
	checkUpdateFaults(t, updates)
	for name, run := range updates {
		c, _ := newFake(t, map[string]string{"update_mailaccount": "!mail_login_not_found"})
		if err := run(c); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: expected ErrNotFound, got %v", name, err)
		}
	}
}

func TestMailFilter_StringAndValidate(t *testing.T) {
	if got := (MailFilter{Name: "greyl"}).String(); got != "greyl" {
		t.Fatalf("String(): %q", got)
	}
	if got := (MailFilter{Name: "spamc_move", Action: "move=Junk"}).String(); got != "spamc_move:move=Junk" {
		t.Fatalf("String(): %q", got)
	}
	for _, f := range []MailFilter{
		{Name: "greyl"},
		{Name: "rbl_cbl", Action: "mark"},
		{Name: "virus_delete", Action: "delete"},
		{Name: "spamc_move", Action: "move=Junk"},
		{Name: "content", Action: "forward=abuse@example.org"},
	} {
		if err := f.validate(); err != nil {
			t.Errorf("%+v: %v", f, err)
		}
	}
	for name, f := range map[string]MailFilter{
		"no name":             {},
		"separator in name":   {Name: "a;b"},
		"colon in name":       {Name: "a:b"},
		"separator in action": {Name: "a", Action: "move=x;greyl"},
		"unknown action":      {Name: "a", Action: "quarantine"},
		"unknown kind":        {Name: "a", Action: "copy=Junk"},
		"move without folder": {Name: "a", Action: "move="},
		"bad forward":         {Name: "a", Action: "forward=nobody"},
	} {
		if err := f.validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestMail_Filters(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{
		"get_mailstandardfilter": entry("filter", "rspamd", "type", "rspamd", "title", "Rspam", "recommended", "Y") +
			entry("filter", "greyl", "type", "greylisting", "title", "Greylisting", "recommended", "N"),
		"add_mailstandardfilter":    "TRUE",
		"delete_mailstandardfilter": "TRUE",
	})

	available, err := c.Mail.AvailableFilters(ctx)
	want := []MailFilterInfo{
		{Name: "rspamd", Type: "rspamd", Title: "Rspam", Recommended: true},
		{Name: "greyl", Type: "greylisting", Title: "Greylisting"},
	}
	if err != nil || !reflect.DeepEqual(available, want) {
		t.Fatalf("AvailableFilters: %+v %v", available, err)
	}

	err = c.Mail.SetFilters(ctx, "m1", []MailFilter{
		{Name: "spamc_move", Action: "move=Junk"}, {Name: "greyl"}, {Name: "rbl_cbl", Action: "delete"},
	})
	if err != nil {
		t.Fatalf("SetFilters: %v", err)
	}
	wantParams(t, rec.last(t, "add_mailstandardfilter"), map[string]string{
		"mail_login": "m1", "filter": "spamc_move:move=Junk;greyl;rbl_cbl:delete",
	})

	before := rec.count("add_mailstandardfilter")
	if err := c.Mail.SetFilters(ctx, "", []MailFilter{{Name: "greyl"}}); err == nil {
		t.Error("SetFilters without login must fail")
	}
	if err := c.Mail.SetFilters(ctx, "m1", nil); err == nil || !strings.Contains(err.Error(), "DeleteFilters") {
		t.Errorf("an empty list must point at DeleteFilters, got %v", err)
	}
	if err := c.Mail.SetFilters(ctx, "m1", []MailFilter{{Name: "greyl"}, {Name: "a;b"}}); err == nil {
		t.Error("an invalid filter must fail")
	}
	if rec.count("add_mailstandardfilter") != before {
		t.Fatal("invalid input must not reach the API")
	}

	if err := c.Mail.DeleteFilters(ctx, "m1"); err != nil {
		t.Fatalf("DeleteFilters: %v", err)
	}
	wantParams(t, rec.last(t, "delete_mailstandardfilter"), map[string]string{"mail_login": "m1"})
	if err := c.Mail.DeleteFilters(ctx, ""); err == nil {
		t.Error("DeleteFilters without login must fail")
	}
}

func TestMail_FilterFaults(t *testing.T) {
	ctx := context.Background()
	filters := []MailFilter{{Name: "greyl"}}

	c, _ := newFake(t, map[string]string{
		"get_mailstandardfilter": "!kas_error", "add_mailstandardfilter": "!login_not_found",
		"delete_mailstandardfilter": "!login_not_found",
	})
	if _, err := c.Mail.AvailableFilters(ctx); err == nil || !strings.Contains(err.Error(), "listing mail standard filters") {
		t.Errorf("AvailableFilters fault: %v", err)
	}
	if err := c.Mail.SetFilters(ctx, "m9", filters); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetFilters: expected ErrNotFound, got %v", err)
	}
	if err := c.Mail.DeleteFilters(ctx, "m9"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteFilters: expected ErrNotFound, got %v", err)
	}

	c, _ = newFake(t, map[string]string{
		"get_mailstandardfilter": "!empty_list", "add_mailstandardfilter": "!filter_not_allowed",
		"delete_mailstandardfilter": "!in_progress",
	})
	if available, err := c.Mail.AvailableFilters(ctx); err != nil || len(available) != 0 {
		t.Errorf("AvailableFilters empty: %v %v", available, err)
	}
	if err := c.Mail.SetFilters(ctx, "m1", filters); err == nil || !strings.Contains(err.Error(), "setting filters of mail account m1") {
		t.Errorf("SetFilters fault: %v", err)
	}
	if err := c.Mail.DeleteFilters(ctx, "m1"); err == nil || !strings.Contains(err.Error(), "deleting filters of mail account m1") {
		t.Errorf("DeleteFilters fault: %v", err)
	}
}

func TestMail_ForwardMapsAllFields(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_mailforwards": entry(
		"mail_forward_adress", "Sales@example.com",
		"mail_forward_targets", "a@example.org,b@example.org",
		"mail_forward_spamfilter", "kaspdw",
		"in_progress", "TRUE",
	)})
	fw, err := c.Mail.GetForward(ctx, "sales@example.com")
	if err != nil {
		t.Fatalf("GetForward: %v", err)
	}
	want := MailForward{
		LocalPart: "Sales", Domain: "example.com",
		Targets: []string{"a@example.org", "b@example.org"}, SpamFilters: []string{"kaspdw"}, InProgress: true,
	}
	if !reflect.DeepEqual(*fw, want) {
		t.Fatalf("got %+v, want %+v", *fw, want)
	}
	wantParams(t, rec.last(t, "get_mailforwards"), map[string]string{"mail_forward": "sales@example.com"})
	if _, err := c.Mail.GetForward(ctx, ""); err == nil {
		t.Fatal("GetForward without source must fail")
	}
}

func TestMail_ForwardFaults(t *testing.T) {
	ctx := context.Background()
	fw := MailForward{LocalPart: "sales", Domain: "example.com", Targets: []string{"a@example.org"}}

	c, _ := newFake(t, map[string]string{
		"get_mailforwards": "!kas_error", "add_mailforward": "!max_emails_reached",
		"update_mailforward": "!nothing_to_do", "delete_mailforward": "!in_progress",
	})
	if _, err := c.Mail.ListForwards(ctx); err == nil || !strings.Contains(err.Error(), "listing mail forwards") {
		t.Errorf("ListForwards fault: %v", err)
	}
	if _, err := c.Mail.GetForward(ctx, fw.Source()); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading mail forward sales@example.com") {
		t.Errorf("GetForward fault: %v", err)
	}
	if err := c.Mail.CreateForward(ctx, fw); err == nil || !strings.Contains(err.Error(), "creating mail forward") {
		t.Errorf("CreateForward fault: %v", err)
	}
	if err := c.Mail.UpdateForward(ctx, fw); err != nil {
		t.Errorf("UpdateForward: nothing_to_do must be success, got %v", err)
	}
	if err := c.Mail.DeleteForward(ctx, fw.Source()); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "deleting mail forward") {
		t.Errorf("DeleteForward fault: %v", err)
	}

	c, _ = newFake(t, map[string]string{
		"get_mailforwards": "!empty_list", "update_mailforward": "!mail_forward_syntax_incorrect",
	})
	if forwards, err := c.Mail.ListForwards(ctx); err != nil || len(forwards) != 0 {
		t.Errorf("ListForwards empty: %v %v", forwards, err)
	}
	if _, err := c.Mail.GetForward(ctx, fw.Source()); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetForward on an empty list: expected ErrNotFound, got %v", err)
	}
	if err := c.Mail.UpdateForward(ctx, fw); err == nil || !strings.Contains(err.Error(), "updating mail forward") {
		t.Errorf("UpdateForward fault: %v", err)
	}
	if err := c.Mail.UpdateForward(ctx, MailForward{LocalPart: "x y", Domain: "example.com", Targets: fw.Targets}); err == nil {
		t.Error("UpdateForward with an invalid source must fail")
	}
}
