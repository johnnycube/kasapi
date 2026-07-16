// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"testing"

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
