// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// MailService wraps the KAS email account and forward actions.
//
// KAS has no standalone alias objects: incoming aliases are modeled as mail
// forwards, outgoing (sender) aliases as the mail_sender_alias list of a
// mailbox — see MailAccount.SenderAliases.
//
// Parameter names follow the KAS panel docs (Tools -> KAS API); verify them
// against a live get_mailaccounts / get_mailforwards response before relying on
// them. The one-d spelling "adress(es)" is the API's, not a typo.
type MailService struct {
	c *Client
}

// MailAccount is a mailbox hosted at KAS. Passwords are write-only (KAS never
// returns them) and passed separately to Create/UpdatePassword.
type MailAccount struct {
	Login     string // KAS-assigned account login, e.g. "m1234567"
	LocalPart string // part before the @
	Domain    string // part after the @

	// CopyAddresses receive a copy of every incoming mail.
	CopyAddresses []string
	// SenderAliases are addresses the mailbox may use in the FROM header
	// when sending. To receive mail under an alias, create a MailForward
	// pointing at this mailbox instead.
	SenderAliases []string
	// ResponderActive reports whether an autoresponder is enabled.
	ResponderActive bool
}

// Address returns the primary address local@domain.
func (a MailAccount) Address() string {
	return a.LocalPart + "@" + a.Domain
}

// validateAddrParts rejects malformed/injected values before they reach the API.
func validateAddrParts(localPart, domain string) error {
	if localPart == "" || domain == "" {
		return errors.New("kasapi: local part and domain must not be empty")
	}
	if _, err := mail.ParseAddress(localPart + "@" + domain); err != nil {
		return fmt.Errorf("kasapi: invalid address %q: %w", localPart+"@"+domain, err)
	}
	return nil
}

func validateTargets(targets []string) error {
	if len(targets) == 0 {
		return errors.New("kasapi: at least one forward target is required")
	}
	// The API accepts target_0..target_9.
	if len(targets) > 10 {
		return fmt.Errorf("kasapi: at most 10 forward targets are supported, got %d", len(targets))
	}
	for _, t := range targets {
		if _, err := mail.ParseAddress(t); err != nil {
			return fmt.Errorf("kasapi: invalid forward target %q: %w", t, err)
		}
	}
	return nil
}

func validateAddressList(kind string, addrs []string) error {
	for _, a := range addrs {
		if _, err := mail.ParseAddress(a); err != nil {
			return fmt.Errorf("kasapi: invalid %s %q: %w", kind, a, err)
		}
	}
	return nil
}

// --- accounts ---------------------------------------------------------------

// ListAccounts returns all mail accounts of the KAS account.
func (s *MailService) ListAccounts(ctx context.Context) ([]MailAccount, error) {
	ret, err := s.c.Exec(ctx, "get_mailaccounts", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing mail accounts: %w", err)
	}

	items, ok := ret.([]any)
	if !ok {
		return nil, nil
	}

	accounts := make([]MailAccount, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		acc := MailAccount{
			Login:           asString(m["mail_login"]),
			ResponderActive: asString(m["mail_responder"]) == "Y",
			CopyAddresses:   splitAddressList(asString(m["mail_copy_adress"])),
			SenderAliases:   splitAddressList(asString(m["mail_sender_alias"])),
		}
		// mail_adresses lists the addresses bound to the account.
		if addrs := splitAddressList(asString(m["mail_adresses"])); len(addrs) > 0 {
			if lp, dom, ok := strings.Cut(addrs[0], "@"); ok {
				acc.LocalPart, acc.Domain = lp, dom
			}
		}
		accounts = append(accounts, acc)
	}
	return accounts, nil
}

// GetAccount returns the account with the given KAS login, or ErrNotFound.
func (s *MailService) GetAccount(ctx context.Context, login string) (*MailAccount, error) {
	accounts, err := s.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	for i := range accounts {
		if accounts[i].Login == login {
			return &accounts[i], nil
		}
	}
	return nil, ErrNotFound
}

// CreateAccount creates a mailbox for localPart@domain and returns the
// KAS-assigned login. The password is used only for this call.
func (s *MailService) CreateAccount(ctx context.Context, a MailAccount, password string) (string, error) {
	if err := validateAddrParts(a.LocalPart, a.Domain); err != nil {
		return "", err
	}
	if password == "" {
		return "", errors.New("kasapi: mail account password must not be empty")
	}
	if err := validateAddressList("copy address", a.CopyAddresses); err != nil {
		return "", err
	}
	if err := validateAddressList("sender alias", a.SenderAliases); err != nil {
		return "", err
	}

	params := map[string]any{
		"local_part":    a.LocalPart,
		"domain_part":   a.Domain,
		"mail_password": password,
	}
	if len(a.CopyAddresses) > 0 {
		params["copy_adress"] = strings.Join(a.CopyAddresses, ",")
	}
	if len(a.SenderAliases) > 0 {
		params["mail_sender_alias"] = strings.Join(a.SenderAliases, ",")
	}

	ret, err := s.c.Exec(ctx, "add_mailaccount", params)
	if err != nil {
		return "", fmt.Errorf("creating mail account %s: %w", a.Address(), err)
	}

	if login := asString(ret); login != "" && login != "TRUE" {
		return login, nil
	}

	// Fallback: find the account by its address.
	accounts, err := s.ListAccounts(ctx)
	if err != nil {
		return "", fmt.Errorf("account created but login lookup failed: %w", err)
	}
	for _, acc := range accounts {
		if strings.EqualFold(acc.Address(), a.Address()) {
			return acc.Login, nil
		}
	}
	return "", fmt.Errorf("account %s created but not found afterwards", a.Address())
}

// UpdatePassword changes the mailbox password.
func (s *MailService) UpdatePassword(ctx context.Context, login, newPassword string) error {
	if login == "" {
		return errors.New("kasapi: mail login must not be empty")
	}
	if newPassword == "" {
		return errors.New("kasapi: new password must not be empty")
	}
	_, err := s.c.Exec(ctx, "update_mailaccount", map[string]any{
		"mail_login":        login,
		"mail_new_password": newPassword,
	})
	if err != nil {
		return fmt.Errorf("updating password of mail account %s: %w", login, err)
	}
	return nil
}

// UpdateCopyAddresses replaces the copy address list of a mailbox. An empty
// list clears it.
func (s *MailService) UpdateCopyAddresses(ctx context.Context, login string, copyAddresses []string) error {
	if login == "" {
		return errors.New("kasapi: mail login must not be empty")
	}
	if err := validateAddressList("copy address", copyAddresses); err != nil {
		return err
	}
	_, err := s.c.Exec(ctx, "update_mailaccount", map[string]any{
		"mail_login":  login,
		"copy_adress": strings.Join(copyAddresses, ","),
	})
	if err != nil {
		return fmt.Errorf("updating copy addresses of mail account %s: %w", login, err)
	}
	return nil
}

// UpdateSenderAliases replaces the sender alias list of a mailbox — the
// addresses it may use in the FROM header when sending. An empty list clears
// it. Aliases only affect sending; to receive mail under an alias, create a
// MailForward pointing at the mailbox.
func (s *MailService) UpdateSenderAliases(ctx context.Context, login string, aliases []string) error {
	if login == "" {
		return errors.New("kasapi: mail login must not be empty")
	}
	if err := validateAddressList("sender alias", aliases); err != nil {
		return err
	}
	_, err := s.c.Exec(ctx, "update_mailaccount", map[string]any{
		"mail_login":        login,
		"mail_sender_alias": strings.Join(aliases, ","),
	})
	if err != nil {
		return fmt.Errorf("updating sender aliases of mail account %s: %w", login, err)
	}
	return nil
}

// DeleteAccount removes a mailbox and all its data.
func (s *MailService) DeleteAccount(ctx context.Context, login string) error {
	if login == "" {
		return errors.New("kasapi: mail login must not be empty")
	}
	_, err := s.c.Exec(ctx, "delete_mailaccount", map[string]any{
		"mail_login": login,
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && strings.Contains(apiErr.Code, "not_found") {
			return ErrNotFound
		}
		return fmt.Errorf("deleting mail account %s: %w", login, err)
	}
	return nil
}

// --- forwards ----------------------------------------------------------------

// MailForward forwards mail for Source (local@domain) to one or more targets.
type MailForward struct {
	LocalPart string
	Domain    string
	Targets   []string
}

func (f MailForward) Source() string { return f.LocalPart + "@" + f.Domain }

// ListForwards returns all mail forwards of the KAS account.
func (s *MailService) ListForwards(ctx context.Context) ([]MailForward, error) {
	ret, err := s.c.Exec(ctx, "get_mailforwards", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing mail forwards: %w", err)
	}

	items, ok := ret.([]any)
	if !ok {
		return nil, nil
	}

	forwards := make([]MailForward, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		fw := MailForward{
			Targets: splitAddressList(asString(m["mail_forward_targets"])),
		}
		if lp, dom, ok := strings.Cut(asString(m["mail_forward_adress"]), "@"); ok {
			fw.LocalPart, fw.Domain = lp, dom
		}
		forwards = append(forwards, fw)
	}
	return forwards, nil
}

// GetForward returns the forward for source (local@domain), or ErrNotFound.
func (s *MailService) GetForward(ctx context.Context, source string) (*MailForward, error) {
	forwards, err := s.ListForwards(ctx)
	if err != nil {
		return nil, err
	}
	for i := range forwards {
		if strings.EqualFold(forwards[i].Source(), source) {
			return &forwards[i], nil
		}
	}
	return nil, ErrNotFound
}

// CreateForward creates a forward. The source address is its identifier.
func (s *MailService) CreateForward(ctx context.Context, f MailForward) error {
	if err := validateAddrParts(f.LocalPart, f.Domain); err != nil {
		return err
	}
	if err := validateTargets(f.Targets); err != nil {
		return err
	}
	params := map[string]any{
		"local_part":  f.LocalPart,
		"domain_part": f.Domain,
	}
	addTargetParams(params, f.Targets)
	_, err := s.c.Exec(ctx, "add_mailforward", params)
	if err != nil {
		return fmt.Errorf("creating mail forward %s: %w", f.Source(), err)
	}
	return nil
}

// UpdateForward replaces the targets of an existing forward.
func (s *MailService) UpdateForward(ctx context.Context, f MailForward) error {
	if err := validateAddrParts(f.LocalPart, f.Domain); err != nil {
		return err
	}
	if err := validateTargets(f.Targets); err != nil {
		return err
	}
	params := map[string]any{
		"mail_forward": f.Source(),
	}
	addTargetParams(params, f.Targets)
	_, err := s.c.Exec(ctx, "update_mailforward", params)
	if err != nil {
		return fmt.Errorf("updating mail forward %s: %w", f.Source(), err)
	}
	return nil
}

// DeleteForward removes a forward by its source address.
func (s *MailService) DeleteForward(ctx context.Context, source string) error {
	if source == "" {
		return errors.New("kasapi: forward source must not be empty")
	}
	_, err := s.c.Exec(ctx, "delete_mailforward", map[string]any{
		"mail_forward": source,
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && strings.Contains(apiErr.Code, "not_found") {
			return ErrNotFound
		}
		return fmt.Errorf("deleting mail forward %s: %w", source, err)
	}
	return nil
}

// --- helpers ------------------------------------------------------------------

// splitAddressList splits KAS address lists, which use ";" or "," depending on
// the action, and trims empties.
func splitAddressList(s string) []string {
	if s == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// addTargetParams sets target_0..target_9 as expected by the forward actions.
func addTargetParams(params map[string]any, targets []string) {
	for i, t := range targets {
		params[fmt.Sprintf("target_%d", i)] = t
	}
}
