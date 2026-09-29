// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"strconv"
	"strings"
	"time"
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
	// Responder is the autoresponder configuration.
	Responder Responder
	// State reports whether the mailbox receives mail and allows retrieval.
	State MailState
	// AllowNets restricts access to IP addresses, CIDR networks or "webmail".
	AllowNets []string
	// SpamFilters names the active standard filters, e.g. "pdw".
	SpamFilters []string
	// WebmailAutologin lets the KAS panel log into webmail without the password.
	WebmailAutologin bool
	// InProgress reports whether KAS is still applying a change.
	InProgress bool
}

// MailState is the activation state of a mailbox.
type MailState string

const (
	// MailActive receives mail and allows retrieval.
	MailActive MailState = "Y"
	// MailReceiveDisabled rejects incoming mail; stored mail stays retrievable.
	MailReceiveDisabled MailState = "N"
	// MailForbidden rejects incoming mail and blocks retrieval.
	MailForbidden MailState = "forbidden"
)

// Responder is the autoresponder of a mailbox.
type Responder struct {
	// Active turns the responder on; Start and End limit it to a window.
	Active bool
	// Start and End bound the responder. Set both or neither.
	Start time.Time
	End   time.Time
	// Text is the reply body. KAS rejects an active responder without one.
	Text string
	// ContentType is "text" (the KAS default) or "html".
	ContentType string
	// DisplayName is the sender name shown on the reply.
	DisplayName string
}

// responderValue renders N, Y or the window as "start|end" unix timestamps.
func (r Responder) responderValue() string {
	switch {
	case !r.Active:
		return "N"
	case !r.Start.IsZero():
		return strconv.FormatInt(r.Start.Unix(), 10) + "|" + strconv.FormatInt(r.End.Unix(), 10)
	}
	return "Y"
}

func (r Responder) validate() error {
	if !r.Active {
		return nil
	}
	if strings.TrimSpace(r.Text) == "" {
		return errors.New("kasapi: an active responder needs a text")
	}
	if r.Start.IsZero() != r.End.IsZero() {
		return errors.New("kasapi: responder start and end must be set together")
	}
	if !r.Start.IsZero() && !r.Start.Before(r.End) {
		return errors.New("kasapi: responder start must be before its end")
	}
	switch r.ContentType {
	case "", "text", "html":
	default:
		return fmt.Errorf("kasapi: responder content type must be text or html, got %q", r.ContentType)
	}
	return nil
}

// responderFrom reads the responder fields of a get_mailaccounts entry.
func responderFrom(m map[string]any) Responder {
	r := Responder{
		Text:        asString(m["mail_responder_text"]),
		ContentType: asString(m["mail_responder_content_type"]),
		DisplayName: asString(m["mail_responder_displayname"]),
	}
	raw := strings.TrimSpace(asString(m["mail_responder"]))
	if start, end, ok := strings.Cut(raw, "|"); ok {
		from, errFrom := strconv.ParseInt(strings.TrimSpace(start), 10, 64)
		to, errTo := strconv.ParseInt(strings.TrimSpace(end), 10, 64)
		if errFrom == nil && errTo == nil {
			r.Active = true
			r.Start, r.End = time.Unix(from, 0).UTC(), time.Unix(to, 0).UTC()
		}
		return r
	}
	r.Active = isYes(raw)
	return r
}

// mailStateFrom reads mail_is_active; an absent field means active.
func mailStateFrom(v any) MailState {
	switch raw := strings.TrimSpace(asString(v)); strings.ToLower(raw) {
	case "", "y":
		return MailActive
	case "n":
		return MailReceiveDisabled
	default:
		return MailState(strings.ToLower(raw))
	}
}

func mailAccountFrom(m map[string]any) MailAccount {
	acc := MailAccount{
		Login:            asString(m["mail_login"]),
		CopyAddresses:    splitAddressList(asString(m["mail_copy_adress"])),
		SenderAliases:    splitAddressList(asString(m["mail_sender_alias"])),
		Responder:        responderFrom(m),
		State:            mailStateFrom(m["mail_is_active"]),
		AllowNets:        splitList(asString(m["mail_allow_nets"])),
		SpamFilters:      splitList(asString(m["mail_spamfilter"])),
		WebmailAutologin: isYes(m["webmail_autologin"]),
		InProgress:       isYes(m["in_progress"]),
	}
	acc.ResponderActive = acc.Responder.Active
	// mail_adresses lists the addresses bound to the account.
	if addrs := splitAddressList(asString(m["mail_adresses"])); len(addrs) > 0 {
		if lp, dom, ok := strings.Cut(addrs[0], "@"); ok {
			acc.LocalPart, acc.Domain = lp, dom
		}
	}
	return acc
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

// validateAllowNets accepts IP addresses, CIDR networks and "webmail".
func validateAllowNets(nets []string) error {
	for _, n := range nets {
		if n == "webmail" {
			continue
		}
		if _, err := netip.ParseAddr(n); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(n); err == nil {
			continue
		}
		return fmt.Errorf("kasapi: invalid allowed client %q: want an IP address, a CIDR network or \"webmail\"", n)
	}
	return nil
}

// --- accounts ---------------------------------------------------------------

// ListAccounts returns all mail accounts of the KAS account.
func (s *MailService) ListAccounts(ctx context.Context) ([]MailAccount, error) {
	items, err := s.c.list(ctx, "get_mailaccounts", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing mail accounts: %w", err)
	}
	accounts := make([]MailAccount, 0, len(items))
	for _, m := range items {
		accounts = append(accounts, mailAccountFrom(m))
	}
	return accounts, nil
}

// GetAccount returns the account with the given KAS login, or ErrNotFound.
func (s *MailService) GetAccount(ctx context.Context, login string) (*MailAccount, error) {
	if login == "" {
		return nil, errors.New("kasapi: mail login must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_mailaccounts", map[string]any{"mail_login": login})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading mail account %s: %w", login, err)
	}
	for _, m := range items {
		if acc := mailAccountFrom(m); acc.Login == login {
			return &acc, nil
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
	if err := a.Responder.validate(); err != nil {
		return "", err
	}
	if err := validateAllowNets(a.AllowNets); err != nil {
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
	if a.Responder.Active {
		addResponderParams(params, a.Responder)
	}
	if len(a.AllowNets) > 0 {
		params["mail_allow_nets"] = joinList(a.AllowNets)
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
	if err != nil && !isNothingToDo(err) {
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
	if err != nil && !isNothingToDo(err) {
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
	if err != nil && !isNothingToDo(err) {
		return fmt.Errorf("updating sender aliases of mail account %s: %w", login, err)
	}
	return nil
}

// addResponderParams sets the responder request parameters.
func addResponderParams(params map[string]any, r Responder) {
	params["responder"] = r.responderValue()
	if !r.Active {
		return
	}
	params["responder_text"] = r.Text
	if r.ContentType != "" {
		params["mail_responder_content_type"] = r.ContentType
	}
	if r.DisplayName != "" {
		params["mail_responder_displayname"] = r.DisplayName
	}
}

// updateAccount runs update_mailaccount for login with the given parameters.
func (s *MailService) updateAccount(ctx context.Context, login, what string, params map[string]any) error {
	if login == "" {
		return errors.New("kasapi: mail login must not be empty")
	}
	params["mail_login"] = login
	err := s.c.update(ctx, "update_mailaccount", params)
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("updating %s of mail account %s: %w", what, login, err)
}

// UpdateResponder sets the autoresponder; Active false turns it off.
func (s *MailService) UpdateResponder(ctx context.Context, login string, r Responder) error {
	if err := r.validate(); err != nil {
		return err
	}
	params := map[string]any{}
	addResponderParams(params, r)
	return s.updateAccount(ctx, login, "responder", params)
}

// UpdateState sets whether the mailbox receives mail and allows retrieval.
func (s *MailService) UpdateState(ctx context.Context, login string, state MailState) error {
	switch state {
	case MailActive, MailReceiveDisabled, MailForbidden:
	default:
		return fmt.Errorf("kasapi: invalid mail state %q", state)
	}
	return s.updateAccount(ctx, login, "state", map[string]any{"is_active": string(state)})
}

// UpdateAllowNets replaces the allowed clients; an empty list lifts the restriction.
func (s *MailService) UpdateAllowNets(ctx context.Context, login string, nets []string) error {
	if err := validateAllowNets(nets); err != nil {
		return err
	}
	return s.updateAccount(ctx, login, "allowed clients", map[string]any{"mail_allow_nets": joinList(nets)})
}

// UpdateWebmailAutologin sets whether the KAS panel may log into webmail.
func (s *MailService) UpdateWebmailAutologin(ctx context.Context, login string, enabled bool) error {
	return s.updateAccount(ctx, login, "webmail autologin", map[string]any{"webmail_autologin": yn(enabled)})
}

// --- standard filters ---------------------------------------------------------

// MailFilterInfo describes a standard filter KAS offers.
type MailFilterInfo struct {
	Name        string // identifier used in MailFilter.Name
	Type        string // filter family, e.g. "rspamd"; "content" filters take an action
	Title       string // display name
	Recommended bool
}

// MailFilter selects a standard filter for a mailbox.
type MailFilter struct {
	// Name is the filter identifier from AvailableFilters.
	Name string
	// Action, for content filters only: delete, mark, move=<folder> or forward=<address>.
	Action string
}

func (f MailFilter) String() string {
	if f.Action == "" {
		return f.Name
	}
	return f.Name + ":" + f.Action
}

func (f MailFilter) validate() error {
	if f.Name == "" {
		return errors.New("kasapi: mail filter name must not be empty")
	}
	// ";" and ":" are the separators of the filter parameter.
	if strings.ContainsAny(f.Name, ";:") || strings.Contains(f.Action, ";") {
		return fmt.Errorf("kasapi: mail filter %q contains a separator character", f.String())
	}
	if f.Action == "" || f.Action == "delete" || f.Action == "mark" {
		return nil
	}
	kind, arg, ok := strings.Cut(f.Action, "=")
	if !ok || arg == "" {
		return fmt.Errorf("kasapi: invalid mail filter action %q", f.Action)
	}
	switch kind {
	case "move":
		return nil
	case "forward":
		if _, err := mail.ParseAddress(arg); err != nil {
			return fmt.Errorf("kasapi: invalid forward address in mail filter action %q: %w", f.Action, err)
		}
		return nil
	}
	return fmt.Errorf("kasapi: invalid mail filter action %q", f.Action)
}

// AvailableFilters returns the standard filters the account may use.
func (s *MailService) AvailableFilters(ctx context.Context) ([]MailFilterInfo, error) {
	items, err := s.c.list(ctx, "get_mailstandardfilter", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing mail standard filters: %w", err)
	}
	filters := make([]MailFilterInfo, 0, len(items))
	for _, m := range items {
		filters = append(filters, MailFilterInfo{
			Name:        asString(m["filter"]),
			Type:        asString(m["type"]),
			Title:       asString(m["title"]),
			Recommended: isYes(m["recommended"]),
		})
	}
	return filters, nil
}

// SetFilters sets the standard filters of a mailbox; DeleteFilters removes them.
func (s *MailService) SetFilters(ctx context.Context, login string, filters []MailFilter) error {
	if login == "" {
		return errors.New("kasapi: mail login must not be empty")
	}
	if len(filters) == 0 {
		return errors.New("kasapi: at least one mail filter is required; use DeleteFilters to remove them")
	}
	parts := make([]string, 0, len(filters))
	for _, f := range filters {
		if err := f.validate(); err != nil {
			return err
		}
		parts = append(parts, f.String())
	}
	err := s.c.update(ctx, "add_mailstandardfilter", map[string]any{
		"mail_login": login,
		"filter":     strings.Join(parts, ";"),
	})
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("setting filters of mail account %s: %w", login, err)
}

// DeleteFilters removes all standard filters of a mailbox.
func (s *MailService) DeleteFilters(ctx context.Context, login string) error {
	if login == "" {
		return errors.New("kasapi: mail login must not be empty")
	}
	err := s.c.remove(ctx, "delete_mailstandardfilter", map[string]any{"mail_login": login})
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("deleting filters of mail account %s: %w", login, err)
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
	// SpamFilters names the standard filters active on the forward.
	SpamFilters []string
	// InProgress reports whether KAS is still applying a change.
	InProgress bool
}

func mailForwardFrom(m map[string]any) MailForward {
	fw := MailForward{
		Targets:     splitAddressList(asString(m["mail_forward_targets"])),
		SpamFilters: splitList(asString(m["mail_forward_spamfilter"])),
		InProgress:  isYes(m["in_progress"]),
	}
	if lp, dom, ok := strings.Cut(asString(m["mail_forward_adress"]), "@"); ok {
		fw.LocalPart, fw.Domain = lp, dom
	}
	return fw
}

func (f MailForward) Source() string { return f.LocalPart + "@" + f.Domain }

// ListForwards returns all mail forwards of the KAS account.
func (s *MailService) ListForwards(ctx context.Context) ([]MailForward, error) {
	items, err := s.c.list(ctx, "get_mailforwards", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing mail forwards: %w", err)
	}
	forwards := make([]MailForward, 0, len(items))
	for _, m := range items {
		forwards = append(forwards, mailForwardFrom(m))
	}
	return forwards, nil
}

// GetForward returns the forward for source (local@domain), or ErrNotFound.
func (s *MailService) GetForward(ctx context.Context, source string) (*MailForward, error) {
	if source == "" {
		return nil, errors.New("kasapi: forward source must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_mailforwards", map[string]any{"mail_forward": source})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading mail forward %s: %w", source, err)
	}
	for _, m := range items {
		if fw := mailForwardFrom(m); strings.EqualFold(fw.Source(), source) {
			return &fw, nil
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
	if err != nil && !isNothingToDo(err) {
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
func splitAddressList(s string) []string { return splitList(s) }

// addTargetParams sets target_0..target_9 as expected by the forward actions.
func addTargetParams(params map[string]any, targets []string) {
	for i, t := range targets {
		params[fmt.Sprintf("target_%d", i)] = t
	}
}
