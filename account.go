// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strings"
)

// AccountService wraps the KAS account actions: subaccounts
// (get/add/update/delete_account), the settings of the logged-in account
// (get/update_accountsettings), its resources (get_accountresources), SSH
// access (update_superusersettings) and the server information
// (get_server_information).
//
// Response fields follow recorded KAS responses (chmmou/kasapi-cli) and are
// not yet verified from this repository.
type AccountService struct {
	c *Client
}

// AccountLimit names a resource limit of an account, as KAS names it in requests.
type AccountLimit string

// The limits an account can be given. A limit of 0 allows none.
const (
	LimitSubaccounts  AccountLimit = "max_account"
	LimitDomains      AccountLimit = "max_domain"
	LimitSubdomains   AccountLimit = "max_subdomain"
	LimitWebspace     AccountLimit = "max_webspace" // in MB
	LimitMailAccounts AccountLimit = "max_mail_account"
	LimitMailForwards AccountLimit = "max_mail_forward"
	LimitMailingLists AccountLimit = "max_mailinglist"
	LimitDatabases    AccountLimit = "max_database"
	LimitFTPUsers     AccountLimit = "max_ftpuser"
	LimitSambaUsers   AccountLimit = "max_sambauser"
	LimitCronjobs     AccountLimit = "max_cronjobs"
	LimitWBKs         AccountLimit = "max_wbk"
)

// AccountLimits lists every AccountLimit.
var AccountLimits = []AccountLimit{
	LimitSubaccounts, LimitDomains, LimitSubdomains, LimitWebspace,
	LimitMailAccounts, LimitMailForwards, LimitMailingLists, LimitDatabases,
	LimitFTPUsers, LimitSambaUsers, LimitCronjobs, LimitWBKs,
}

// limitAliases are the names get_accounts reports two limits under. The
// requests follow the docs; the recorded requests of chmmou/kasapi-cli send
// max_mail_list instead of max_mailinglist. Not yet verified from here.
var limitAliases = map[string]AccountLimit{
	"max_mail_list": LimitMailingLists,
	"max_databases": LimitDatabases,
}

// AccessLog is the access log mode of an account.
type AccessLog string

// The access log modes KAS offers.
const (
	LogFull  AccessLog = "voll"
	LogShort AccessLog = "kurz"
	LogNoIP  AccessLog = "ohneip"
	LogNone  AccessLog = "keine"
)

// Subaccount is a KAS account below the logged-in one. Passwords are not mapped.
type Subaccount struct {
	Login       string // e.g. "w0123456"
	Comment     string
	ContactMail string
	Limits      map[AccountLimit]int

	DirectoryProtection bool // may protect directories
	SoftwareInstall     bool // may use the software installer
	DNSSettings         bool // may edit DNS records
	KASAccessForbidden  bool // may not log in to the KAS panel
	// SSHAccess is set with UpdateSSH.
	SSHAccess bool

	Logging AccessLog
	LogAge  int // days the access logs are kept
	// Statistics is the language of the /usage statistics, or "0" for none.
	Statistics string
	// ShowPassword is the panel's show_password setting.
	ShowPassword bool

	TwoFactor  bool // two-factor authentication is on
	InProgress bool // KAS is still applying a change
}

// AccountOptions are the settings the logged-in account and its subaccounts
// share. Unset fields are not sent.
type AccountOptions struct {
	Comment     *string
	ContactMail *string
	Logging     *AccessLog
	LogAge      *int // days, 1-999
	// Statistics is the language of the /usage statistics, or "0" for none.
	// The docs list "de" and "ne".
	Statistics   *string
	ShowPassword *bool
}

// AccountChange creates or changes a subaccount. Unset fields are not sent.
type AccountChange struct {
	AccountOptions
	// Limits sends the given limits only.
	Limits              map[AccountLimit]int
	DirectoryProtection *bool
	SoftwareInstall     *bool
	DNSSettings         *bool
	KASAccessForbidden  *bool
}

// AccountHost is the host a new subaccount is created with.
type AccountHost struct {
	// Kind is "domain", "subdomain", or "" for an account without host.
	Kind string
	// Label is the domain without TLD ("example") or the subdomain label ("forum").
	Label string
	// Parent is the TLD ("de") of a domain, or the domain ("example.de") of a subdomain.
	Parent string
	// Path is the document root; KAS defaults to /Label.Parent/.
	Path string
}

// AccountSettings are the settings of the logged-in account. Passwords are not mapped.
type AccountSettings struct {
	Login       string
	Comment     string
	ContactMail string
	Superuser   bool   // the account is a main account
	Server      string // host the account runs on

	DirectoryProtection bool
	SoftwareInstall     bool
	DNSSettings         bool
	SSHAccess           bool
	SSHKeys             []string // public keys allowed to log in
	// SSHHostKeys are the fingerprints of the server's SSH host keys.
	SSHHostKeys []SSHFingerprint

	Logging      AccessLog
	LogAge       int
	Statistics   string
	ShowPassword bool
	TwoFactor    bool
	InProgress   bool
}

// SSHFingerprint is the fingerprint of an SSH host key.
type SSHFingerprint struct {
	KeyType     string // e.g. "ED25519"
	Hash        string // "MD5" or "SHA256"
	Fingerprint string
}

// SSHChange changes the SSH access of an account. Unset fields are not sent.
type SSHChange struct {
	Access *bool
	// Keys replaces the public keys, one per entry; an empty list removes all.
	// KAS takes them newline-separated, which is not yet verified.
	Keys *[]string
}

// AccountResource is the use of one AccountLimit. Max and Free are -1 when unlimited.
type AccountResource struct {
	Max      int
	Used     int
	Created  int
	Reserved int
	Free     int
	Exceeded bool
}

// ServerComponent is one entry of the server information: a PHP version,
// the database server or the operating system.
type ServerComponent struct {
	Service string // "php", "mysql" or "os"
	Version string
	// Interface and FileExtension are set for PHP; the extension, e.g.
	// "php82", selects this version for a file.
	Interface     string
	FileExtension string
	VersionType   string // set for mysql
	Distribution  string // set for os
}

func subaccountFrom(m map[string]any) Subaccount {
	a := Subaccount{
		Login:               asString(m["account_login"]),
		Comment:             asString(m["account_comment"]),
		ContactMail:         asString(m["account_contact_mail"]),
		Limits:              map[AccountLimit]int{},
		DirectoryProtection: isYes(m["inst_htaccess"]),
		SoftwareInstall:     isYes(m["inst_software"]),
		DNSSettings:         isYes(m["dns_settings"]),
		KASAccessForbidden:  isYes(m["kas_access_forbidden"]),
		SSHAccess:           isYes(m["ssh_access"]),
		Logging:             AccessLog(asString(m["logging"])),
		LogAge:              asInt(m["logage"]),
		Statistics:          asString(m["statistic"]),
		ShowPassword:        isYes(m["show_password"]),
		TwoFactor:           isYes(m["account_2fa"]),
		InProgress:          isYes(m["in_progress"]),
	}
	for _, l := range AccountLimits {
		if v, ok := m[string(l)]; ok {
			a.Limits[l] = asInt(v)
		}
	}
	for key, l := range limitAliases {
		if v, ok := m[key]; ok {
			a.Limits[l] = asInt(v)
		}
	}
	return a
}

func (o AccountOptions) isZero() bool {
	return o.Comment == nil && o.ContactMail == nil && o.Logging == nil &&
		o.LogAge == nil && o.Statistics == nil && o.ShowPassword == nil
}

func (o AccountOptions) validate() error {
	if o.ContactMail != nil && *o.ContactMail != "" {
		if _, err := mail.ParseAddress(*o.ContactMail); err != nil {
			return fmt.Errorf("kasapi: invalid contact mail %q: %w", *o.ContactMail, err)
		}
	}
	if o.Logging != nil {
		switch *o.Logging {
		case LogFull, LogShort, LogNoIP, LogNone:
		default:
			return fmt.Errorf("kasapi: access log mode must be voll, kurz, ohneip or keine, got %q", *o.Logging)
		}
	}
	if o.LogAge != nil && (*o.LogAge < 1 || *o.LogAge > 999) {
		return fmt.Errorf("kasapi: log age must be 1-999 days, got %d", *o.LogAge)
	}
	return nil
}

func (o AccountOptions) params(params map[string]any) {
	setString(params, "account_comment", o.Comment)
	setString(params, "account_contact_mail", o.ContactMail)
	if o.Logging != nil {
		params["logging"] = string(*o.Logging)
	}
	if o.LogAge != nil {
		params["logage"] = *o.LogAge
	}
	setString(params, "statistic", o.Statistics)
	setFlag(params, "show_password", o.ShowPassword)
}

func (ch AccountChange) isZero() bool {
	return ch.AccountOptions.isZero() && len(ch.Limits) == 0 && ch.DirectoryProtection == nil &&
		ch.SoftwareInstall == nil && ch.DNSSettings == nil && ch.KASAccessForbidden == nil
}

func (ch AccountChange) validate() error {
	for l, v := range ch.Limits {
		if !knownLimit(l) {
			return fmt.Errorf("kasapi: unknown account limit %q", l)
		}
		if v < 0 {
			return fmt.Errorf("kasapi: account limit %s must not be negative, got %d", l, v)
		}
	}
	return ch.AccountOptions.validate()
}

func (ch AccountChange) params(params map[string]any) {
	ch.AccountOptions.params(params)
	for l, v := range ch.Limits {
		params[string(l)] = v
	}
	setFlag(params, "inst_htaccess", ch.DirectoryProtection)
	setFlag(params, "inst_software", ch.SoftwareInstall)
	setFlag(params, "dns_settings", ch.DNSSettings)
	setFlag(params, "kas_access_forbidden", ch.KASAccessForbidden)
}

func knownLimit(l AccountLimit) bool {
	for _, k := range AccountLimits {
		if k == l {
			return true
		}
	}
	return false
}

func (h AccountHost) params(params map[string]any) error {
	switch h.Kind {
	case "":
		if h.Label != "" || h.Parent != "" || h.Path != "" {
			return errors.New(`kasapi: account host fields need Kind "domain" or "subdomain"`)
		}
		params["hostname_art"] = ""
		return nil
	case "domain", "subdomain":
	default:
		return fmt.Errorf(`kasapi: account host kind must be "domain", "subdomain" or "", got %q`, h.Kind)
	}
	if h.Label == "" || h.Parent == "" {
		return fmt.Errorf("kasapi: a %s account needs label and parent", h.Kind)
	}
	params["hostname_art"] = h.Kind
	params["hostname_part1"] = h.Label
	params["hostname_part2"] = h.Parent
	if h.Path != "" {
		params["hostname_path"] = h.Path
	}
	return nil
}

// List returns the subaccounts of the logged-in account.
func (s *AccountService) List(ctx context.Context) ([]Subaccount, error) {
	items, err := s.c.list(ctx, "get_accounts", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing accounts: %w", err)
	}
	accounts := make([]Subaccount, 0, len(items))
	for _, m := range items {
		accounts = append(accounts, subaccountFrom(m))
	}
	return accounts, nil
}

// Get returns the subaccount with the given login, or ErrNotFound.
func (s *AccountService) Get(ctx context.Context, login string) (*Subaccount, error) {
	if login == "" {
		return nil, errors.New("kasapi: account login must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_accounts", map[string]any{"account_login": login})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading account %s: %w", login, err)
	}
	for _, m := range items {
		if a := subaccountFrom(m); a.Login == login {
			return &a, nil
		}
	}
	return nil, ErrNotFound
}

// Create adds a subaccount and returns its login. Limits not given default to 0.
func (s *AccountService) Create(ctx context.Context, host AccountHost, ch AccountChange, kasPassword, ftpPassword string) (string, error) {
	if kasPassword == "" || ftpPassword == "" {
		return "", errors.New("kasapi: KAS and FTP password of the new account must not be empty")
	}
	if err := ch.validate(); err != nil {
		return "", err
	}
	params := map[string]any{
		"account_kas_password": kasPassword,
		"account_ftp_password": ftpPassword,
	}
	if err := host.params(params); err != nil {
		return "", err
	}
	ch.params(params)
	ret, err := s.c.Exec(ctx, "add_account", params)
	if err != nil {
		return "", fmt.Errorf("creating account: %w", err)
	}
	login := createdID(ret)
	if login == "" {
		return "", errors.New("kasapi: account created but KAS returned no login")
	}
	return login, nil
}

// Update applies the set fields of ch to a subaccount.
func (s *AccountService) Update(ctx context.Context, login string, ch AccountChange) error {
	if login == "" {
		return errors.New("kasapi: account login must not be empty")
	}
	if ch.isZero() {
		return errors.New("kasapi: no account setting to update")
	}
	if err := ch.validate(); err != nil {
		return err
	}
	params := map[string]any{"account_login": login}
	ch.params(params)
	return wrapHostErr("updating account", login, s.c.update(ctx, "update_account", params))
}

// UpdatePassword changes the KAS password of a subaccount.
func (s *AccountService) UpdatePassword(ctx context.Context, login, newPassword string) error {
	if login == "" {
		return errors.New("kasapi: account login must not be empty")
	}
	if newPassword == "" {
		return errors.New("kasapi: new password must not be empty")
	}
	err := s.c.update(ctx, "update_account", map[string]any{
		"account_login":        login,
		"account_kas_password": newPassword,
	})
	return wrapHostErr("updating password of account", login, err)
}

// Delete removes a subaccount. KAS refuses one that has subaccounts itself.
func (s *AccountService) Delete(ctx context.Context, login string) error {
	if login == "" {
		return errors.New("kasapi: account login must not be empty")
	}
	err := s.c.remove(ctx, "delete_account", map[string]any{"account_login": login})
	return wrapHostErr("deleting account", login, err)
}

// UpdateSSH changes the SSH access of an account. Only a main account may
// call it, for itself or a subaccount.
func (s *AccountService) UpdateSSH(ctx context.Context, login string, ch SSHChange) error {
	if login == "" {
		return errors.New("kasapi: account login must not be empty")
	}
	if ch.Access == nil && ch.Keys == nil {
		return errors.New("kasapi: no SSH setting to update")
	}
	params := map[string]any{"account_login": login}
	setFlag(params, "ssh_access", ch.Access)
	if ch.Keys != nil {
		for _, k := range *ch.Keys {
			if k == "" || strings.ContainsAny(k, "\r\n") {
				return fmt.Errorf("kasapi: SSH key %q must be one non-empty line", k)
			}
		}
		params["ssh_keys"] = strings.Join(*ch.Keys, "\n")
	}
	return wrapHostErr("updating SSH access of account", login, s.c.update(ctx, "update_superusersettings", params))
}

// Settings returns the settings of the logged-in account.
func (s *AccountService) Settings(ctx context.Context) (*AccountSettings, error) {
	ret, err := s.c.Exec(ctx, "get_accountsettings", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("reading account settings: %w", err)
	}
	m, _ := ret.(map[string]any)
	if inner, ok := m["settings"].(map[string]any); ok {
		m = inner
	}
	if m == nil {
		return nil, fmt.Errorf("kasapi: account settings: unexpected response %v", ret)
	}
	a := subaccountFrom(m)
	return &AccountSettings{
		Login: a.Login, Comment: a.Comment, ContactMail: a.ContactMail,
		Superuser: isYes(m["is_superuser"]), Server: asString(m["server"]),
		DirectoryProtection: a.DirectoryProtection, SoftwareInstall: a.SoftwareInstall,
		DNSSettings: a.DNSSettings, SSHAccess: a.SSHAccess,
		SSHKeys:     splitLines(asString(m["ssh_keys"])),
		SSHHostKeys: fingerprintsFrom(m["ssh_fingerprints"]),
		Logging:     a.Logging, LogAge: a.LogAge, Statistics: a.Statistics,
		ShowPassword: a.ShowPassword, TwoFactor: a.TwoFactor, InProgress: a.InProgress,
	}, nil
}

// fingerprintsFrom reads {key type: {"MD5:": fp, "SHA256:": fp}}, sorted.
func fingerprintsFrom(v any) []SSHFingerprint {
	byType, _ := v.(map[string]any)
	var out []SSHFingerprint
	for keyType, hashes := range byType {
		hm, _ := hashes.(map[string]any)
		for hash, fp := range hm {
			out = append(out, SSHFingerprint{
				KeyType: keyType, Hash: strings.TrimSuffix(hash, ":"), Fingerprint: asString(fp),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].KeyType != out[j].KeyType {
			return out[i].KeyType < out[j].KeyType
		}
		return out[i].Hash < out[j].Hash
	})
	return out
}

// UpdateSettings applies the set options to the logged-in account.
func (s *AccountService) UpdateSettings(ctx context.Context, o AccountOptions) error {
	if o.isZero() {
		return errors.New("kasapi: no account setting to update")
	}
	if err := o.validate(); err != nil {
		return err
	}
	params := map[string]any{}
	o.params(params)
	if err := s.c.update(ctx, "update_accountsettings", params); err != nil {
		return fmt.Errorf("updating account settings: %w", err)
	}
	return nil
}

// UpdateOwnPassword changes the KAS password of the logged-in account. The
// client keeps Config.Password; create a new Client to log in again.
func (s *AccountService) UpdateOwnPassword(ctx context.Context, newPassword string) error {
	if newPassword == "" {
		return errors.New("kasapi: new password must not be empty")
	}
	err := s.c.update(ctx, "update_accountsettings", map[string]any{"account_password": newPassword})
	if err != nil {
		return fmt.Errorf("updating account password: %w", err)
	}
	return nil
}

// Resources returns the use of each limit of the logged-in account.
func (s *AccountService) Resources(ctx context.Context) (map[AccountLimit]AccountResource, error) {
	ret, err := s.c.Exec(ctx, "get_accountresources", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("reading account resources: %w", err)
	}
	m, _ := ret.(map[string]any)
	out := make(map[AccountLimit]AccountResource, len(m))
	for key, v := range m {
		r, ok := v.(map[string]any)
		if !ok {
			continue
		}
		l := AccountLimit(key)
		if alias, ok := limitAliases[key]; ok {
			l = alias
		}
		out[l] = AccountResource{
			Max: asInt(r["max"]), Used: asInt(r["used"]), Created: asInt(r["created"]),
			Reserved: asInt(r["reserved"]), Free: asInt(r["free"]), Exceeded: isYes(r["exceeded"]),
		}
	}
	return out, nil
}

// ServerInfo returns the PHP versions, database server and operating system
// of the account's server.
func (s *AccountService) ServerInfo(ctx context.Context) ([]ServerComponent, error) {
	items, err := s.c.list(ctx, "get_server_information", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("reading server information: %w", err)
	}
	out := make([]ServerComponent, 0, len(items))
	for _, m := range items {
		out = append(out, ServerComponent{
			Service:       asString(m["service"]),
			Version:       asString(m["version"]),
			Interface:     asString(m["interface"]),
			FileExtension: asString(m["file_extension"]),
			VersionType:   asString(m["version_type"]),
			Distribution:  asString(m["distribution"]),
		})
	}
	return out, nil
}

// setString sets params[key] when v is set.
func setString(params map[string]any, key string, v *string) {
	if v != nil {
		params[key] = *v
	}
}

// setFlag sets params[key] to Y or N when v is set.
func setFlag(params map[string]any, key string, v *bool) {
	if v != nil {
		params[key] = yn(*v)
	}
}
