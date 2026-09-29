// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// DDNSService wraps the KAS dynamic DNS actions (get/add/update/delete_ddnsuser).
type DDNSService struct {
	c *Client
}

// DDNSUser is a dynamic DNS login and the host it controls. Passwords are not mapped.
type DDNSUser struct {
	Login   string // KAS-assigned login, e.g. "dyn0123456"
	Comment string // free text; KAS requires one on create
	Zone    string // zone of the host, e.g. "example.com"
	Label   string // host label inside the zone, e.g. "home"

	// TargetIP is the initial IPv4 address on create; the DDNS client sets it afterwards.
	TargetIP string
	// TargetIPv6 is set by the DDNS client only.
	TargetIPv6 string
	// DualStack lets the host carry an A and an AAAA record.
	DualStack bool
}

// Host returns the full host name the user controls, label.zone.
func (u DDNSUser) Host() string {
	if u.Label == "" {
		return u.Zone
	}
	return u.Label + "." + u.Zone
}

func ddnsUserFrom(m map[string]any) DDNSUser {
	u := DDNSUser{
		Login:      asString(m["dyndns_login"]),
		Comment:    asString(m["dyndns_comment"]),
		Zone:       asString(m["dyndns_zone"]),
		Label:      asString(m["dyndns_label"]),
		TargetIP:   asString(m["dyndns_target_ipv4"]),
		TargetIPv6: asString(m["dyndns_target_ipv6"]),
		DualStack:  isYes(m["dyndns_dual_stack"]),
	}
	// Older responses carry the address in dyndns_target_ip.
	if u.TargetIP == "" {
		u.TargetIP = asString(m["dyndns_target_ip"])
	}
	return u
}

// List returns all DDNS users of the KAS account.
func (s *DDNSService) List(ctx context.Context) ([]DDNSUser, error) {
	items, err := s.c.list(ctx, "get_ddnsusers", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing DDNS users: %w", err)
	}
	users := make([]DDNSUser, 0, len(items))
	for _, m := range items {
		users = append(users, ddnsUserFrom(m))
	}
	return users, nil
}

// Get returns the DDNS user with the given login, or ErrNotFound.
func (s *DDNSService) Get(ctx context.Context, login string) (*DDNSUser, error) {
	if login == "" {
		return nil, errors.New("kasapi: DDNS login must not be empty")
	}
	// The filter is ddns_login; every other DDNS action uses dyndns_login.
	items, err := s.c.getOne(ctx, "get_ddnsusers", map[string]any{"ddns_login": login})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading DDNS user %s: %w", login, err)
	}
	for _, m := range items {
		if u := ddnsUserFrom(m); u.Login == login {
			return &u, nil
		}
	}
	return nil, ErrNotFound
}

// Create adds a DDNS user for u.Label.u.Zone and returns the KAS-assigned login.
func (s *DDNSService) Create(ctx context.Context, u DDNSUser, password string) (string, error) {
	if password == "" {
		return "", errors.New("kasapi: DDNS password must not be empty")
	}
	if u.Zone == "" || u.Label == "" {
		return "", errors.New("kasapi: DDNS zone and label must not be empty")
	}
	if u.Comment == "" {
		return "", errors.New("kasapi: DDNS comment must not be empty")
	}
	addr, err := netip.ParseAddr(u.TargetIP)
	if err != nil {
		return "", fmt.Errorf("kasapi: invalid DDNS target IP %q: %w", u.TargetIP, err)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("kasapi: DDNS target IP %q must be an IPv4 address", u.TargetIP)
	}
	params := map[string]any{
		"dyndns_comment":   u.Comment,
		"dyndns_password":  password,
		"dyndns_zone":      strings.TrimSuffix(u.Zone, "."),
		"dyndns_label":     u.Label,
		"dyndns_target_ip": u.TargetIP,
	}
	if u.DualStack {
		params["dyndns_dual_stack"] = yn(true)
	}
	ret, err := s.c.Exec(ctx, "add_ddnsuser", params)
	if err != nil {
		return "", fmt.Errorf("creating DDNS user for %s: %w", u.Host(), err)
	}
	login := createdID(ret)
	if login == "" {
		return "", fmt.Errorf("kasapi: DDNS user for %s created but KAS returned no login", u.Host())
	}
	return login, nil
}

// Update replaces comment and dual-stack mode; zone and label are fixed at creation.
func (s *DDNSService) Update(ctx context.Context, u DDNSUser) error {
	if u.Login == "" {
		return errors.New("kasapi: DDNS login must not be empty")
	}
	if u.Comment == "" {
		return errors.New("kasapi: DDNS comment must not be empty")
	}
	err := s.c.update(ctx, "update_ddnsuser", map[string]any{
		"dyndns_login":      u.Login,
		"dyndns_comment":    u.Comment,
		"dyndns_dual_stack": yn(u.DualStack),
	})
	return wrapHostErr("updating DDNS user", u.Login, err)
}

// UpdatePassword changes the password the DDNS client authenticates with.
func (s *DDNSService) UpdatePassword(ctx context.Context, login, newPassword string) error {
	if login == "" {
		return errors.New("kasapi: DDNS login must not be empty")
	}
	if newPassword == "" {
		return errors.New("kasapi: new password must not be empty")
	}
	err := s.c.update(ctx, "update_ddnsuser", map[string]any{
		"dyndns_login":    login,
		"dyndns_password": newPassword,
	})
	return wrapHostErr("updating password of DDNS user", login, err)
}

// Delete removes a DDNS user and the record of its host.
func (s *DDNSService) Delete(ctx context.Context, login string) error {
	if login == "" {
		return errors.New("kasapi: DDNS login must not be empty")
	}
	err := s.c.remove(ctx, "delete_ddnsuser", map[string]any{"dyndns_login": login})
	return wrapHostErr("deleting DDNS user", login, err)
}
