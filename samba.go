// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
)

// SambaService wraps the KAS network drive actions (get/add/update/delete_sambauser).
type SambaService struct {
	c *Client
}

// SambaUser is a network drive login confined to a directory. The password is not mapped.
type SambaUser struct {
	Login   string // KAS-assigned login, e.g. "s0123456"
	Path    string // directory the drive exposes
	Comment string // free text; KAS requires one on create

	// InProgress reports whether KAS is still applying a change.
	InProgress bool
}

func sambaUserFrom(m map[string]any) SambaUser {
	return SambaUser{
		Login:      asString(m["samba_login"]),
		Path:       asString(m["samba_path"]),
		Comment:    asString(m["samba_comment"]),
		InProgress: isYes(m["in_progress"]),
	}
}

// List returns all network drive users of the KAS account.
func (s *SambaService) List(ctx context.Context) ([]SambaUser, error) {
	items, err := s.c.list(ctx, "get_sambausers", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing network drive users: %w", err)
	}
	users := make([]SambaUser, 0, len(items))
	for _, m := range items {
		users = append(users, sambaUserFrom(m))
	}
	return users, nil
}

// Get returns the network drive user with the given login, or ErrNotFound.
func (s *SambaService) Get(ctx context.Context, login string) (*SambaUser, error) {
	if login == "" {
		return nil, errors.New("kasapi: network drive login must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_sambausers", map[string]any{"samba_login": login})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading network drive user %s: %w", login, err)
	}
	for _, m := range items {
		if u := sambaUserFrom(m); u.Login == login {
			return &u, nil
		}
	}
	return nil, ErrNotFound
}

// Create adds a network drive user and returns the KAS-assigned login.
func (s *SambaService) Create(ctx context.Context, u SambaUser, password string) (string, error) {
	if u.Path == "" {
		return "", errors.New("kasapi: network drive path must not be empty")
	}
	if u.Comment == "" {
		return "", errors.New("kasapi: network drive comment must not be empty")
	}
	if password == "" {
		return "", errors.New("kasapi: network drive password must not be empty")
	}
	ret, err := s.c.Exec(ctx, "add_sambauser", map[string]any{
		"samba_path":    u.Path,
		"samba_comment": u.Comment,
		// The docs name it samba_new_password; the recorded KAS response of
		// chmmou/kasapi-cli shows samba_password. Not yet verified from here.
		"samba_password": password,
	})
	if err != nil {
		return "", fmt.Errorf("creating network drive user %q: %w", u.Comment, err)
	}
	login := createdID(ret)
	if login == "" {
		return "", fmt.Errorf("kasapi: network drive user %q created but KAS returned no login", u.Comment)
	}
	return login, nil
}

// Update replaces path and comment of u.Login.
func (s *SambaService) Update(ctx context.Context, u SambaUser) error {
	if u.Login == "" {
		return errors.New("kasapi: network drive login must not be empty")
	}
	if u.Path == "" || u.Comment == "" {
		return errors.New("kasapi: network drive path and comment must not be empty")
	}
	err := s.c.update(ctx, "update_sambauser", map[string]any{
		"samba_login":   u.Login,
		"samba_path":    u.Path,
		"samba_comment": u.Comment,
	})
	return wrapHostErr("updating network drive user", u.Login, err)
}

// UpdatePassword changes the password of a network drive user.
func (s *SambaService) UpdatePassword(ctx context.Context, login, newPassword string) error {
	if login == "" {
		return errors.New("kasapi: network drive login must not be empty")
	}
	if newPassword == "" {
		return errors.New("kasapi: new password must not be empty")
	}
	err := s.c.update(ctx, "update_sambauser", map[string]any{
		"samba_login":        login,
		"samba_new_password": newPassword,
	})
	return wrapHostErr("updating password of network drive user", login, err)
}

// Delete removes a network drive user.
func (s *SambaService) Delete(ctx context.Context, login string) error {
	if login == "" {
		return errors.New("kasapi: network drive login must not be empty")
	}
	err := s.c.remove(ctx, "delete_sambauser", map[string]any{"samba_login": login})
	return wrapHostErr("deleting network drive user", login, err)
}
