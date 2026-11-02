// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// DirectoryProtectionService wraps the KAS directory protection actions
// (get/add/update/delete_directoryprotection): HTTP basic auth on a directory.
type DirectoryProtectionService struct {
	c *Client
}

// DirectoryProtection is one login of a protected directory. Path and User
// together identify it. The password is not mapped.
type DirectoryProtection struct {
	Path string // protected directory, e.g. "/example.com/admin/"
	User string // login name

	// AuthName is the realm the login prompt shows; the KAS docs call it the comment.
	AuthName string
	// InProgress reports whether KAS is still applying a change.
	InProgress bool
}

func directoryProtectionFrom(m map[string]any) DirectoryProtection {
	return DirectoryProtection{
		Path:       asString(m["directory_path"]),
		User:       asString(m["directory_user"]),
		AuthName:   asString(m["directory_authname"]),
		InProgress: isYes(m["in_progress"]),
	}
}

func (p DirectoryProtection) validate() error {
	if p.Path == "" || p.User == "" {
		return errors.New("kasapi: directory path and user must not be empty")
	}
	// htpasswd separates user and password with a colon.
	if strings.Contains(p.User, ":") {
		return fmt.Errorf("kasapi: directory user %q must not contain a colon", p.User)
	}
	return nil
}

// List returns the logins of all protected directories.
func (s *DirectoryProtectionService) List(ctx context.Context) ([]DirectoryProtection, error) {
	items, err := s.c.list(ctx, "get_directoryprotection", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing directory protections: %w", err)
	}
	out := make([]DirectoryProtection, 0, len(items))
	for _, m := range items {
		out = append(out, directoryProtectionFrom(m))
	}
	return out, nil
}

// Get returns the login user of the directory path, or ErrNotFound.
func (s *DirectoryProtectionService) Get(ctx context.Context, path, user string) (*DirectoryProtection, error) {
	if err := (DirectoryProtection{Path: path, User: user}).validate(); err != nil {
		return nil, err
	}
	items, err := s.c.getOne(ctx, "get_directoryprotection", map[string]any{"directory_path": path})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading directory protection %s: %w", path, err)
	}
	for _, m := range items {
		if p := directoryProtectionFrom(m); p.User == user && sameDir(p.Path, path) {
			return &p, nil
		}
	}
	return nil, ErrNotFound
}

// Create protects p.Path with the login p.User.
func (s *DirectoryProtectionService) Create(ctx context.Context, p DirectoryProtection, password string) error {
	params, err := p.params(password)
	if err != nil {
		return err
	}
	if _, err := s.c.Exec(ctx, "add_directoryprotection", params); err != nil {
		return fmt.Errorf("creating directory protection %s for %s: %w", p.Path, p.User, err)
	}
	return nil
}

// Update sets realm and password of a login. KAS documents the password as
// required on update, and it cannot be read back, so both are sent.
func (s *DirectoryProtectionService) Update(ctx context.Context, p DirectoryProtection, password string) error {
	params, err := p.params(password)
	if err != nil {
		return err
	}
	err = s.c.update(ctx, "update_directoryprotection", params)
	return wrapHostErr("updating directory protection", p.Path+" for "+p.User, err)
}

// Delete removes the login user from the directory path.
func (s *DirectoryProtectionService) Delete(ctx context.Context, path, user string) error {
	if err := (DirectoryProtection{Path: path, User: user}).validate(); err != nil {
		return err
	}
	err := s.c.remove(ctx, "delete_directoryprotection", map[string]any{
		"directory_path": path,
		"directory_user": user,
	})
	return wrapHostErr("deleting directory protection", path+" for "+user, err)
}

func (p DirectoryProtection) params(password string) (map[string]any, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("kasapi: directory password must not be empty")
	}
	if p.AuthName == "" {
		return nil, errors.New("kasapi: directory auth name must not be empty")
	}
	return map[string]any{
		"directory_path":     p.Path,
		"directory_user":     p.User,
		"directory_password": password,
		"directory_authname": p.AuthName,
	}, nil
}

// sameDir compares two directory paths, ignoring a trailing slash.
func sameDir(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}
