// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// DatabaseService wraps the KAS database actions (get/add/update/delete_database).
type DatabaseService struct {
	c *Client
}

// Database is a MySQL database; KAS assigns its name and login. Passwords are not mapped.
type Database struct {
	Name    string // database name, e.g. "d0123456"
	Login   string // database user; KAS uses the database name
	Comment string // free text; KAS requires one on create
	// AllowedHosts may connect from outside: IP addresses or CIDR networks.
	AllowedHosts []string
	// UsedSpace as KAS reports it (used_database_space).
	UsedSpace int
	// InProgress reports whether KAS is still applying a change.
	InProgress bool
}

func databaseFrom(m map[string]any) Database {
	return Database{
		Name:         asString(m["database_name"]),
		Login:        asString(m["database_login"]),
		Comment:      asString(m["database_comment"]),
		AllowedHosts: splitList(asString(m["database_allowed_hosts"])),
		UsedSpace:    asInt(m["used_database_space"]),
		InProgress:   isYes(m["in_progress"]),
	}
}

// List returns all databases of the KAS account.
func (s *DatabaseService) List(ctx context.Context) ([]Database, error) {
	items, err := s.c.list(ctx, "get_databases", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing databases: %w", err)
	}
	dbs := make([]Database, 0, len(items))
	for _, m := range items {
		dbs = append(dbs, databaseFrom(m))
	}
	return dbs, nil
}

// Get returns the database with the given login, or ErrNotFound.
func (s *DatabaseService) Get(ctx context.Context, login string) (*Database, error) {
	if login == "" {
		return nil, errors.New("kasapi: database login must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_databases", map[string]any{"database_login": login})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading database %s: %w", login, err)
	}
	for _, m := range items {
		if db := databaseFrom(m); db.Login == login {
			return &db, nil
		}
	}
	return nil, ErrNotFound
}

// Create adds a database from d.Comment and d.AllowedHosts and returns its login.
func (s *DatabaseService) Create(ctx context.Context, d Database, password string) (string, error) {
	if password == "" {
		return "", errors.New("kasapi: database password must not be empty")
	}
	if d.Comment == "" {
		return "", errors.New("kasapi: database comment must not be empty")
	}
	params := map[string]any{
		"database_password": password,
		"database_comment":  d.Comment,
	}
	if len(d.AllowedHosts) > 0 {
		params["database_allowed_hosts"] = joinList(d.AllowedHosts)
	}
	ret, err := s.c.Exec(ctx, "add_database", params)
	if err != nil {
		return "", fmt.Errorf("creating database %q: %w", d.Comment, err)
	}
	login := createdID(ret)
	if login == "" {
		return "", fmt.Errorf("kasapi: database %q created but KAS returned no login", d.Comment)
	}
	return login, nil
}

// Update replaces comment and allowed hosts; an empty list closes external access.
func (s *DatabaseService) Update(ctx context.Context, d Database) error {
	if d.Login == "" {
		return errors.New("kasapi: database login must not be empty")
	}
	if strings.TrimSpace(d.Comment) == "" {
		return errors.New("kasapi: database comment must not be empty")
	}
	err := s.c.update(ctx, "update_database", map[string]any{
		"database_login":         d.Login,
		"database_comment":       d.Comment,
		"database_allowed_hosts": joinList(d.AllowedHosts),
	})
	return wrapHostErr("updating database", d.Login, err)
}

// UpdatePassword changes the password of a database user.
func (s *DatabaseService) UpdatePassword(ctx context.Context, login, newPassword string) error {
	if login == "" {
		return errors.New("kasapi: database login must not be empty")
	}
	if newPassword == "" {
		return errors.New("kasapi: new password must not be empty")
	}
	err := s.c.update(ctx, "update_database", map[string]any{
		"database_login":        login,
		"database_new_password": newPassword,
	})
	return wrapHostErr("updating password of database", login, err)
}

// Delete removes a database and all its data.
func (s *DatabaseService) Delete(ctx context.Context, login string) error {
	if login == "" {
		return errors.New("kasapi: database login must not be empty")
	}
	err := s.c.remove(ctx, "delete_database", map[string]any{"database_login": login})
	return wrapHostErr("deleting database", login, err)
}
