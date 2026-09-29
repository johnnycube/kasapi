// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
)

// FTPService wraps the KAS FTP user actions (get/add/update/delete_ftpuser).
type FTPService struct {
	c *Client
}

// FTPUser is an additional FTP login. Permissions are sent as given; the zero
// value grants nothing. Passwords are not mapped.
type FTPUser struct {
	Login   string // KAS-assigned login, e.g. "f0123456"
	Path    string // directory the login is confined to; "" means "/"
	Comment string // free text; KAS requires one on create

	Read  bool // may download files
	Write bool // may upload, change and delete files
	List  bool // may list directories

	// VirusScan runs uploads through ClamAV.
	VirusScan bool
	// MainUser marks the account's own FTP login, which cannot be deleted.
	MainUser bool
	// InProgress reports whether KAS is still applying a change.
	InProgress bool
}

func ftpUserFrom(m map[string]any) FTPUser {
	return FTPUser{
		Login:      asString(m["ftp_login"]),
		Path:       asString(m["ftp_path"]),
		Comment:    asString(m["ftp_comment"]),
		Read:       isYes(m["ftp_permission_read"]),
		Write:      isYes(m["ftp_permission_write"]),
		List:       isYes(m["ftp_permission_list"]),
		VirusScan:  isYes(m["ftp_virus_clamav"]),
		MainUser:   isYes(m["ftp_is_main_user"]),
		InProgress: isYes(m["in_progress"]),
	}
}

// settings renders the fields Create and Update share.
func (u FTPUser) settings() map[string]any {
	params := map[string]any{
		"ftp_comment":          u.Comment,
		"ftp_permission_read":  yn(u.Read),
		"ftp_permission_write": yn(u.Write),
		"ftp_permission_list":  yn(u.List),
		"ftp_virus_clamav":     yn(u.VirusScan),
	}
	if u.Path != "" {
		params["ftp_path"] = u.Path
	}
	return params
}

// List returns all FTP users of the KAS account, the main login included.
func (s *FTPService) List(ctx context.Context) ([]FTPUser, error) {
	items, err := s.c.list(ctx, "get_ftpusers", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing FTP users: %w", err)
	}
	users := make([]FTPUser, 0, len(items))
	for _, m := range items {
		users = append(users, ftpUserFrom(m))
	}
	return users, nil
}

// Get returns the FTP user with the given login, or ErrNotFound.
func (s *FTPService) Get(ctx context.Context, login string) (*FTPUser, error) {
	if login == "" {
		return nil, errors.New("kasapi: FTP login must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_ftpusers", map[string]any{"ftp_login": login})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading FTP user %s: %w", login, err)
	}
	for _, m := range items {
		if u := ftpUserFrom(m); u.Login == login {
			return &u, nil
		}
	}
	return nil, ErrNotFound
}

// Create adds an FTP user and returns the KAS-assigned login.
func (s *FTPService) Create(ctx context.Context, u FTPUser, password string) (string, error) {
	if password == "" {
		return "", errors.New("kasapi: FTP password must not be empty")
	}
	if u.Comment == "" {
		return "", errors.New("kasapi: FTP comment must not be empty")
	}
	params := u.settings()
	params["ftp_password"] = password
	ret, err := s.c.Exec(ctx, "add_ftpuser", params)
	if err != nil {
		return "", fmt.Errorf("creating FTP user %q: %w", u.Comment, err)
	}
	login := createdID(ret)
	if login == "" {
		return "", fmt.Errorf("kasapi: FTP user %q created but KAS returned no login", u.Comment)
	}
	return login, nil
}

// Update replaces path, comment, permissions and virus scanning of u.Login.
func (s *FTPService) Update(ctx context.Context, u FTPUser) error {
	if u.Login == "" {
		return errors.New("kasapi: FTP login must not be empty")
	}
	params := u.settings()
	params["ftp_login"] = u.Login
	return wrapHostErr("updating FTP user", u.Login, s.c.update(ctx, "update_ftpuser", params))
}

// UpdatePassword changes the password of an FTP user.
func (s *FTPService) UpdatePassword(ctx context.Context, login, newPassword string) error {
	if login == "" {
		return errors.New("kasapi: FTP login must not be empty")
	}
	if newPassword == "" {
		return errors.New("kasapi: new password must not be empty")
	}
	err := s.c.update(ctx, "update_ftpuser", map[string]any{
		"ftp_login":        login,
		"ftp_new_password": newPassword,
	})
	return wrapHostErr("updating password of FTP user", login, err)
}

// Delete removes an FTP user. KAS refuses the account's main login.
func (s *FTPService) Delete(ctx context.Context, login string) error {
	if login == "" {
		return errors.New("kasapi: FTP login must not be empty")
	}
	err := s.c.remove(ctx, "delete_ftpuser", map[string]any{"ftp_login": login})
	return wrapHostErr("deleting FTP user", login, err)
}
