// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// MailingListService wraps the KAS mailing list actions
// (get/add/update/delete_mailinglist). KAS runs the lists on Majordomo.
type MailingListService struct {
	c *Client
}

// MailingList is a Majordomo mailing list. The list password is not mapped.
//
// Response fields follow recorded KAS responses (chmmou/kasapi-cli) and are
// not yet verified from this repository.
type MailingList struct {
	// Name is the KAS identifier, the label and the domain joined with dashes,
	// e.g. "announce-example-com" for announce@example.com.
	Name   string
	Domain string
	Active bool

	// Subscribers, RestrictPost and Config are reported by Get only.
	Subscribers []string
	// RestrictPost lists the addresses allowed to post; empty means unrestricted.
	RestrictPost []string
	// Config is the complete Majordomo configuration file.
	Config string

	// InProgress reports whether KAS is still applying a change.
	InProgress bool
}

// MailingListUpdate is a change to a mailing list. Unset fields are not sent.
type MailingListUpdate struct {
	// Subscribers replaces the subscriber list; an empty list removes all.
	Subscribers *[]string
	// RestrictPost replaces the addresses allowed to post.
	RestrictPost *[]string
	// Config replaces the complete Majordomo configuration file.
	Config *string
	Active *bool
}

func (u MailingListUpdate) isZero() bool {
	return u.Subscribers == nil && u.RestrictPost == nil && u.Config == nil && u.Active == nil
}

func mailingListFrom(m map[string]any) MailingList {
	return MailingList{
		Name:         asString(m["mailinglist_name"]),
		Domain:       asString(m["mailinglist_domain"]),
		Active:       isYes(m["mailinglist_is_active"]),
		Subscribers:  splitLines(asString(m["mailinglist_subscriber"])),
		RestrictPost: splitLines(asString(m["mailinglist_restrict_post"])),
		Config:       asString(m["mailinglist_config"]),
		InProgress:   isYes(m["in_progress"]),
	}
}

// List returns all mailing lists without subscribers and configuration.
func (s *MailingListService) List(ctx context.Context) ([]MailingList, error) {
	items, err := s.c.list(ctx, "get_mailinglists", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing mailing lists: %w", err)
	}
	lists := make([]MailingList, 0, len(items))
	for _, m := range items {
		lists = append(lists, mailingListFrom(m))
	}
	return lists, nil
}

// Get returns the mailing list with its subscribers and configuration, or ErrNotFound.
func (s *MailingListService) Get(ctx context.Context, name string) (*MailingList, error) {
	if name == "" {
		return nil, errors.New("kasapi: mailing list name must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_mailinglists", map[string]any{"mailinglist_name": name})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading mailing list %s: %w", name, err)
	}
	for _, m := range items {
		if l := mailingListFrom(m); l.Name == name {
			return &l, nil
		}
	}
	return nil, ErrNotFound
}

// Create adds the list label@domain and returns its KAS name.
func (s *MailingListService) Create(ctx context.Context, label, domain, password string) (string, error) {
	if err := validateAddrParts(label, domain); err != nil {
		return "", err
	}
	if password == "" {
		return "", errors.New("kasapi: mailing list password must not be empty")
	}
	ret, err := s.c.Exec(ctx, "add_mailinglist", map[string]any{
		"mailinglist_name":     label,
		"mailinglist_domain":   domain,
		"mailinglist_password": password,
	})
	if err != nil {
		return "", fmt.Errorf("creating mailing list %s@%s: %w", label, domain, err)
	}
	name := createdID(ret)
	if name == "" {
		return "", fmt.Errorf("kasapi: mailing list %s@%s created but KAS returned no name", label, domain)
	}
	return name, nil
}

// Update applies the set fields of u to the list.
func (s *MailingListService) Update(ctx context.Context, name string, u MailingListUpdate) error {
	if name == "" {
		return errors.New("kasapi: mailing list name must not be empty")
	}
	if u.isZero() {
		return errors.New("kasapi: no mailing list setting to update")
	}
	params := map[string]any{"mailinglist_name": name}
	// KAS takes both address lists newline-separated.
	if u.Subscribers != nil {
		if err := validateLineList("subscriber", *u.Subscribers); err != nil {
			return err
		}
		params["subscriber"] = strings.Join(*u.Subscribers, "\n")
	}
	if u.RestrictPost != nil {
		if err := validateLineList("restrict-post address", *u.RestrictPost); err != nil {
			return err
		}
		params["restrict_post"] = strings.Join(*u.RestrictPost, "\n")
	}
	if u.Config != nil {
		params["config"] = *u.Config
	}
	if u.Active != nil {
		params["is_active"] = yn(*u.Active)
	}
	return wrapHostErr("updating mailing list", name, s.c.update(ctx, "update_mailinglist", params))
}

// Delete removes a mailing list.
func (s *MailingListService) Delete(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("kasapi: mailing list name must not be empty")
	}
	err := s.c.remove(ctx, "delete_mailinglist", map[string]any{"mailinglist_name": name})
	return wrapHostErr("deleting mailing list", name, err)
}

// validateLineList checks addresses KAS takes newline-separated.
func validateLineList(kind string, addrs []string) error {
	for _, a := range addrs {
		if strings.ContainsAny(a, "\r\n") {
			return fmt.Errorf("kasapi: %s %q must not contain a line break", kind, a)
		}
	}
	return validateAddressList(kind, addrs)
}

// splitLines splits a newline-separated KAS list and drops empty lines.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
