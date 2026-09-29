// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// SubdomainService wraps the KAS subdomain actions (get/add/update/delete_subdomain).
// As with mail, verify the parameter names against the KAS panel docs before
// relying on them.
type SubdomainService struct {
	c *Client
}

// Subdomain is a subdomain configured in the KAS account. Its identity is the
// full FQDN (e.g. "blog.example.com").
type Subdomain struct {
	FQDN string // full host name
	// Path is the document root, or the redirect target with a RedirectStatus.
	Path string
	// RedirectStatus is 0 (no redirect), 301, 302 or 307.
	RedirectStatus int
	// PHPVersion is the PHP version the host runs, e.g. "8.4".
	PHPVersion string
	// PHPDeprecated reports whether KAS flags that PHP version as deprecated.
	PHPDeprecated bool
	// Active reports whether the host is served.
	Active bool
	// InProgress reports whether KAS is still applying a change.
	InProgress bool
	// TLS is the certificate state of the host.
	TLS HostTLS
}

func subdomainFrom(m map[string]any) Subdomain {
	return Subdomain{
		FQDN:           asString(m["subdomain_name"]),
		Path:           asString(m["subdomain_path"]),
		RedirectStatus: asInt(m["subdomain_redirect_status"]),
		PHPVersion:     asString(m["php_version"]),
		PHPDeprecated:  isYes(m["php_deprecated"]),
		Active:         isYes(m["is_active"]),
		InProgress:     isYes(m["in_progress"]),
		TLS:            hostTLSFrom(m),
	}
}

// List returns all subdomains of the KAS account.
func (s *SubdomainService) List(ctx context.Context) ([]Subdomain, error) {
	items, err := s.c.list(ctx, "get_subdomains", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing subdomains: %w", err)
	}
	subs := make([]Subdomain, 0, len(items))
	for _, m := range items {
		subs = append(subs, subdomainFrom(m))
	}
	return subs, nil
}

// Get returns the subdomain with the given FQDN, or ErrNotFound.
func (s *SubdomainService) Get(ctx context.Context, fqdn string) (*Subdomain, error) {
	if fqdn == "" {
		return nil, errors.New("kasapi: subdomain FQDN must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_subdomains", map[string]any{"subdomain_name": fqdn})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading subdomain %s: %w", fqdn, err)
	}
	for _, m := range items {
		if sub := subdomainFrom(m); strings.EqualFold(sub.FQDN, fqdn) {
			return &sub, nil
		}
	}
	return nil, ErrNotFound
}

// Create adds the subdomain name.domain with an optional document root path.
func (s *SubdomainService) Create(ctx context.Context, name, domain, path string) error {
	return s.CreateWithSettings(ctx, name, domain, HostSettings{Path: path})
}

// CreateWithSettings adds the subdomain name.domain. KAS rejects Active on create.
func (s *SubdomainService) CreateWithSettings(ctx context.Context, name, domain string, hs HostSettings) error {
	if name == "" || domain == "" {
		return errors.New("kasapi: subdomain name and domain must not be empty")
	}
	if hs.Active != nil {
		return errors.New("kasapi: add_subdomain does not accept the active flag; create the subdomain, then update it")
	}
	if err := hs.validate(); err != nil {
		return err
	}
	params := map[string]any{
		"subdomain_name": name,
		"domain_name":    domain,
	}
	hs.params(params, "subdomain_path")
	if _, err := s.c.Exec(ctx, "add_subdomain", params); err != nil {
		return fmt.Errorf("creating subdomain %s.%s: %w", name, domain, err)
	}
	return nil
}

// UpdatePath changes the document root path of an existing subdomain.
func (s *SubdomainService) UpdatePath(ctx context.Context, fqdn, path string) error {
	if fqdn == "" {
		return errors.New("kasapi: subdomain FQDN must not be empty")
	}
	// An empty path is sent as is; Update would skip it as unset.
	err := s.c.update(ctx, "update_subdomain", map[string]any{
		"subdomain_name": fqdn,
		"subdomain_path": path,
	})
	return wrapHostErr("updating subdomain", fqdn, err)
}

// Update changes the set fields of an existing subdomain.
func (s *SubdomainService) Update(ctx context.Context, fqdn string, hs HostSettings) error {
	if fqdn == "" {
		return errors.New("kasapi: subdomain FQDN must not be empty")
	}
	if hs.isZero() {
		return errors.New("kasapi: no subdomain setting to update")
	}
	if err := hs.validate(); err != nil {
		return err
	}
	params := map[string]any{"subdomain_name": fqdn}
	hs.params(params, "subdomain_path")
	return wrapHostErr("updating subdomain", fqdn, s.c.update(ctx, "update_subdomain", params))
}

// Delete removes a subdomain by its FQDN.
func (s *SubdomainService) Delete(ctx context.Context, fqdn string) error {
	if fqdn == "" {
		return errors.New("kasapi: subdomain FQDN must not be empty")
	}
	err := s.c.remove(ctx, "delete_subdomain", map[string]any{"subdomain_name": fqdn})
	return wrapHostErr("deleting subdomain", fqdn, err)
}

// wrapHostErr adds context to an error and keeps ErrNotFound matchable.
func wrapHostErr(what, name string, err error) error {
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("%s %s: %w", what, name, err)
}
