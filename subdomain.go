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
	Path string // document root path relative to the account root, e.g. "/blog/"
}

// List returns all subdomains of the KAS account.
func (s *SubdomainService) List(ctx context.Context) ([]Subdomain, error) {
	ret, err := s.c.Exec(ctx, "get_subdomains", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing subdomains: %w", err)
	}

	items, ok := ret.([]any)
	if !ok {
		return nil, nil
	}

	subs := make([]Subdomain, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		subs = append(subs, Subdomain{
			FQDN: asString(m["subdomain_name"]),
			Path: asString(m["subdomain_path"]),
		})
	}
	return subs, nil
}

// Get returns the subdomain with the given FQDN, or ErrNotFound.
func (s *SubdomainService) Get(ctx context.Context, fqdn string) (*Subdomain, error) {
	subs, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range subs {
		if strings.EqualFold(subs[i].FQDN, fqdn) {
			return &subs[i], nil
		}
	}
	return nil, ErrNotFound
}

// Create adds the subdomain name.domain with an optional document root path.
func (s *SubdomainService) Create(ctx context.Context, name, domain, path string) error {
	if name == "" || domain == "" {
		return errors.New("kasapi: subdomain name and domain must not be empty")
	}
	params := map[string]any{
		"subdomain_name": name,
		"domain_name":    domain,
	}
	if path != "" {
		params["subdomain_path"] = path
	}
	_, err := s.c.Exec(ctx, "add_subdomain", params)
	if err != nil {
		return fmt.Errorf("creating subdomain %s.%s: %w", name, domain, err)
	}
	return nil
}

// UpdatePath changes the document root path of an existing subdomain.
func (s *SubdomainService) UpdatePath(ctx context.Context, fqdn, path string) error {
	if fqdn == "" {
		return errors.New("kasapi: subdomain FQDN must not be empty")
	}
	_, err := s.c.Exec(ctx, "update_subdomain", map[string]any{
		"subdomain_name": fqdn,
		"subdomain_path": path,
	})
	if err != nil {
		return fmt.Errorf("updating subdomain %s: %w", fqdn, err)
	}
	return nil
}

// Delete removes a subdomain by its FQDN.
func (s *SubdomainService) Delete(ctx context.Context, fqdn string) error {
	if fqdn == "" {
		return errors.New("kasapi: subdomain FQDN must not be empty")
	}
	_, err := s.c.Exec(ctx, "delete_subdomain", map[string]any{
		"subdomain_name": fqdn,
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && strings.Contains(apiErr.Code, "not_found") {
			return ErrNotFound
		}
		return fmt.Errorf("deleting subdomain %s: %w", fqdn, err)
	}
	return nil
}
