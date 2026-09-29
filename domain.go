// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// DomainService wraps the KAS domain actions. Read-only by design: the
// add/update/delete_domain actions touch registration and routing and are left
// to Client.Exec. Use it directly if you need them.
type DomainService struct {
	c *Client
}

// Domain is a domain hosted in the KAS account.
type Domain struct {
	Name string // e.g. "example.com"
	Path string // document root path relative to the account root
}

func domainFrom(m map[string]any) Domain {
	return Domain{
		Name: asString(m["domain_name"]),
		Path: asString(m["domain_path"]),
	}
}

// List returns all domains of the KAS account.
func (s *DomainService) List(ctx context.Context) ([]Domain, error) {
	items, err := s.c.list(ctx, "get_domains", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	domains := make([]Domain, 0, len(items))
	for _, m := range items {
		domains = append(domains, domainFrom(m))
	}
	return domains, nil
}

// Get returns the domain with the given name, or ErrNotFound.
func (s *DomainService) Get(ctx context.Context, name string) (*Domain, error) {
	if name == "" {
		return nil, errors.New("kasapi: domain name must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_domains", map[string]any{"domain_name": name})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading domain %s: %w", name, err)
	}
	for _, m := range items {
		if d := domainFrom(m); strings.EqualFold(d.Name, name) {
			return &d, nil
		}
	}
	return nil, ErrNotFound
}
