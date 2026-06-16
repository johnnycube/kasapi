// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
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

// List returns all domains of the KAS account.
func (s *DomainService) List(ctx context.Context) ([]Domain, error) {
	ret, err := s.c.Exec(ctx, "get_domains", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}

	items, ok := ret.([]any)
	if !ok {
		return nil, nil
	}

	domains := make([]Domain, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		domains = append(domains, Domain{
			Name: asString(m["domain_name"]),
			Path: asString(m["domain_path"]),
		})
	}
	return domains, nil
}

// Get returns the domain with the given name, or ErrNotFound.
func (s *DomainService) Get(ctx context.Context, name string) (*Domain, error) {
	domains, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range domains {
		if strings.EqualFold(domains[i].Name, name) {
			return &domains[i], nil
		}
	}
	return nil, ErrNotFound
}
