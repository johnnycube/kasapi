// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// DomainService reads domains and changes their host settings; it never registers or deletes.
type DomainService struct {
	c *Client
}

// Domain is a domain hosted in the KAS account.
type Domain struct {
	Name string // e.g. "example.com"
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
	// DKIMSelector is the selector of the DKIM key KAS signs mail with.
	DKIMSelector string
	// TLS is the certificate state of the host.
	TLS HostTLS
}

func domainFrom(m map[string]any) Domain {
	return Domain{
		Name:           asString(m["domain_name"]),
		Path:           asString(m["domain_path"]),
		RedirectStatus: asInt(m["domain_redirect_status"]),
		PHPVersion:     asString(m["php_version"]),
		PHPDeprecated:  isYes(m["php_deprecated"]),
		Active:         isYes(m["is_active"]),
		InProgress:     isYes(m["in_progress"]),
		DKIMSelector:   asString(m["dkim_selector"]),
		TLS:            hostTLSFrom(m),
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

// Update changes the set host settings of an existing domain.
func (s *DomainService) Update(ctx context.Context, name string, hs HostSettings) error {
	if name == "" {
		return errors.New("kasapi: domain name must not be empty")
	}
	if hs.isZero() {
		return errors.New("kasapi: no domain setting to update")
	}
	if err := hs.validate(); err != nil {
		return err
	}
	params := map[string]any{"domain_name": name}
	hs.params(params, "domain_path")
	return wrapHostErr("updating domain", name, s.c.update(ctx, "update_domain", params))
}
