// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// DNSService wraps the KAS DNS actions (get/add/update/delete_dns_settings).
type DNSService struct {
	c *Client
}

// DNSRecord is a single record in a KAS-hosted zone.
type DNSRecord struct {
	ID   string // assigned by KAS ("record_id")
	Zone string // zone host, e.g. "example.com" (trailing dot optional)
	Name string // record name relative to the zone; "" for the apex
	Type string // A, AAAA, CNAME, MX, TXT, SRV, NS, CAA, ...
	Data string // record payload
	Aux  int    // auxiliary value (MX priority, SRV weight); 0 otherwise

	// Changeable reports whether KAS allows modifying this record. System
	// records (e.g. default NS) are read-only.
	Changeable bool
	// Deletable reports whether KAS allows deleting this record.
	Deletable bool
}

func dnsRecordFrom(zone string, m map[string]any) DNSRecord {
	return DNSRecord{
		ID:         asString(m["record_id"]),
		Zone:       strings.TrimSuffix(normalizeZone(zone), "."),
		Name:       asString(m["record_name"]),
		Type:       asString(m["record_type"]),
		Data:       asString(m["record_data"]),
		Aux:        asInt(m["record_aux"]),
		Changeable: isYes(m["record_changeable"]),
		// The field name carries the API's spelling.
		Deletable: isYes(m["record_deleteable"]),
	}
}

// normalizeZone ensures the trailing dot KAS expects in zone_host.
func normalizeZone(zone string) string {
	zone = strings.TrimSpace(zone)
	if zone != "" && !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	return zone
}

// List returns all records of a zone.
func (s *DNSService) List(ctx context.Context, zone string) ([]DNSRecord, error) {
	items, err := s.c.list(ctx, "get_dns_settings", map[string]any{
		"zone_host": normalizeZone(zone),
	})
	if err != nil {
		return nil, fmt.Errorf("listing DNS records for %q: %w", zone, err)
	}
	records := make([]DNSRecord, 0, len(items))
	for _, m := range items {
		records = append(records, dnsRecordFrom(zone, m))
	}
	return records, nil
}

// Get returns a single record by id, or ErrNotFound.
func (s *DNSService) Get(ctx context.Context, zone, id string) (*DNSRecord, error) {
	if id == "" {
		return nil, errors.New("kasapi: DNS record id must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_dns_settings", map[string]any{
		"zone_host": normalizeZone(zone),
		"record_id": id,
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading DNS record %s: %w", id, err)
	}
	for _, m := range items {
		if rec := dnsRecordFrom(zone, m); rec.ID == id {
			return &rec, nil
		}
	}
	return nil, ErrNotFound
}

// Create adds a record and returns its new record id.
func (s *DNSService) Create(ctx context.Context, r DNSRecord) (string, error) {
	ret, err := s.c.Exec(ctx, "add_dns_settings", map[string]any{
		"zone_host":   normalizeZone(r.Zone),
		"record_type": strings.ToUpper(r.Type),
		"record_name": r.Name,
		"record_data": r.Data,
		"record_aux":  r.Aux,
	})
	if err != nil {
		return "", fmt.Errorf("creating DNS record %s %s.%s: %w", r.Type, r.Name, r.Zone, err)
	}

	if id := asString(ret); id != "" && id != "TRUE" {
		return id, nil // ReturnInfo carries the new record id
	}

	// Fallback: re-read the zone and match the record we just created.
	records, err := s.List(ctx, r.Zone)
	if err != nil {
		return "", fmt.Errorf("record created but id lookup failed: %w", err)
	}
	for _, rec := range records {
		if rec.Name == r.Name &&
			strings.EqualFold(rec.Type, r.Type) &&
			rec.Data == r.Data &&
			rec.Aux == r.Aux {
			return rec.ID, nil
		}
	}
	return "", fmt.Errorf("record created but not found in zone %q afterwards", r.Zone)
}

// Update modifies name, data and aux of a record. The type is immutable in the
// KAS API; recreate the record to change it.
func (s *DNSService) Update(ctx context.Context, r DNSRecord) error {
	if r.ID == "" {
		return fmt.Errorf("updating DNS record: missing record id")
	}
	_, err := s.c.Exec(ctx, "update_dns_settings", map[string]any{
		"record_id":   r.ID,
		"record_name": r.Name,
		"record_data": r.Data,
		"record_aux":  r.Aux,
	})
	if err != nil && !isNothingToDo(err) {
		return fmt.Errorf("updating DNS record %s: %w", r.ID, err)
	}
	return nil
}

// Delete removes a record by id. Deleting an already absent record returns
// ErrNotFound.
func (s *DNSService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("deleting DNS record: missing record id")
	}
	_, err := s.c.Exec(ctx, "delete_dns_settings", map[string]any{
		"record_id": id,
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && strings.Contains(apiErr.Code, "not_found") {
			return ErrNotFound
		}
		return fmt.Errorf("deleting DNS record %s: %w", id, err)
	}
	return nil
}
