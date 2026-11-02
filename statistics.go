// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// StatisticsService wraps the read-only KAS statistics actions (get_space,
// get_space_usage, get_traffic).
//
// Response fields follow recorded KAS responses (chmmou/kasapi-cli) and are
// not yet verified from this repository.
type StatisticsService struct {
	c *Client
}

// AccountSpace is the storage one account uses, in kB.
type AccountSpace struct {
	Login string
	// Webspace is the total; the other fields are its parts.
	Webspace     int64
	MaxWebspace  int64
	HTDocs       int64
	Chroot       int64
	Databases    int64
	MailAccounts int64
	// Calculated is when KAS last measured the account.
	Calculated time.Time
}

// DirectoryUsage is the storage below one directory, in bytes.
type DirectoryUsage struct {
	Directory  string
	Bytes      int64
	Count      int64 // entries KAS counted below the directory
	HasSubdirs bool
	Calculated time.Time
}

// Traffic is the traffic of one account in one month, or on one day of it.
type Traffic struct {
	Login string
	Year  int
	Month int
	Day   int // 0 for the month total

	HTTPBytes int64
	HTTPHits  int64
	FTPBytes  int64
	FTPHits   int64
}

// Space returns the storage of the logged-in account, or with subaccounts
// set, that of its subaccounts.
func (s *StatisticsService) Space(ctx context.Context, subaccounts bool) ([]AccountSpace, error) {
	params := map[string]any{}
	if subaccounts {
		params["show_subaccounts"] = yn(true)
	}
	ret, err := s.c.Exec(ctx, "get_space", params)
	if err != nil && !isEmptyList(err) {
		return nil, fmt.Errorf("reading storage: %w", err)
	}
	items := entriesOf(ret)
	out := make([]AccountSpace, 0, len(items))
	for _, m := range items {
		out = append(out, AccountSpace{
			Login:        asString(m["account_login"]),
			Webspace:     asInt64(m["used_webspace"]),
			MaxWebspace:  asInt64(m["max_webspace"]),
			HTDocs:       asInt64(m["used_htdocs_space"]),
			Chroot:       asInt64(m["used_chroot_space"]),
			Databases:    asInt64(m["used_database_space"]),
			MailAccounts: asInt64(m["used_mailaccount_space"]),
			Calculated:   unixTime(m["last_calculation"]),
		})
	}
	return out, nil
}

// SpaceUsage returns the storage of the directories below dir; "" means the
// account root.
func (s *StatisticsService) SpaceUsage(ctx context.Context, dir string) ([]DirectoryUsage, error) {
	params := map[string]any{}
	if dir != "" {
		params["directory"] = dir
	}
	items, err := s.c.list(ctx, "get_space_usage", params)
	if err != nil {
		return nil, fmt.Errorf("reading storage of %q: %w", dir, err)
	}
	out := make([]DirectoryUsage, 0, len(items))
	for _, m := range items {
		out = append(out, DirectoryUsage{
			Directory:  asString(m["directory"]),
			Bytes:      asInt64(m["bytes"]),
			Count:      asInt64(m["count"]),
			HasSubdirs: isYes(m["has_sub_dirs"]),
			Calculated: unixTime(m["last_calculation"]),
		})
	}
	return out, nil
}

// Traffic returns the traffic of the given month; 0 selects the current year
// or month.
func (s *StatisticsService) Traffic(ctx context.Context, year, month int) ([]Traffic, error) {
	if year < 0 || month < 0 || month > 12 {
		return nil, fmt.Errorf("kasapi: invalid traffic period %d-%d", year, month)
	}
	params := map[string]any{}
	if year > 0 {
		params["year"] = year
	}
	if month > 0 {
		params["month"] = month
	}
	ret, err := s.c.Exec(ctx, "get_traffic", params)
	if err != nil && !isEmptyList(err) {
		return nil, fmt.Errorf("reading traffic: %w", err)
	}
	items := entriesOf(ret)
	out := make([]Traffic, 0, len(items))
	for _, m := range items {
		out = append(out, Traffic{
			Login:     asString(m["account_login"]),
			Year:      asInt(m["year"]),
			Month:     asInt(m["month"]),
			Day:       asInt(m["day"]),
			HTTPBytes: asInt64(m["http_traffic"]),
			HTTPHits:  asInt64(m["http_hits"]),
			FTPBytes:  asInt64(m["ftp_traffic"]),
			FTPHits:   asInt64(m["ftp_hits"]),
		})
	}
	return out, nil
}

// entriesOf returns the entries of a statistics response: a list, a map of
// entries keyed by index, or a single entry.
func entriesOf(ret any) []map[string]any {
	if items, ok := ret.([]any); ok {
		return listItems(items)
	}
	m, ok := ret.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if _, isEntry := v.(map[string]any); !isEntry {
			return []map[string]any{m}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k].(map[string]any))
	}
	return out
}

func asInt64(v any) int64 {
	return int64(asFloat(v))
}

// unixTime reads a Unix timestamp; 0 or a missing value is the zero time.
func unixTime(v any) time.Time {
	sec := asInt64(v)
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
