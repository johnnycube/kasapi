// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"strings"
)

// yn renders a bool as the Y/N flag KAS expects in request parameters.
func yn(b bool) string {
	if b {
		return "Y"
	}
	return "N"
}

// isYes reads a KAS flag: Y/N, TRUE/FALSE or the German j/n.
func isYes(v any) bool {
	switch strings.ToUpper(strings.TrimSpace(asString(v))) {
	case "Y", "J", "TRUE", "1":
		return true
	}
	return false
}

// listItems returns the entries of a get_* response.
func listItems(ret any) []map[string]any {
	items, ok := ret.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// notFoundCodes are the KAS faults that report the addressed object as
// absent, from the KAS docs and recorded responses. Faults about a missing
// prerequisite (kas_login_not_found, email_domain_doesnt_exist,
// filter_doesnt_exist, ...) are deliberately not here: the object may well
// exist, and a consumer that drops state on ErrNotFound must not be misled.
var notFoundCodes = map[string]bool{
	"record_id_not_found": true, "zone_not_found": true,
	"domain_not_found_in_kas":    true,
	"subdomain_not_found_in_kas": true, "subdomain_not_found": true,
	// KAS sends both spellings.
	"subdomain_doesnt_exist": true, "subdomain_doenst_exist": true,
	"mail_login_not_found": true, "mailaccount_not_found": true,
	// The standard filter actions name the mail login this way.
	"login_not_found":        true,
	"mail_forward_not_found": true, "mail_forward_not_found_in_kas": true,
	"ftp_login_not_found":      true,
	"database_login_not_found": true,
	"cronjob_not_found":        true, "cronjob_id_not_found": true,
	"dyndns_login_not_found":  true,
	"mailinglist_not_found":   true,
	"samba_login_not_found":   true,
	"account_login_not_found": true,
}

// isNotFound reports whether err is a KAS fault naming a missing object.
func isNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && notFoundCodes[apiErr.Code]
}

// isEmptyList reports whether err is the "empty_list" fault.
func isEmptyList(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == "empty_list"
}

// isNothingToDo reports whether err is the "nothing_to_do" fault.
func isNothingToDo(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == "nothing_to_do"
}

// list runs a get_* action; "empty_list" is an empty result.
func (c *Client) list(ctx context.Context, action string, params map[string]any) ([]map[string]any, error) {
	ret, err := c.Exec(ctx, action, params)
	if err != nil {
		if isEmptyList(err) {
			return nil, nil
		}
		return nil, err
	}
	return listItems(ret), nil
}

// getOne runs a filtered get_* action; a missing object is ErrNotFound.
func (c *Client) getOne(ctx context.Context, action string, params map[string]any) ([]map[string]any, error) {
	ret, err := c.Exec(ctx, action, params)
	if err != nil {
		if isNotFound(err) || isEmptyList(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	items := listItems(ret)
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	return items, nil
}

// update runs an update_* action; "nothing_to_do" is success.
func (c *Client) update(ctx context.Context, action string, params map[string]any) error {
	_, err := c.Exec(ctx, action, params)
	switch {
	case err == nil, isNothingToDo(err):
		return nil
	case isNotFound(err):
		return ErrNotFound
	}
	return err
}

// remove runs a delete_* action; a missing object is ErrNotFound.
func (c *Client) remove(ctx context.Context, action string, params map[string]any) error {
	_, err := c.Exec(ctx, action, params)
	if err != nil && isNotFound(err) {
		return ErrNotFound
	}
	return err
}

// createdID returns the identifier an add_* action reports, or "".
func createdID(ret any) string {
	id := strings.TrimSpace(asString(ret))
	if _, isScalar := ret.(string); !isScalar || id == "" || strings.EqualFold(id, "TRUE") {
		return ""
	}
	return id
}

// joinList renders a string list as the comma-separated parameter KAS expects.
func joinList(items []string) string {
	return strings.Join(items, ",")
}

// splitList splits a "," or ";" separated KAS list and drops empty entries.
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
