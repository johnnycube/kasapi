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

// isNotFound reports whether err is a KAS fault naming a missing object.
func isNotFound(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return strings.Contains(apiErr.Code, "not_found") ||
		strings.Contains(apiErr.Code, "doesnt_exist") ||
		strings.Contains(apiErr.Code, "doenst_exist")
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
