// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestYN(t *testing.T) {
	if yn(true) != "Y" || yn(false) != "N" {
		t.Fatalf("yn: %q %q", yn(true), yn(false))
	}
}

func TestIsYes(t *testing.T) {
	for _, v := range []any{"Y", "y", "j", "J", "TRUE", "true", " Y ", "1", 1, 1.0} {
		if !isYes(v) {
			t.Errorf("isYes(%#v) = false, want true", v)
		}
	}
	for _, v := range []any{"N", "n", "FALSE", "", "0", "forbidden", nil, 0} {
		if isYes(v) {
			t.Errorf("isYes(%#v) = true, want false", v)
		}
	}
}

func TestListItems(t *testing.T) {
	if got := listItems("TRUE"); got != nil {
		t.Fatalf("scalar must yield no items, got %v", got)
	}
	if got := listItems(nil); got != nil {
		t.Fatalf("nil must yield no items, got %v", got)
	}
	got := listItems([]any{map[string]any{"a": "1"}, "stray", map[string]any{"a": "2"}})
	if len(got) != 2 || got[0]["a"] != "1" || got[1]["a"] != "2" {
		t.Fatalf("non-map entries must be skipped, got %v", got)
	}
}

func TestFaultClassification(t *testing.T) {
	notFound := []string{"zone_not_found", "cronjob_id_not_found", "email_domain_doesnt_exist", "subdomain_doenst_exist"}
	for _, code := range notFound {
		if !isNotFound(&APIError{Code: code}) {
			t.Errorf("isNotFound(%s) = false", code)
		}
	}
	for _, err := range []error{&APIError{Code: "flood_protection"}, errors.New("zone_not_found"), nil} {
		if isNotFound(err) {
			t.Errorf("isNotFound(%v) = true", err)
		}
	}

	if !isEmptyList(&APIError{Code: "empty_list"}) || isEmptyList(&APIError{Code: "nothing_to_do"}) || isEmptyList(nil) {
		t.Error("isEmptyList misclassifies")
	}
	if !isNothingToDo(&APIError{Code: "nothing_to_do"}) || isNothingToDo(&APIError{Code: "empty_list"}) || isNothingToDo(nil) {
		t.Error("isNothingToDo misclassifies")
	}

	// Wrapped faults stay recognizable.
	wrapped := errors.Join(errors.New("context"), &APIError{Code: "empty_list"})
	if !isEmptyList(wrapped) {
		t.Error("wrapped fault not recognized")
	}
}

func TestCreatedID(t *testing.T) {
	for in, want := range map[string]string{
		"f0000004": "f0000004", " 324700 ": "324700", "TRUE": "", "true": "", "": "",
	} {
		if got := createdID(in); got != want {
			t.Errorf("createdID(%q) = %q, want %q", in, got, want)
		}
	}
	if got := createdID(map[string]any{"a": "b"}); got != "" {
		t.Errorf("a non-scalar must yield no id, got %q", got)
	}
	if got := createdID(nil); got != "" {
		t.Errorf("nil must yield no id, got %q", got)
	}
}

func TestJoinAndSplitList(t *testing.T) {
	if got := joinList([]string{"a", "b"}); got != "a,b" {
		t.Fatalf("joinList: %q", got)
	}
	if got := joinList(nil); got != "" {
		t.Fatalf("joinList(nil): %q", got)
	}
	for in, want := range map[string][]string{
		"":             nil,
		"a":            {"a"},
		"a,b":          {"a", "b"},
		"a;b":          {"a", "b"},
		"sf,ef,pdw,":   {"sf", "ef", "pdw"},
		" a , ,b ;; c": {"a", "b", "c"},
	} {
		if got := splitList(in); !reflect.DeepEqual(got, want) {
			t.Errorf("splitList(%q) = %#v, want %#v", in, got, want)
		}
	}
}

func TestClientList(t *testing.T) {
	ctx := context.Background()

	c, _ := newFake(t, map[string]string{"get_x": entry("k", "v") + entry("k", "w")})
	items, err := c.list(ctx, "get_x", nil)
	if err != nil || len(items) != 2 || items[1]["k"] != "w" {
		t.Fatalf("list: %v %v", items, err)
	}

	c, _ = newFake(t, map[string]string{"get_x": "!empty_list"})
	items, err = c.list(ctx, "get_x", nil)
	if err != nil || items != nil {
		t.Fatalf("empty_list must be an empty result, got %v %v", items, err)
	}

	c, _ = newFake(t, map[string]string{"get_x": "!kas_error"})
	if _, err = c.list(ctx, "get_x", nil); err == nil {
		t.Fatal("other faults must be returned")
	}
}

func TestClientGetOne(t *testing.T) {
	ctx := context.Background()

	c, rec := newFake(t, map[string]string{"get_x": entry("k", "v")})
	items, err := c.getOne(ctx, "get_x", map[string]any{"id": "7"})
	if err != nil || len(items) != 1 {
		t.Fatalf("getOne: %v %v", items, err)
	}
	wantParams(t, rec.last(t, "get_x"), map[string]string{"id": "7"})

	for name, answer := range map[string]string{
		"not found fault": "!x_not_found",
		"empty_list":      "!empty_list",
		"empty array":     "",
		"scalar":          "TRUE",
	} {
		c, _ = newFake(t, map[string]string{"get_x": answer})
		if _, err := c.getOne(ctx, "get_x", nil); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: expected ErrNotFound, got %v", name, err)
		}
	}

	c, _ = newFake(t, map[string]string{"get_x": "!kas_error"})
	if _, err := c.getOne(ctx, "get_x", nil); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("other faults must be returned as they are, got %v", err)
	}
}

func TestClientUpdateAndRemove(t *testing.T) {
	ctx := context.Background()

	for answer, want := range map[string]error{
		"TRUE":           nil,
		"!nothing_to_do": nil,
		"!x_not_found":   ErrNotFound,
	} {
		c, _ := newFake(t, map[string]string{"update_x": answer})
		if err := c.update(ctx, "update_x", nil); !errors.Is(err, want) {
			t.Errorf("update with %s: got %v, want %v", answer, err, want)
		}
	}
	c, _ := newFake(t, map[string]string{"update_x": "!in_progress"})
	var apiErr *APIError
	if err := c.update(ctx, "update_x", nil); !errors.As(err, &apiErr) || apiErr.Code != "in_progress" {
		t.Fatalf("update must return other faults, got %v", err)
	}

	for answer, want := range map[string]error{
		"TRUE":         nil,
		"!x_not_found": ErrNotFound,
	} {
		c, _ := newFake(t, map[string]string{"delete_x": answer})
		if err := c.remove(ctx, "delete_x", nil); !errors.Is(err, want) {
			t.Errorf("remove with %s: got %v, want %v", answer, err, want)
		}
	}
	// A delete that changes nothing is not a success: the object is there.
	c, _ = newFake(t, map[string]string{"delete_x": "!nothing_to_do"})
	if err := c.remove(ctx, "delete_x", nil); err == nil {
		t.Fatal("remove must return nothing_to_do")
	}
}
