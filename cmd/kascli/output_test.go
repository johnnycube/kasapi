// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/johnnycube/kasapi/kasapitest"
)

func testPrinter(t *testing.T, format string, noHeaders bool) (*printer, *bytes.Buffer) {
	t.Helper()
	p, err := newPrinter(format, noHeaders)
	if err != nil {
		t.Fatalf("newPrinter(%q): %v", format, err)
	}
	buf := &bytes.Buffer{}
	p.out = buf
	return p, buf
}

func TestNewPrinter(t *testing.T) {
	for _, format := range []string{"", "table", "wide", "json", "yaml", "name"} {
		if _, err := newPrinter(format, false); err != nil {
			t.Errorf("format %q: %v", format, err)
		}
	}
	for _, format := range []string{"xml", "JSON", "csv"} {
		if _, err := newPrinter(format, false); err == nil || !strings.Contains(err.Error(), "allowed formats") {
			t.Errorf("format %q: %v", format, err)
		}
	}
}

func TestPrintList(t *testing.T) {
	rows := []row{
		{name: "thing/a", cells: []string{"a", ""}, wideCells: []string{"wide-a"}, object: map[string]any{"id": "a"}},
		{name: "thing/b", cells: []string{"b", "2"}, wideCells: []string{""}, object: map[string]any{"id": "b"}},
	}
	headers, wide := []string{"ID", "VALUE"}, []string{"EXTRA"}

	p, buf := testPrinter(t, "", false)
	if err := p.printList(headers, wide, rows); err != nil {
		t.Fatalf("table: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "ID") || strings.Contains(lines[0], "EXTRA") {
		t.Fatalf("table:\n%s", buf)
	}
	// An empty cell is shown as <none>, so columns stay aligned.
	if !strings.Contains(lines[1], "<none>") || strings.Contains(buf.String(), "wide-a") {
		t.Fatalf("table:\n%s", buf)
	}

	p, buf = testPrinter(t, "wide", false)
	_ = p.printList(headers, wide, rows)
	if !strings.Contains(buf.String(), "EXTRA") || !strings.Contains(buf.String(), "wide-a") {
		t.Fatalf("wide:\n%s", buf)
	}
	// The caller's slices must not grow.
	if len(headers) != 2 || len(rows[0].cells) != 2 {
		t.Fatal("printList modified its input")
	}

	p, buf = testPrinter(t, "wide", true)
	_ = p.printList(headers, wide, rows)
	if strings.Contains(buf.String(), "ID") || !strings.Contains(buf.String(), "wide-a") {
		t.Fatalf("wide without headers:\n%s", buf)
	}

	p, buf = testPrinter(t, "name", false)
	_ = p.printList(headers, wide, rows)
	if buf.String() != "thing/a\nthing/b\n" {
		t.Fatalf("name: %q", buf)
	}

	p, buf = testPrinter(t, "json", false)
	_ = p.printList(headers, wide, rows)
	if !strings.Contains(buf.String(), `"id": "a"`) || !strings.HasPrefix(buf.String(), "[") {
		t.Fatalf("json:\n%s", buf)
	}

	p, buf = testPrinter(t, "yaml", false)
	_ = p.printList(headers, wide, rows)
	if buf.String() != "- id: a\n- id: b\n" {
		t.Fatalf("yaml: %q", buf)
	}
}

func TestPrintList_Empty(t *testing.T) {
	p, buf := testPrinter(t, "", false)
	if err := p.printList([]string{"ID"}, nil, nil); err != nil {
		t.Fatalf("empty table: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "ID" {
		t.Fatalf("an empty table prints its header: %q", buf)
	}
	p, buf = testPrinter(t, "", true)
	_ = p.printList([]string{"ID"}, nil, nil)
	if buf.Len() != 0 {
		t.Fatalf("an empty table without headers prints nothing: %q", buf)
	}
	p, buf = testPrinter(t, "json", false)
	_ = p.printList([]string{"ID"}, nil, nil)
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Fatalf("an empty list is [] in json, not null: %q", buf)
	}
	p, buf = testPrinter(t, "name", false)
	_ = p.printList([]string{"ID"}, nil, nil)
	if buf.Len() != 0 {
		t.Fatalf("name: %q", buf)
	}
}

func TestPrintObject(t *testing.T) {
	obj := map[string]any{"k": "v"}
	for format, want := range map[string]string{
		"": "{\n  \"k\": \"v\"\n}\n", "json": "{\n  \"k\": \"v\"\n}\n",
		"table": "{\n  \"k\": \"v\"\n}\n", "yaml": "k: v\n",
	} {
		p, buf := testPrinter(t, format, false)
		if err := p.printObject(obj); err != nil || buf.String() != want {
			t.Errorf("format %q: %q %v", format, buf, err)
		}
	}
	// A value JSON cannot encode is an error, not a panic.
	p, _ := testPrinter(t, "json", false)
	if err := p.printObject(make(chan int)); err == nil {
		t.Fatal("an unencodable value must fail")
	}
}

func TestOutputHelpers(t *testing.T) {
	if boolWord(true) != "true" || boolWord(false) != "false" {
		t.Fatal("boolWord")
	}
	if got := tabLine([]string{"a", "", "c"}); got != "a\t<none>\tc" {
		t.Fatalf("tabLine: %q", got)
	}
	if got := tabLine(nil); got != "" {
		t.Fatalf("tabLine(nil): %q", got)
	}
	if got := anySlice(nil); got == nil || len(got) != 0 {
		t.Fatalf("anySlice(nil) must be an empty list, got %#v", got)
	}
	if got := anySlice([]string{"a"}); len(got) != 1 || got[0] != "a" {
		t.Fatalf("anySlice: %#v", got)
	}
	if got := objects([]row{{object: 1}, {object: "x"}}); len(got) != 2 || got[1] != "x" {
		t.Fatalf("objects: %#v", got)
	}
}

func TestCLI_ExecOutputAndErrors(t *testing.T) {
	setupCLI(t, func(action string, params map[string]any) (string, string) {
		if action == "fail" {
			return "", "zone_not_found"
		}
		return kasapitest.MapItem("zone", params["zone_host"].(string)) + kasapitest.MapItem("n", params["n"].(string)), ""
	})
	out := capture(t, "exec", "get_x", "zone_host=example.com.", "n=a=b")
	if !strings.Contains(out, `"zone": "example.com."`) || !strings.Contains(out, `"n": "a=b"`) {
		t.Fatalf("exec output: a value may contain '=':\n%s", out)
	}
	wantErr(t, "zone_not_found", "exec", "fail")
	wantErr(t, "expected key=value", "exec", "get_x", "=value")
	wantErr(t, "allowed formats", "exec", "get_x", "-o", "xml")
	wantErr(t, "allowed formats", "api-resources", "-o", "xml")
	wantErr(t, "allowed formats", "config", "get-contexts", "-o", "xml")
	wantErr(t, "allowed formats", "config", "view", "-o", "xml")
}

func TestCLI_APIResourcesTable(t *testing.T) {
	out := capture(t, "api-resources")
	for _, want := range []string{"NAME", "SHORTNAMES", "VERBS", "cronjobs", "get,create,update,delete", "tls", "<none>"} {
		if !strings.Contains(out, want) {
			t.Errorf("api-resources lacks %q:\n%s", want, out)
		}
	}
	if out := capture(t, "api-resources", "-o", "name"); !strings.Contains(out, "ddnsusers\n") {
		t.Fatalf("name output:\n%s", out)
	}
}
