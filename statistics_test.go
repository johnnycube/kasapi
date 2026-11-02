// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/johnnycube/kasapi/kasapitest"
)

func spaceEntry(login string) string {
	return entry(
		"account_login", login, "last_calculation", "1777688517",
		"used_htdocs_space", "4843107", "used_chroot_space", "73727", "used_database_space", "153942",
		"used_mailaccount_space", "6877004", "used_webspace", "11947780", "max_webspace", "36454400",
	)
}

func TestStatistics_Space(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_space": spaceEntry("w0000001") + spaceEntry("w0000002")})
	got, err := c.Statistics.Space(ctx, true)
	if err != nil || len(got) != 2 {
		t.Fatalf("Space: %v %v", got, err)
	}
	want := AccountSpace{
		Login: "w0000001", Webspace: 11947780, MaxWebspace: 36454400, HTDocs: 4843107,
		Chroot: 73727, Databases: 153942, MailAccounts: 6877004,
		Calculated: time.Unix(1777688517, 0).UTC(),
	}
	if got[0] != want {
		t.Fatalf("got %+v\nwant %+v", got[0], want)
	}
	wantParams(t, rec.last(t, "get_space"), map[string]string{"show_subaccounts": "Y"})

	// The account alone may come as one entry instead of a list.
	single := strings.TrimSuffix(strings.TrimPrefix(spaceEntry("w0000000"), "<item>"), "</item>")
	c, rec = newFake(t, map[string]string{"get_space": single})
	got, err = c.Statistics.Space(ctx, false)
	if err != nil || len(got) != 1 || got[0].Login != "w0000000" {
		t.Fatalf("single: %+v %v", got, err)
	}
	wantAbsent(t, rec.last(t, "get_space"), "show_subaccounts", "show_details")

	c, _ = newFake(t, map[string]string{"get_space": "!empty_list"})
	if got, err := c.Statistics.Space(ctx, true); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	c, _ = newFake(t, map[string]string{"get_space": "!kas_error"})
	if _, err := c.Statistics.Space(ctx, false); err == nil || !strings.Contains(err.Error(), "reading storage") {
		t.Fatalf("fault: %v", err)
	}
}

func TestStatistics_SpaceUsage(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_space_usage": entry(
		"directory", "/example.com/", "count", "478", "bytes", "356123958",
		"last_calculation", "0", "has_sub_dirs", "Y")})
	got, err := c.Statistics.SpaceUsage(ctx, "/")
	if err != nil || len(got) != 1 {
		t.Fatalf("SpaceUsage: %v %v", got, err)
	}
	if want := (DirectoryUsage{Directory: "/example.com/", Bytes: 356123958, Count: 478, HasSubdirs: true}); got[0] != want {
		t.Fatalf("got %+v, want %+v", got[0], want)
	}
	wantParams(t, rec.last(t, "get_space_usage"), map[string]string{"directory": "/"})
	if _, err := c.Statistics.SpaceUsage(ctx, ""); err != nil {
		t.Fatalf("SpaceUsage root: %v", err)
	}
	wantAbsent(t, rec.last(t, "get_space_usage"), "directory")

	c, _ = newFake(t, map[string]string{"get_space_usage": "!directory_not_found"})
	if _, err := c.Statistics.SpaceUsage(ctx, "/x/"); err == nil || !strings.Contains(err.Error(), `reading storage of "/x/"`) {
		t.Fatalf("fault: %v", err)
	}
}

func TestStatistics_Traffic(t *testing.T) {
	ctx := context.Background()
	month := kasapitest.MapItem("account_login", "w0000001") + kasapitest.MapItem("year", "2026") +
		kasapitest.MapItem("month", "05") + kasapitest.MapItem("http_traffic", "4104052") +
		kasapitest.MapItem("ftp_traffic", "") + kasapitest.MapItem("http_hits", "216") +
		kasapitest.MapItem("ftp_hits", "") + kasapitest.MapItem("comment", "summary")
	day := month + kasapitest.MapItem("day", "01")
	c, rec := newFake(t, map[string]string{"get_traffic": kasapitest.MapItem("01", day) + kasapitest.MapItem("0", month)})
	got, err := c.Statistics.Traffic(ctx, 2026, 5)
	if err != nil {
		t.Fatalf("Traffic: %v", err)
	}
	want := []Traffic{
		{Login: "w0000001", Year: 2026, Month: 5, HTTPBytes: 4104052, HTTPHits: 216},
		{Login: "w0000001", Year: 2026, Month: 5, Day: 1, HTTPBytes: 4104052, HTTPHits: 216},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	wantParams(t, rec.last(t, "get_traffic"), map[string]string{"year": "2026", "month": "5"})

	c, rec = newFake(t, map[string]string{"get_traffic": entry("account_login", "w0000001", "year", "2026", "month", "11")})
	if got, err := c.Statistics.Traffic(ctx, 0, 0); err != nil || len(got) != 1 || got[0].Month != 11 {
		t.Fatalf("list response: %+v %v", got, err)
	}
	wantAbsent(t, rec.last(t, "get_traffic"), "year", "month")

	for _, p := range [][2]int{{-1, 1}, {2026, -1}, {2026, 13}} {
		if _, err := c.Statistics.Traffic(ctx, p[0], p[1]); err == nil {
			t.Errorf("Traffic%v must fail", p)
		}
	}
	c, _ = newFake(t, map[string]string{"get_traffic": ""})
	if got, err := c.Statistics.Traffic(ctx, 0, 0); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	c, _ = newFake(t, map[string]string{"get_traffic": "!kas_error"})
	if _, err := c.Statistics.Traffic(ctx, 0, 0); err == nil || !strings.Contains(err.Error(), "reading traffic") {
		t.Fatalf("fault: %v", err)
	}
}

func TestEntriesOf(t *testing.T) {
	if got := entriesOf("TRUE"); got != nil {
		t.Errorf("scalar: %v", got)
	}
	if got := entriesOf(map[string]any{}); got != nil {
		t.Errorf("empty map: %v", got)
	}
	if got := unixTime("-5"); !got.IsZero() {
		t.Errorf("negative timestamp: %v", got)
	}
}
