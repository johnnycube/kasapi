// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// cronjobEntry is a get_cronjobs entry as KAS sends it, password included.
func cronjobEntry(id string, extra ...string) string {
	kv := []string{
		"cronjob_id", id,
		"cronjob_comment", "hourly import",
		"shell_command", "",
		"timeout", "",
		"protocol", "https",
		"http_url", "example.com/cron.php",
		"http_user", "cron",
		"http_password", "plaintext-password",
		"minute", "59",
		"hour", "*/1",
		"day_of_month", "*",
		"month", "*",
		"day_of_week", "*",
		"mail_adress", "cronjob@example.com",
		"mail_condition", "no-mail",
		"mail_subject", "comment",
		"is_active", "Y",
	}
	return entry(append(kv, extra...)...)
}

func TestCronjobs_ListMapsAllFields(t *testing.T) {
	c, _ := newFake(t, map[string]string{"get_cronjobs": cronjobEntry("325208") + cronjobEntry("325209", "is_active", "N")})
	jobs, err := c.Cronjobs.List(context.Background())
	if err != nil || len(jobs) != 2 {
		t.Fatalf("List: %v %v", jobs, err)
	}
	want := Cronjob{
		ID: "325208", Comment: "hourly import", Protocol: "https", URL: "example.com/cron.php",
		Minute: "59", Hour: "*/1", DayOfMonth: "*", Month: "*", DayOfWeek: "*",
		HTTPUser: "cron", MailAddress: "cronjob@example.com", MailCondition: "no-mail",
		MailSubject: "comment", Active: true,
	}
	if jobs[0] != want {
		t.Fatalf("got %+v, want %+v", jobs[0], want)
	}
	if jobs[0].HTTPPassword != "" {
		t.Fatal("the HTTP password of the response must not be mapped")
	}
	if jobs[1].Active {
		t.Fatalf("second job must be inactive: %+v", jobs[1])
	}
}

func TestCronjobs_ListEmptyAndFault(t *testing.T) {
	ctx := context.Background()
	for _, answer := range []string{"", "!empty_list"} {
		c, _ := newFake(t, map[string]string{"get_cronjobs": answer})
		if jobs, err := c.Cronjobs.List(ctx); err != nil || len(jobs) != 0 {
			t.Fatalf("answer %q: %v %v", answer, jobs, err)
		}
	}
	c, _ := newFake(t, map[string]string{"get_cronjobs": "!kas_error"})
	if _, err := c.Cronjobs.List(ctx); err == nil || !strings.Contains(err.Error(), "listing cronjobs") {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestCronjobs_Get(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_cronjobs": cronjobEntry("325208")})

	job, err := c.Cronjobs.Get(ctx, "325208")
	if err != nil || job.ID != "325208" {
		t.Fatalf("Get: %+v %v", job, err)
	}
	wantParams(t, rec.last(t, "get_cronjobs"), map[string]string{"cronjob_id": "325208"})

	if _, err := c.Cronjobs.Get(ctx, "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := c.Cronjobs.Get(ctx, ""); err == nil {
		t.Fatal("Get without id must fail")
	}
	c, _ = newFake(t, map[string]string{"get_cronjobs": "!cronjob_id_not_found"})
	if _, err := c.Cronjobs.Get(ctx, "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not-found fault: expected ErrNotFound, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"get_cronjobs": "!kas_error"})
	if _, err := c.Cronjobs.Get(ctx, "325208"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "reading cronjob 325208") {
		t.Fatalf("other faults must be returned with context, got %v", err)
	}
}

func TestCronjob_Validate(t *testing.T) {
	base := Cronjob{URL: "example.com/cron.php", Comment: "job"}
	with := func(change func(*Cronjob)) Cronjob {
		j := base
		change(&j)
		return j
	}
	valid := []Cronjob{
		base,
		with(func(j *Cronjob) { j.Protocol = "http" }),
		with(func(j *Cronjob) { j.Protocol = "https"; j.MailSubject = "comment" }),
		with(func(j *Cronjob) { j.MailSubject = "default"; j.MailAddress = "ops@example.com" }),
		with(func(j *Cronjob) { j.HTTPUser = "cron"; j.HTTPPassword = "pw" }),
		// A job read with Get carries the user without the password.
		with(func(j *Cronjob) { j.HTTPUser = "cron" }),
	}
	for _, j := range valid {
		if err := j.validate(); err != nil {
			t.Errorf("%+v: %v", j, err)
		}
	}
	invalid := map[string]Cronjob{
		"no URL":                with(func(j *Cronjob) { j.URL = " " }),
		"URL with protocol":     with(func(j *Cronjob) { j.URL = "https://example.com/cron.php" }),
		"no comment":            with(func(j *Cronjob) { j.Comment = "" }),
		"bad protocol":          with(func(j *Cronjob) { j.Protocol = "ftp" }),
		"bad mail subject":      with(func(j *Cronjob) { j.MailSubject = "custom" }),
		"bad mail address":      with(func(j *Cronjob) { j.MailAddress = "nobody" }),
		"password without user": with(func(j *Cronjob) { j.HTTPPassword = "pw" }),
	}
	for name, j := range invalid {
		if err := j.validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestCronjob_Params(t *testing.T) {
	// An empty job spells out every default.
	got := Cronjob{URL: "example.com/cron.php", Comment: "job"}.params()
	want := map[string]any{
		"protocol": "https", "http_url": "example.com/cron.php", "cronjob_comment": "job",
		"minute": "*", "hour": "*", "day_of_month": "*", "month": "*", "day_of_week": "*",
		"is_active": "N",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	got = Cronjob{
		URL: "example.com/cron.php", Comment: "job", Protocol: "http",
		Minute: "*/15", Hour: "3", DayOfMonth: "1", Month: "6", DayOfWeek: "0",
		HTTPUser: "cron", HTTPPassword: "pw",
		MailAddress: "ops@example.com", MailCondition: "OK", MailSubject: "comment", Active: true,
	}.params()
	want = map[string]any{
		"protocol": "http", "http_url": "example.com/cron.php", "cronjob_comment": "job",
		"minute": "*/15", "hour": "3", "day_of_month": "1", "month": "6", "day_of_week": "0",
		"http_user": "cron", "http_password": "pw",
		"mail_address": "ops@example.com", "mail_condition": "OK", "mail_subject": "comment",
		"is_active": "Y",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	// The user alone is not sent: it would clear the stored password.
	got = Cronjob{URL: "x", Comment: "job", HTTPUser: "cron"}.params()
	if _, ok := got["http_user"]; ok {
		t.Fatalf("http_user without password must not be sent: %#v", got)
	}

	if orStar("") != "*" || orStar("  ") != "*" || orStar("5") != "5" {
		t.Fatal("orStar")
	}
}

func TestCronjobs_Create(t *testing.T) {
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"add_cronjob": "324700"})

	id, err := c.Cronjobs.Create(ctx, Cronjob{URL: "example.com/cron.php", Comment: "job", Minute: "9", Hour: "8", Active: true})
	if err != nil || id != "324700" {
		t.Fatalf("Create: %q %v", id, err)
	}
	got := rec.last(t, "add_cronjob")
	wantParams(t, got, map[string]string{
		"protocol": "https", "http_url": "example.com/cron.php", "cronjob_comment": "job",
		"minute": "9", "hour": "8", "day_of_month": "*", "is_active": "Y",
	})
	wantAbsent(t, got, "cronjob_id", "http_user", "http_password", "mail_address")

	before := rec.count("add_cronjob")
	if _, err := c.Cronjobs.Create(ctx, Cronjob{Comment: "job"}); err == nil {
		t.Error("Create without URL must fail")
	}
	if _, err := c.Cronjobs.Create(ctx, Cronjob{URL: "x", Comment: "job", HTTPUser: "cron"}); err == nil {
		t.Error("Create with an HTTP user but no password must fail")
	}
	if rec.count("add_cronjob") != before {
		t.Fatal("invalid input must not reach the API")
	}

	c, _ = newFake(t, map[string]string{"add_cronjob": "TRUE"})
	if _, err := c.Cronjobs.Create(ctx, Cronjob{URL: "x", Comment: "job"}); err == nil || !strings.Contains(err.Error(), "returned no id") {
		t.Fatalf("a create without id must fail, got %v", err)
	}
	c, _ = newFake(t, map[string]string{"add_cronjob": "!time_not_allowed"})
	if _, err := c.Cronjobs.Create(ctx, Cronjob{URL: "x", Comment: "job"}); err == nil ||
		!strings.Contains(err.Error(), `creating cronjob "job"`) {
		t.Fatalf("fault must be returned with context, got %v", err)
	}
}

func TestCronjobs_UpdateRoundTrip(t *testing.T) {
	// The stored HTTP password must survive a read-modify-write.
	ctx := context.Background()
	c, rec := newFake(t, map[string]string{"get_cronjobs": cronjobEntry("325208"), "update_cronjob": "TRUE"})

	job, err := c.Cronjobs.Get(ctx, "325208")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	job.Active = false
	if err := c.Cronjobs.Update(ctx, *job); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := rec.last(t, "update_cronjob")
	wantParams(t, got, map[string]string{
		"cronjob_id": "325208", "is_active": "N", "minute": "59", "hour": "*/1",
		"mail_address": "cronjob@example.com", "mail_subject": "comment",
	})
	wantAbsent(t, got, "http_user", "http_password")

	// New credentials are sent together.
	job.HTTPPassword = "n3w"
	if err := c.Cronjobs.Update(ctx, *job); err != nil {
		t.Fatalf("Update: %v", err)
	}
	wantParams(t, rec.last(t, "update_cronjob"), map[string]string{"http_user": "cron", "http_password": "n3w"})

	before := rec.count("update_cronjob")
	if err := c.Cronjobs.Update(ctx, Cronjob{URL: "x", Comment: "job"}); err == nil {
		t.Error("Update without id must fail")
	}
	if err := c.Cronjobs.Update(ctx, Cronjob{ID: "1", Comment: "job"}); err == nil {
		t.Error("Update without URL must fail")
	}
	if rec.count("update_cronjob") != before {
		t.Fatal("invalid input must not reach the API")
	}
}

func TestCronjobs_UpdateAndDeleteFaults(t *testing.T) {
	ctx := context.Background()
	job := Cronjob{ID: "325208", URL: "x", Comment: "job"}

	c, rec := newFake(t, map[string]string{"update_cronjob": "!nothing_to_do", "delete_cronjob": "TRUE"})
	if err := c.Cronjobs.Update(ctx, job); err != nil {
		t.Errorf("Update: nothing_to_do must be success, got %v", err)
	}
	if err := c.Cronjobs.Delete(ctx, job.ID); err != nil {
		t.Errorf("Delete: %v", err)
	}
	wantParams(t, rec.last(t, "delete_cronjob"), map[string]string{"cronjob_id": "325208"})
	if err := c.Cronjobs.Delete(ctx, ""); err == nil {
		t.Error("Delete without id must fail")
	}

	c, _ = newFake(t, map[string]string{"update_cronjob": "!cronjob_not_found", "delete_cronjob": "!cronjob_id_not_found"})
	if err := c.Cronjobs.Update(ctx, job); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update: expected ErrNotFound, got %v", err)
	}
	if err := c.Cronjobs.Delete(ctx, job.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete: expected ErrNotFound, got %v", err)
	}

	c, _ = newFake(t, map[string]string{"update_cronjob": "!minute_syntax_incorrect", "delete_cronjob": "!in_progress"})
	if err := c.Cronjobs.Update(ctx, job); err == nil || !strings.Contains(err.Error(), "updating cronjob 325208") {
		t.Errorf("Update fault: %v", err)
	}
	if err := c.Cronjobs.Delete(ctx, job.ID); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "deleting cronjob 325208") {
		t.Errorf("Delete fault: %v", err)
	}
}
