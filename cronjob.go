// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// CronjobService wraps the KAS cronjob actions (get/add/update/delete_cronjob).
type CronjobService struct {
	c *Client
}

// Cronjob requests a URL on a schedule. Empty schedule fields are sent as "*".
// Active is sent as given; the zero value is an inactive job.
type Cronjob struct {
	ID      string // KAS-assigned id
	Comment string // free text; KAS requires one
	// Protocol is "http" or "https"; empty means "https".
	Protocol string
	// URL without the protocol, e.g. "example.com/cron.php".
	URL string

	Minute     string
	Hour       string
	DayOfMonth string
	Month      string
	DayOfWeek  string // 0-7, Sunday is 0 or 7

	// HTTP basic auth. The password is write-only.
	HTTPUser     string
	HTTPPassword string

	// MailAddress receives the output of each run.
	MailAddress string
	// MailCondition suppresses the mail when the output contains this word.
	MailCondition string
	// MailSubject is "default" or "comment", which uses Comment as subject.
	MailSubject string

	Active bool
}

func cronjobFrom(m map[string]any) Cronjob {
	return Cronjob{
		ID:         asString(m["cronjob_id"]),
		Comment:    asString(m["cronjob_comment"]),
		Protocol:   asString(m["protocol"]),
		URL:        asString(m["http_url"]),
		Minute:     asString(m["minute"]),
		Hour:       asString(m["hour"]),
		DayOfMonth: asString(m["day_of_month"]),
		Month:      asString(m["month"]),
		DayOfWeek:  asString(m["day_of_week"]),
		HTTPUser:   asString(m["http_user"]),
		// The response field is mail_adress, the request parameter mail_address.
		MailAddress:   asString(m["mail_adress"]),
		MailCondition: asString(m["mail_condition"]),
		MailSubject:   asString(m["mail_subject"]),
		Active:        isYes(m["is_active"]),
	}
}

func (j Cronjob) validate() error {
	if strings.TrimSpace(j.URL) == "" {
		return errors.New("kasapi: cronjob URL must not be empty")
	}
	if strings.Contains(j.URL, "://") {
		return fmt.Errorf("kasapi: cronjob URL %q must not carry a protocol; set Protocol instead", j.URL)
	}
	if strings.TrimSpace(j.Comment) == "" {
		return errors.New("kasapi: cronjob comment must not be empty")
	}
	switch j.Protocol {
	case "", "http", "https":
	default:
		return fmt.Errorf("kasapi: cronjob protocol must be http or https, got %q", j.Protocol)
	}
	switch j.MailSubject {
	case "", "default", "comment":
	default:
		return fmt.Errorf("kasapi: cronjob mail subject must be default or comment, got %q", j.MailSubject)
	}
	if j.HTTPPassword != "" && j.HTTPUser == "" {
		return errors.New("kasapi: cronjob HTTP password needs an HTTP user")
	}
	if j.MailAddress != "" {
		if _, err := mail.ParseAddress(j.MailAddress); err != nil {
			return fmt.Errorf("kasapi: invalid cronjob mail address %q: %w", j.MailAddress, err)
		}
	}
	return nil
}

func orStar(field string) string {
	if strings.TrimSpace(field) == "" {
		return "*"
	}
	return field
}

// params renders the request parameters Create and Update share.
func (j Cronjob) params() map[string]any {
	protocol := j.Protocol
	if protocol == "" {
		protocol = "https"
	}
	params := map[string]any{
		"protocol":        protocol,
		"http_url":        j.URL,
		"cronjob_comment": j.Comment,
		"minute":          orStar(j.Minute),
		"hour":            orStar(j.Hour),
		"day_of_month":    orStar(j.DayOfMonth),
		"month":           orStar(j.Month),
		"day_of_week":     orStar(j.DayOfWeek),
		"is_active":       yn(j.Active),
	}
	// The user alone would clear the stored password.
	if j.HTTPUser != "" && j.HTTPPassword != "" {
		params["http_user"] = j.HTTPUser
		params["http_password"] = j.HTTPPassword
	}
	if j.MailAddress != "" {
		params["mail_address"] = j.MailAddress
	}
	if j.MailCondition != "" {
		params["mail_condition"] = j.MailCondition
	}
	if j.MailSubject != "" {
		params["mail_subject"] = j.MailSubject
	}
	return params
}

// List returns all cronjobs of the KAS account.
func (s *CronjobService) List(ctx context.Context) ([]Cronjob, error) {
	items, err := s.c.list(ctx, "get_cronjobs", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("listing cronjobs: %w", err)
	}
	jobs := make([]Cronjob, 0, len(items))
	for _, m := range items {
		jobs = append(jobs, cronjobFrom(m))
	}
	return jobs, nil
}

// Get returns the cronjob with the given id, or ErrNotFound.
func (s *CronjobService) Get(ctx context.Context, id string) (*Cronjob, error) {
	if id == "" {
		return nil, errors.New("kasapi: cronjob id must not be empty")
	}
	items, err := s.c.getOne(ctx, "get_cronjobs", map[string]any{"cronjob_id": id})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading cronjob %s: %w", id, err)
	}
	for _, m := range items {
		if job := cronjobFrom(m); job.ID == id {
			return &job, nil
		}
	}
	return nil, ErrNotFound
}

// Create adds a cronjob and returns the KAS-assigned id.
func (s *CronjobService) Create(ctx context.Context, j Cronjob) (string, error) {
	if err := j.validate(); err != nil {
		return "", err
	}
	if j.HTTPUser != "" && j.HTTPPassword == "" {
		return "", errors.New("kasapi: cronjob HTTP user needs an HTTP password")
	}
	ret, err := s.c.Exec(ctx, "add_cronjob", j.params())
	if err != nil {
		return "", fmt.Errorf("creating cronjob %q: %w", j.Comment, err)
	}
	id := createdID(ret)
	if id == "" {
		return "", fmt.Errorf("kasapi: cronjob %q created but KAS returned no id", j.Comment)
	}
	return id, nil
}

// Update replaces the settings of j.ID; basic auth is sent only with user and password.
func (s *CronjobService) Update(ctx context.Context, j Cronjob) error {
	if j.ID == "" {
		return errors.New("kasapi: cronjob id must not be empty")
	}
	if err := j.validate(); err != nil {
		return err
	}
	params := j.params()
	params["cronjob_id"] = j.ID
	return wrapHostErr("updating cronjob", j.ID, s.c.update(ctx, "update_cronjob", params))
}

// Delete removes a cronjob by id.
func (s *CronjobService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("kasapi: cronjob id must not be empty")
	}
	err := s.c.remove(ctx, "delete_cronjob", map[string]any{"cronjob_id": id})
	return wrapHostErr("deleting cronjob", id, err)
}
