// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// TLSService installs certificates and sets HTTPS redirect and HSTS (update_ssl).
// The API cannot request a Let's Encrypt certificate; that is a KAS panel feature.
type TLSService struct {
	c *Client
}

// TLSUpdate is a change to the TLS setup of a host. Unset fields are not sent.
type TLSUpdate struct {
	// Certificate and Key are PEM-encoded. Set both or neither.
	Certificate string
	Key         string
	// Bundle holds the PEM-encoded intermediate certificates.
	Bundle string
	// CSR is the PEM-encoded signing request.
	CSR string
	// Active enables or disables the certificate.
	Active *bool
	// ForceHTTPS redirects HTTP requests to HTTPS with a 301.
	ForceHTTPS *bool
	// HSTSMaxAge in seconds; -1 turns HSTS off.
	HSTSMaxAge *int
}

// validate checks certificate and key before the key leaves the process.
func (u TLSUpdate) validate(hostname string) error {
	if (u.Certificate == "") != (u.Key == "") {
		return errors.New("kasapi: certificate and key must be set together")
	}
	if u.Certificate == "" && u.Bundle == "" && u.CSR == "" &&
		u.Active == nil && u.ForceHTTPS == nil && u.HSTSMaxAge == nil {
		return errors.New("kasapi: no TLS setting to update")
	}
	if u.HSTSMaxAge != nil && *u.HSTSMaxAge < -1 {
		return fmt.Errorf("kasapi: HSTS max-age must be -1 or a number of seconds, got %d", *u.HSTSMaxAge)
	}
	if u.Certificate != "" {
		pair, err := tls.X509KeyPair([]byte(u.Certificate), []byte(u.Key))
		if err != nil {
			return fmt.Errorf("kasapi: certificate and key do not form a pair: %w", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return fmt.Errorf("kasapi: parsing certificate: %w", err)
		}
		if err := leaf.VerifyHostname(hostname); err != nil {
			return fmt.Errorf("kasapi: certificate does not cover %s: %w", hostname, err)
		}
	}
	if u.Bundle != "" {
		if err := validateCertificates(u.Bundle); err != nil {
			return fmt.Errorf("kasapi: bundle: %w", err)
		}
	}
	return nil
}

// validateCertificates checks that pemData holds only parsable certificates.
func validateCertificates(pemData string) error {
	rest := []byte(pemData)
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return errors.New("no PEM certificate found")
	}
	return nil
}

// Update applies u to the domain or subdomain hostname.
func (s *TLSService) Update(ctx context.Context, hostname string, u TLSUpdate) error {
	if hostname == "" {
		return errors.New("kasapi: hostname must not be empty")
	}
	if err := u.validate(hostname); err != nil {
		return err
	}
	params := map[string]any{"hostname": hostname}
	if u.Certificate != "" {
		params["ssl_certificate_sni_crt"] = u.Certificate
		params["ssl_certificate_sni_key"] = u.Key
	}
	if u.Bundle != "" {
		params["ssl_certificate_sni_bundle"] = u.Bundle
	}
	if u.CSR != "" {
		params["ssl_certificate_sni_csr"] = u.CSR
	}
	if u.Active != nil {
		params["ssl_certificate_is_active"] = yn(*u.Active)
	}
	if u.ForceHTTPS != nil {
		params["ssl_certificate_force_https"] = yn(*u.ForceHTTPS)
	}
	if u.HSTSMaxAge != nil {
		params["ssl_certificate_hsts_max_age"] = *u.HSTSMaxAge
	}
	return wrapHostErr("updating TLS of", hostname, s.c.update(ctx, "update_ssl", params))
}

// Get returns the TLS state of a domain or subdomain, or ErrNotFound.
func (s *TLSService) Get(ctx context.Context, hostname string) (*HostTLS, error) {
	if hostname == "" {
		return nil, errors.New("kasapi: hostname must not be empty")
	}
	d, err := s.c.Domains.Get(ctx, hostname)
	if err == nil {
		return &d.TLS, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	sub, err := s.c.Subdomains.Get(ctx, hostname)
	if err != nil {
		return nil, err
	}
	return &sub.TLS, nil
}
