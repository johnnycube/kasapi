// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"fmt"
	"strings"
)

// HostSettings are the settings of a domain or subdomain. Unset fields are not sent.
type HostSettings struct {
	// Path is the document root, or the redirect target with a RedirectStatus.
	Path string
	// RedirectStatus is 0 (no redirect), 301, 302 or 307.
	RedirectStatus *int
	// PHPVersion, e.g. "8.4". KAS defaults to 7.1 on create.
	PHPVersion string
	// Active enables or disables the host. KAS accepts it on updates only.
	Active *bool
}

// isZero reports whether no setting is set.
func (h HostSettings) isZero() bool {
	return h.Path == "" && h.RedirectStatus == nil && h.PHPVersion == "" && h.Active == nil
}

// validate rejects values KAS would answer with a syntax fault.
func (h HostSettings) validate() error {
	if h.RedirectStatus != nil {
		switch *h.RedirectStatus {
		case 0, 301, 302, 307:
		default:
			return fmt.Errorf("kasapi: redirect status must be 0, 301, 302 or 307, got %d", *h.RedirectStatus)
		}
		if *h.RedirectStatus != 0 && h.Path == "" {
			return fmt.Errorf("kasapi: redirect status %d needs the redirect target in Path", *h.RedirectStatus)
		}
	}
	return nil
}

// params adds the set fields to a request.
func (h HostSettings) params(params map[string]any, pathKey string) {
	if h.Path != "" {
		params[pathKey] = h.Path
	}
	if h.RedirectStatus != nil {
		params["redirect_status"] = *h.RedirectStatus
	}
	if h.PHPVersion != "" {
		params["php_version"] = h.PHPVersion
	}
	if h.Active != nil {
		params["is_active"] = yn(*h.Active)
	}
}

// HostTLS is the TLS state of a domain or subdomain. The private key is not mapped.
type HostTLS struct {
	// Active reports whether the certificate is served.
	Active bool
	// Type is the certificate type; "LE90D" marks Let's Encrypt.
	Type string
	// ForceHTTPS reports whether HTTP requests are redirected to HTTPS.
	ForceHTTPS bool
	// HSTSMaxAge in seconds; -1 when HSTS is off.
	HSTSMaxAge int
	// Certificate and Bundle are PEM-encoded.
	Certificate string
	Bundle      string
}

// LetsEncrypt reports whether the KAS panel issued the certificate via Let's Encrypt.
func (t HostTLS) LetsEncrypt() bool {
	return strings.HasPrefix(strings.ToUpper(t.Type), "LE")
}

// hostTLSFrom reads the ssl_certificate_sni_* fields.
func hostTLSFrom(m map[string]any) HostTLS {
	t := HostTLS{
		Active:      isYes(m["ssl_certificate_sni_is_active"]),
		Type:        asString(m["ssl_certificate_sni_type"]),
		ForceHTTPS:  isYes(m["ssl_certificate_sni_force_https"]),
		HSTSMaxAge:  -1,
		Certificate: asString(m["ssl_certificate_sni_crt"]),
		Bundle:      asString(m["ssl_certificate_sni_bundle"]),
	}
	// An unset max-age arrives as an empty string, which is "off", not 0.
	if raw := strings.TrimSpace(asString(m["ssl_certificate_sni_hsts_max_age"])); raw != "" {
		t.HSTSMaxAge = asInt(raw)
	}
	return t
}
