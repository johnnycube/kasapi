// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// KasAuth and KasApi each take a single string parameter holding a JSON document.
const soapEnvelopeTpl = `<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:ns1="%s"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
    SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <SOAP-ENV:Body>
    <ns1:%s>
      <Params xsi:type="xsd:string">%s</Params>
    </ns1:%s>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`

// soapCall performs a SOAP request and returns the decoded <return> element as
// a generic value (map[string]any, []any or string).
func (c *Client) soapCall(ctx context.Context, endpoint, namespace, method, jsonPayload string) (any, error) {
	var escaped bytes.Buffer
	if err := xml.EscapeText(&escaped, []byte(jsonPayload)); err != nil {
		return nil, fmt.Errorf("kasapi: escaping payload: %w", err)
	}

	body := fmt.Sprintf(soapEnvelopeTpl, namespace, method, escaped.String(), method)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kasapi: building request: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", fmt.Sprintf("%s#%s", namespace, method))
	req.Header.Set("User-Agent", c.cfg.UserAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kasapi: performing request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("kasapi: reading response: %w", err)
	}

	root, err := parseXMLTree(raw)
	if err != nil {
		return nil, fmt.Errorf("kasapi: parsing SOAP response (status %d): %w", resp.StatusCode, err)
	}

	// KAS reports application errors as faults with a symbolic faultstring.
	if fault := root.find("Fault"); fault != nil {
		code := strings.TrimSpace(fault.childText("faultstring"))
		if code == "" {
			code = strings.TrimSpace(fault.childText("faultcode"))
		}
		return nil, &APIError{Code: code}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kasapi: unexpected HTTP status %d", resp.StatusCode)
	}

	ret := root.find("return")
	if ret == nil {
		return nil, fmt.Errorf("kasapi: response contains no <return> element")
	}
	return ret.toValue(), nil
}

// KAS answers with SOAP-encoded PHP structures (apache Map / SOAP-ENC arrays).
// Rather than model each response, decode into a generic tree and convert it to
// map[string]any / []any / string; typed services pick the fields they need.

type xmlNode struct {
	name     string
	text     string
	children []*xmlNode
}

func parseXMLTree(raw []byte) (*xmlNode, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	root := &xmlNode{name: "#root"}
	stack := []*xmlNode{root}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xmlNode{name: t.Name.Local}
			parent := stack[len(stack)-1]
			parent.children = append(parent.children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			stack[len(stack)-1].text += string(t)
		}
	}
	return root, nil
}

// find returns the first descendant with the given local name (depth-first).
func (n *xmlNode) find(name string) *xmlNode {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
		if found := c.find(name); found != nil {
			return found
		}
	}
	return nil
}

func (n *xmlNode) childText(name string) string {
	for _, c := range n.children {
		if c.name == name {
			return c.text
		}
	}
	return ""
}

// toValue converts a node into map[string]any, []any or string, handling the
// three KAS shapes: apache Map (<item><key/><value/></item>), SOAP-ENC array
// (repeated <item>) and plain scalar.
func (n *xmlNode) toValue() any {
	if len(n.children) == 0 {
		return strings.TrimSpace(n.text)
	}

	// apache Map: every child is an <item> with key/value -> map.
	if isKeyValueMap(n) {
		m := make(map[string]any, len(n.children))
		for _, item := range n.children {
			var key string
			var val any = ""
			for _, kv := range item.children {
				switch kv.name {
				case "key":
					key = strings.TrimSpace(kv.text)
				case "value":
					val = kv.toValue()
				}
			}
			m[key] = val
		}
		return m
	}

	// SOAP-ENC array: repeated keyless <item> -> slice.
	if allNamed(n, "item") {
		list := make([]any, 0, len(n.children))
		for _, item := range n.children {
			list = append(list, item.toValue())
		}
		return list
	}

	// Fallback: struct-like, map children by element name. Duplicate names
	// are collected into a slice.
	m := make(map[string]any, len(n.children))
	for _, c := range n.children {
		v := c.toValue()
		if existing, ok := m[c.name]; ok {
			if s, isSlice := existing.([]any); isSlice {
				m[c.name] = append(s, v)
			} else {
				m[c.name] = []any{existing, v}
			}
			continue
		}
		m[c.name] = v
	}
	return m
}

func isKeyValueMap(n *xmlNode) bool {
	if len(n.children) == 0 {
		return false
	}
	for _, c := range n.children {
		if c.name != "item" {
			return false
		}
		hasKey := false
		for _, kv := range c.children {
			if kv.name == "key" {
				hasKey = true
			}
		}
		if !hasKey {
			return false
		}
	}
	return true
}

func allNamed(n *xmlNode, name string) bool {
	if len(n.children) == 0 {
		return false
	}
	for _, c := range n.children {
		if c.name != name {
			return false
		}
	}
	return true
}
