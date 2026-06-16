// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package kasapi

import (
	"reflect"
	"testing"
)

func TestParseXMLTree_KeyValueMap(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
 <SOAP-ENV:Body>
  <ns1:KasApiResponse>
   <return>
    <item><key>ReturnString</key><value>TRUE</value></item>
    <item><key>KasFloodDelay</key><value>2</value></item>
   </return>
  </ns1:KasApiResponse>
 </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`)

	root, err := parseXMLTree(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := root.find("return").toValue()
	want := map[string]any{"ReturnString": "TRUE", "KasFloodDelay": "2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestParseXMLTree_ListOfMaps(t *testing.T) {
	raw := []byte(`<r><return>
 <item>
  <item><key>record_id</key><value>1</value></item>
  <item><key>record_type</key><value>A</value></item>
 </item>
 <item>
  <item><key>record_id</key><value>2</value></item>
  <item><key>record_type</key><value>TXT</value></item>
 </item>
</return></r>`)

	root, err := parseXMLTree(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, ok := root.find("return").toValue().([]any)
	if !ok {
		t.Fatalf("expected list, got %#v", root.find("return").toValue())
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 items, got %d", len(got))
	}
	first := got[0].(map[string]any)
	if first["record_id"] != "1" || first["record_type"] != "A" {
		t.Fatalf("unexpected first item: %#v", first)
	}
}

func TestParseXMLTree_Scalar(t *testing.T) {
	raw := []byte(`<r><return xsi:type="xsd:string">  token-123  </return></r>`)
	root, err := parseXMLTree(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := root.find("return").toValue(); got != "token-123" {
		t.Fatalf("got %#v, want token-123", got)
	}
}

func TestParseXMLTree_Fault(t *testing.T) {
	raw := []byte(`<e><Body><Fault>
 <faultcode>SOAP-ENV:Server</faultcode>
 <faultstring>kas_login_incorrect</faultstring>
</Fault></Body></e>`)
	root, err := parseXMLTree(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fault := root.find("Fault")
	if fault == nil {
		t.Fatal("fault not found")
	}
	if got := fault.childText("faultstring"); got != "kas_login_incorrect" {
		t.Fatalf("got %q", got)
	}
}

func TestSplitAddressList(t *testing.T) {
	got := splitAddressList(" a@x.de ; b@x.de,c@x.de;;")
	want := []string{"a@x.de", "b@x.de", "c@x.de"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if splitAddressList("") != nil {
		t.Fatal("empty input should yield nil")
	}
}
