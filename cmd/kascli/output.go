// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// printer renders results following kubectl output conventions:
// table (default), wide, json, yaml, name; --no-headers suppresses the
// header row of table/wide.
type printer struct {
	format    string // "", "table", "wide", "json", "yaml", "name"
	noHeaders bool
	out       io.Writer
}

func newPrinter(format string, noHeaders bool) (*printer, error) {
	switch format {
	case "", "table", "wide", "json", "yaml", "name":
	default:
		return nil, fmt.Errorf(`unable to match a printer suitable for the output format %q, allowed formats are: json, name, table, wide, yaml`, format)
	}
	return &printer{format: format, noHeaders: noHeaders, out: os.Stdout}, nil
}

// row is one table line plus the data behind it for structured formats.
type row struct {
	// name is the kubectl-style "kind/identifier" for -o name.
	name string
	// cells for table output; wideCells are appended for -o wide.
	cells     []string
	wideCells []string
	// object is the structured representation for -o json/yaml.
	object any
}

// printList renders a homogeneous list. headers/wideHeaders correspond to
// row.cells/row.wideCells.
func (p *printer) printList(headers, wideHeaders []string, rows []row) error {
	switch p.format {
	case "json":
		return p.printJSON(objects(rows))
	case "yaml":
		return p.printYAML(objects(rows))
	case "name":
		for _, r := range rows {
			fmt.Fprintln(p.out, r.name)
		}
		return nil
	}

	wide := p.format == "wide"
	tw := tabwriter.NewWriter(p.out, 0, 8, 3, ' ', 0)
	if !p.noHeaders {
		hs := headers
		if wide {
			hs = append(append([]string{}, headers...), wideHeaders...)
		}
		fmt.Fprintln(tw, tabLine(hs))
	}
	if len(rows) == 0 && !p.noHeaders {
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "No resources found.")
		return nil
	}
	for _, r := range rows {
		cs := r.cells
		if wide {
			cs = append(append([]string{}, r.cells...), r.wideCells...)
		}
		fmt.Fprintln(tw, tabLine(cs))
	}
	return tw.Flush()
}

// printObject renders a single non-list value (e.g. exec results,
// config view).
func (p *printer) printObject(v any) error {
	switch p.format {
	case "yaml":
		return p.printYAML(v)
	default: // json is the default for raw objects
		return p.printJSON(v)
	}
}

func (p *printer) printJSON(v any) error {
	enc := json.NewEncoder(p.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (p *printer) printYAML(v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	_, err = p.out.Write(data)
	return err
}

func objects(rows []row) []any {
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.object)
	}
	return out
}

func tabLine(cells []string) string {
	s := ""
	for i, c := range cells {
		if i > 0 {
			s += "\t"
		}
		if c == "" {
			c = "<none>"
		}
		s += c
	}
	return s
}

func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
