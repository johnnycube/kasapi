// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"strconv"
	"strings"

	kasapi "github.com/johnnycube/kasapi"
)

// listing is what `kascli get` prints for one resource type.
type listing struct {
	headers, wideHeaders []string
	rows                 []row
}

// getRequest carries the client and the command line of one `kascli get`.
type getRequest struct {
	ctx    context.Context
	client *kasapi.Client
	args   []string
	zone   string
}

// getters fetches each resource type kascli can get.
var getters = map[string]func(getRequest) (listing, error){
	"domains":      getDomains,
	"dnsrecords":   getDNSRecords,
	"mailaccounts": getMailAccounts,
	"mailforwards": getMailForwards,
	"subdomains":   getSubdomains,
	"tls":          getTLS,
	"mailfilters":  getMailFilters,
	"ftpusers":     getFTPUsers,
	"databases":    getDatabases,
	"cronjobs":     getCronjobs,
	"ddnsusers":    getDDNSUsers,
}

func cmdGet(g *globals, args []string, zone string) error {
	res, err := canonicalResource(args[0])
	if err != nil {
		return err
	}
	p, err := newPrinter(g.output, g.noHeaders)
	if err != nil {
		return err
	}
	client, ctx, cancel, err := newClient(g)
	if err != nil {
		return err
	}
	defer cancel()

	get, ok := getters[res]
	if !ok {
		return nil
	}
	l, err := get(getRequest{ctx: ctx, client: client, args: args, zone: zone})
	if err != nil {
		return err
	}
	return p.printList(l.headers, l.wideHeaders, l.rows)
}

// rowsOf turns each item into a row.
func rowsOf[T any](items []T, toRow func(T) row) []row {
	rows := make([]row, 0, len(items))
	for _, it := range items {
		rows = append(rows, toRow(it))
	}
	return rows
}

// listOf fetches the items and turns them into a listing.
func listOf[T any](items []T, err error, headers, wide []string, toRow func(T) row) (listing, error) {
	if err != nil {
		return listing{}, err
	}
	return listing{headers: headers, wideHeaders: wide, rows: rowsOf(items, toRow)}, nil
}

func getDomains(r getRequest) (listing, error) {
	domains, err := r.client.Domains.List(r.ctx)
	return listOf(domains, err, []string{"NAME", "PATH"}, hostWideHeaders, func(d kasapi.Domain) row {
		return row{
			name:      "domain/" + d.Name,
			cells:     []string{d.Name, d.Path},
			wideCells: hostWideCells(d.RedirectStatus, d.PHPVersion, d.Active, d.TLS),
			object: hostObject(map[string]any{"name": d.Name, "path": d.Path, "dkimSelector": d.DKIMSelector},
				d.RedirectStatus, d.PHPVersion, d.PHPDeprecated, d.Active, d.InProgress, d.TLS),
		}
	})
}

func getDNSRecords(r getRequest) (listing, error) {
	if r.zone == "" {
		return listing{}, errors.New("--zone is required for dnsrecords (e.g. kascli get dns --zone example.com)")
	}
	records, err := r.client.DNS.List(r.ctx, r.zone)
	return listOf(records, err,
		[]string{"ID", "NAME", "TYPE", "DATA", "AUX"},
		[]string{"ZONE", "CHANGEABLE", "DELETABLE"},
		func(d kasapi.DNSRecord) row {
			return row{
				name:      "dnsrecord/" + d.ID,
				cells:     []string{d.ID, d.Name, d.Type, d.Data, strconv.Itoa(d.Aux)},
				wideCells: []string{d.Zone, boolWord(d.Changeable), boolWord(d.Deletable)},
				object: map[string]any{
					"id": d.ID, "zone": d.Zone, "name": d.Name, "type": d.Type,
					"data": d.Data, "aux": d.Aux, "changeable": d.Changeable,
					"deletable": d.Deletable,
				},
			}
		})
}

func getMailAccounts(r getRequest) (listing, error) {
	accounts, err := r.client.Mail.ListAccounts(r.ctx)
	return listOf(accounts, err,
		[]string{"LOGIN", "ADDRESS", "RESPONDER"},
		[]string{"COPY-ADDRESSES", "SENDER-ALIASES", "STATE", "ALLOW-NETS", "FILTERS"},
		func(a kasapi.MailAccount) row {
			return row{
				name:  "mailaccount/" + a.Login,
				cells: []string{a.Login, a.Address(), boolWord(a.ResponderActive)},
				wideCells: []string{
					strings.Join(a.CopyAddresses, ","), strings.Join(a.SenderAliases, ","),
					mailStateWord(a.State), strings.Join(a.AllowNets, ","), strings.Join(a.SpamFilters, ","),
				},
				object: map[string]any{
					"login": a.Login, "address": a.Address(),
					"responderActive":  a.ResponderActive,
					"responder":        responderObject(a.Responder),
					"copyAddresses":    anySlice(a.CopyAddresses),
					"senderAliases":    anySlice(a.SenderAliases),
					"state":            mailStateWord(a.State),
					"allowNets":        anySlice(a.AllowNets),
					"spamFilters":      anySlice(a.SpamFilters),
					"webmailAutologin": a.WebmailAutologin,
					"inProgress":       a.InProgress,
				},
			}
		})
}

func getMailForwards(r getRequest) (listing, error) {
	forwards, err := r.client.Mail.ListForwards(r.ctx)
	return listOf(forwards, err, []string{"SOURCE", "TARGETS"}, []string{"FILTERS"}, func(f kasapi.MailForward) row {
		return row{
			name:      "mailforward/" + f.Source(),
			cells:     []string{f.Source(), strings.Join(f.Targets, ",")},
			wideCells: []string{strings.Join(f.SpamFilters, ",")},
			object: map[string]any{
				"source": f.Source(), "targets": anySlice(f.Targets),
				"spamFilters": anySlice(f.SpamFilters), "inProgress": f.InProgress,
			},
		}
	})
}

func getSubdomains(r getRequest) (listing, error) {
	subs, err := r.client.Subdomains.List(r.ctx)
	return listOf(subs, err, []string{"FQDN", "PATH"}, hostWideHeaders, func(s kasapi.Subdomain) row {
		return row{
			name:      "subdomain/" + s.FQDN,
			cells:     []string{s.FQDN, s.Path},
			wideCells: hostWideCells(s.RedirectStatus, s.PHPVersion, s.Active, s.TLS),
			object: hostObject(map[string]any{"fqdn": s.FQDN, "path": s.Path},
				s.RedirectStatus, s.PHPVersion, s.PHPDeprecated, s.Active, s.InProgress, s.TLS),
		}
	})
}

func getTLS(r getRequest) (listing, error) {
	if len(r.args) < 2 {
		return listing{}, errors.New("a host name is required (e.g. kascli get tls example.com)")
	}
	host := r.args[1]
	state, err := r.client.TLS.Get(r.ctx, host)
	if err != nil {
		return listing{}, err
	}
	obj := tlsObject(*state)
	obj["host"] = host
	return listing{
		headers: []string{"HOST", "ACTIVE", "TYPE", "FORCE-HTTPS", "HSTS-MAX-AGE"},
		rows: []row{{
			name: "tls/" + host,
			cells: []string{
				host, boolWord(state.Active), state.Type,
				boolWord(state.ForceHTTPS), strconv.Itoa(state.HSTSMaxAge),
			},
			object: obj,
		}},
	}, nil
}

func getMailFilters(r getRequest) (listing, error) {
	filters, err := r.client.Mail.AvailableFilters(r.ctx)
	return listOf(filters, err, []string{"NAME", "TYPE", "TITLE", "RECOMMENDED"}, nil, func(f kasapi.MailFilterInfo) row {
		return row{
			name:  "mailfilter/" + f.Name,
			cells: []string{f.Name, f.Type, f.Title, boolWord(f.Recommended)},
			object: map[string]any{
				"name": f.Name, "type": f.Type, "title": f.Title, "recommended": f.Recommended,
			},
		}
	})
}

func getFTPUsers(r getRequest) (listing, error) {
	users, err := r.client.FTP.List(r.ctx)
	return listOf(users, err,
		[]string{"LOGIN", "PATH", "PERMISSIONS", "COMMENT"},
		[]string{"VIRUS-SCAN", "MAIN-USER"},
		func(u kasapi.FTPUser) row {
			return row{
				name:      "ftpuser/" + u.Login,
				cells:     []string{u.Login, u.Path, ftpPermissions(u), u.Comment},
				wideCells: []string{boolWord(u.VirusScan), boolWord(u.MainUser)},
				object: map[string]any{
					"login": u.Login, "path": u.Path, "comment": u.Comment,
					"read": u.Read, "write": u.Write, "list": u.List,
					"virusScan": u.VirusScan, "mainUser": u.MainUser, "inProgress": u.InProgress,
				},
			}
		})
}

func getDatabases(r getRequest) (listing, error) {
	dbs, err := r.client.Databases.List(r.ctx)
	return listOf(dbs, err,
		[]string{"LOGIN", "COMMENT", "ALLOWED-HOSTS"},
		[]string{"NAME", "USED-SPACE"},
		func(d kasapi.Database) row {
			return row{
				name:      "database/" + d.Login,
				cells:     []string{d.Login, d.Comment, strings.Join(d.AllowedHosts, ",")},
				wideCells: []string{d.Name, strconv.Itoa(d.UsedSpace)},
				object: map[string]any{
					"login": d.Login, "name": d.Name, "comment": d.Comment,
					"allowedHosts": anySlice(d.AllowedHosts), "usedSpace": d.UsedSpace,
					"inProgress": d.InProgress,
				},
			}
		})
}

func getCronjobs(r getRequest) (listing, error) {
	jobs, err := r.client.Cronjobs.List(r.ctx)
	return listOf(jobs, err,
		[]string{"ID", "SCHEDULE", "URL", "ACTIVE", "COMMENT"},
		[]string{"MAIL", "HTTP-USER"},
		func(j kasapi.Cronjob) row {
			return row{
				name:      "cronjob/" + j.ID,
				cells:     []string{j.ID, cronSchedule(j), j.Protocol + "://" + j.URL, boolWord(j.Active), j.Comment},
				wideCells: []string{j.MailAddress, j.HTTPUser},
				object: map[string]any{
					"id": j.ID, "comment": j.Comment, "protocol": j.Protocol, "url": j.URL,
					"minute": j.Minute, "hour": j.Hour, "dayOfMonth": j.DayOfMonth,
					"month": j.Month, "dayOfWeek": j.DayOfWeek, "httpUser": j.HTTPUser,
					"mailAddress": j.MailAddress, "mailCondition": j.MailCondition,
					"mailSubject": j.MailSubject, "active": j.Active,
				},
			}
		})
}

func getDDNSUsers(r getRequest) (listing, error) {
	users, err := r.client.DDNS.List(r.ctx)
	return listOf(users, err,
		[]string{"LOGIN", "HOST", "TARGET-IP", "COMMENT"},
		[]string{"TARGET-IPV6", "DUAL-STACK"},
		func(u kasapi.DDNSUser) row {
			return row{
				name:      "ddnsuser/" + u.Login,
				cells:     []string{u.Login, u.Host(), u.TargetIP, u.Comment},
				wideCells: []string{u.TargetIPv6, boolWord(u.DualStack)},
				object: map[string]any{
					"login": u.Login, "host": u.Host(), "zone": u.Zone, "label": u.Label,
					"targetIP": u.TargetIP, "targetIPv6": u.TargetIPv6,
					"dualStack": u.DualStack, "comment": u.Comment,
				},
			}
		})
}
