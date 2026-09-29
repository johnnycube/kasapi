# kasapi

[![CI](https://github.com/johnnycube/kasapi/actions/workflows/ci.yml/badge.svg)](https://github.com/johnnycube/kasapi/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/johnnycube/kasapi.svg)](https://pkg.go.dev/github.com/johnnycube/kasapi)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Go client for the all-inkl.com KAS hosting API. The KAS panel is exposed as
a SOAP service; this package wraps it in typed methods for the resources worth
automating — DNS records, mailboxes, forwards, domains and subdomains, TLS
certificates, FTP users, databases, cronjobs, dynamic DNS — over a transport
that handles the session handshake, the flood-protection delays and the
PHP-shaped responses on its own.

The core package is dependency-free, standard library only. That is
deliberate: it drops into any project without pulling an import tree along,
and it is the foundation
[terraform-provider-allinkl](https://github.com/johnnycube/terraform-provider-allinkl)
builds on.

> **Unofficial.** Not affiliated with, endorsed by, or supported by
> all-inkl.com (Neue Medien Münnich GmbH). "all-inkl" and "KAS" name the
> service this talks to, nothing more. No warranty — see [LICENSE](LICENSE).

## Design

The client is one layer over the raw API, with typed services on top:

- **Transport.** SOAP envelope construction, the `KasAuth` session handshake
  (SHA1 by default, plain optional), transparent re-authentication when a
  session expires, and the generic decoder that turns KAS's SOAP-encoded PHP
  structures into `map[string]any` / `[]any`.
- **Two-factor authentication.** `Config.OTP` is a callback that supplies the
  one-time PIN. It runs on every handshake — a session that expires needs a
  fresh PIN, so a static value would not survive re-authentication.
- **Flood protection.** Every KAS response carries a `KasFloodDelay` that must
  elapse before the next request. The client honors it, serializes calls, and
  retries `flood_protection` faults with bounded backoff. Large batches apply
  slowly by design — that is the API's constraint, not the client's.
- **`Client.Exec`.** One entry point that runs any KAS action with raw
  parameters. Every typed service is a thin wrapper over it, and it is the
  escape hatch for actions that have no wrapper yet.
- **Typed services.** One per resource, listed below. Adding one is a single
  file over `Exec`.

| Service      | Covers | KAS actions |
|--------------|--------|-------------|
| `DNS`        | records of a zone | `get/add/update/delete_dns_settings` |
| `Domains`    | domains and their host settings; no registration, transfer or deletion | `get_domains`, `update_domain` |
| `Subdomains` | subdomains and their host settings | `get/add/update/delete_subdomain` |
| `TLS`        | certificate, HTTPS redirect and HSTS of a host | `update_ssl` |
| `Mail`       | mailboxes, forwards, autoresponder, access restrictions, standard filters | `*_mailaccount`, `*_mailforward`, `*_mailstandardfilter` |
| `FTP`        | additional FTP logins | `get/add/update/delete_ftpuser` |
| `Databases`  | MySQL databases | `get/add/update/delete_database` |
| `Cronjobs`   | scheduled URL requests | `get/add/update/delete_cronjob` |
| `DDNS`       | dynamic DNS users | `get/add/update/delete_ddnsuser` |

Three conventions hold across the services:

- **Host settings.** Domains and subdomains share `HostSettings`: document
  root, redirect (`0`, `301`, `302`, `307`), PHP version and the active flag.
  Unset fields are not sent. A subdomain created without a PHP version gets
  the KAS default, which the API documents as 7.1 — set one.
- **Updates are idempotent.** KAS answers an update that changes nothing with
  the fault `nothing_to_do`. The desired state is reached, so update methods
  return success.
- **Secrets are write-only.** KAS returns mailbox, FTP, database and DDNS
  passwords and the TLS private key in its `get_*` responses. The services
  deliberately do not map them.

KAS has no standalone mail-alias objects: sender aliases are a mailbox
property, receiving aliases are forwards.

TLS 1.2 is the floor on the default HTTP client, responses are size-limited,
and the client is safe for concurrent use — calls serialize because the API
requires it.

## Objects

One section per object: the type, the service that manages it, its `kascli`
resource and its fields. Fields marked *read-only* are reported by KAS and
ignored on writes.

### Domain and Subdomain

`Domains` (`List`, `Get`, `Update`) and `Subdomains` (`List`, `Get`, `Create`,
`CreateWithSettings`, `Update`, `UpdatePath`, `Delete`). kascli: `domains`
(`do`), `subdomains` (`sub`).

- **`Name` / `FQDN`** — the host name, which is also the identifier.
- **`Path`** — document root relative to the account root, or the redirect
  target when `RedirectStatus` is not 0.
- **`RedirectStatus`** — `0` (none), `301`, `302` or `307`.
- **`PHPVersion`** — e.g. `"8.4"`.
- **`Active`** — whether the host is served. KAS accepts it on updates only.
- **`PHPDeprecated`**, **`InProgress`** — *read-only*. `InProgress` means KAS
  is still applying a change; updates fail with `in_progress` until it clears.
- **`DKIMSelector`** — *read-only*, domains only.
- **`TLS`** — *read-only*, the `HostTLS` of the host.

Writes take `HostSettings` with `Path`, `RedirectStatus`, `PHPVersion` and
`Active`. `RedirectStatus` and `Active` are pointers, so that "not set" and
"set to 0 / false" differ.

### HostTLS and TLSUpdate

`TLS` (`Get`, `Update`). kascli: `tls`.

`HostTLS` is the state KAS reports:

- **`Active`** — whether the certificate is served.
- **`Type`** — the certificate type as KAS names it. `LE90D` marks a Let's
  Encrypt certificate issued through the panel; `LetsEncrypt()` tests for it.
- **`ForceHTTPS`** — whether HTTP requests are redirected to HTTPS.
- **`HSTSMaxAge`** — in seconds, `-1` when HSTS is off.
- **`Certificate`**, **`Bundle`** — PEM-encoded.

`TLSUpdate` is a change:

- **`Certificate`**, **`Key`** — PEM-encoded; set both or neither.
- **`Bundle`**, **`CSR`** — PEM-encoded intermediates and signing request.
- **`Active`**, **`ForceHTTPS`**, **`HSTSMaxAge`** — pointers; unset fields are
  not sent.

### MailAccount

`Mail` (`ListAccounts`, `GetAccount`, `CreateAccount`, `DeleteAccount` and one
`Update…` method per setting). kascli: `mailaccounts` (`ma`).

- **`Login`** — KAS-assigned, e.g. `m0123456`; the identifier.
- **`LocalPart`**, **`Domain`** — the address.
- **`CopyAddresses`** — receive a copy of incoming mail. `UpdateCopyAddresses`.
- **`SenderAliases`** — addresses the mailbox may send as.
  `UpdateSenderAliases`.
- **`Responder`** — the autoresponder, see below. `UpdateResponder`.
- **`State`** — `MailActive`, `MailReceiveDisabled` (no new mail, retrieval
  still works) or `MailForbidden`. `UpdateState`.
- **`AllowNets`** — clients allowed to access the mailbox: IP addresses, CIDR
  networks or `webmail`. Empty means unrestricted. `UpdateAllowNets`.
- **`WebmailAutologin`** — whether the KAS panel may open webmail without the
  password. `UpdateWebmailAutologin`.
- **`SpamFilters`** — *read-only*, names of the active standard filters.
- **`InProgress`** — *read-only*.

The password is passed to `CreateAccount` and `UpdatePassword`; it is never
part of the object.

### Responder

Part of `MailAccount`.

- **`Active`** — turns the responder on.
- **`Start`**, **`End`** — limit it to a window. Set both or neither.
- **`Text`** — the reply. Required for an active responder.
- **`ContentType`** — `text` (the KAS default) or `html`.
- **`DisplayName`** — sender name shown on the reply.

### MailFilter

`Mail` (`AvailableFilters`, `SetFilters`, `DeleteFilters`). kascli:
`mailfilters` (`mfi`).

- **`Name`** — a filter from `AvailableFilters`.
- **`Action`** — for content filters only: `delete`, `mark`, `move=<folder>`
  or `forward=<address>`.

`MailFilterInfo` describes an available filter: `Name`, `Type`, `Title` and
`Recommended`.

### MailForward

`Mail` (`ListForwards`, `GetForward`, `CreateForward`, `UpdateForward`,
`DeleteForward`). kascli: `mailforwards` (`mf`).

- **`LocalPart`**, **`Domain`** — the source address, which is the identifier.
- **`Targets`** — one to ten addresses.
- **`SpamFilters`**, **`InProgress`** — *read-only*.

### FTPUser

`FTP` (`List`, `Get`, `Create`, `Update`, `UpdatePassword`, `Delete`). kascli:
`ftpusers` (`ftp`).

- **`Login`** — KAS-assigned, e.g. `f0123456`; the identifier.
- **`Path`** — directory the login is confined to; empty means `/`.
- **`Comment`** — free text. KAS requires one.
- **`Read`**, **`Write`**, **`List`** — the permissions. They are sent as
  given, so the zero value grants nothing.
- **`VirusScan`** — scans uploads with ClamAV.
- **`MainUser`** — *read-only*. The account's own login, which cannot be
  deleted.
- **`InProgress`** — *read-only*.

### Database

`Databases` (`List`, `Get`, `Create`, `Update`, `UpdatePassword`, `Delete`).
kascli: `databases` (`db`).

- **`Login`**, **`Name`** — KAS-assigned and identical, e.g. `d0123456`.
  `Login` is the identifier.
- **`Comment`** — free text. KAS requires one.
- **`AllowedHosts`** — hosts that may connect from outside: IP addresses or
  CIDR networks. Empty closes external access.
- **`UsedSpace`**, **`InProgress`** — *read-only*.

### Cronjob

`Cronjobs` (`List`, `Get`, `Create`, `Update`, `Delete`). kascli: `cronjobs`
(`cj`).

- **`ID`** — KAS-assigned; the identifier.
- **`Comment`** — free text. KAS requires one.
- **`Protocol`**, **`URL`** — `http` or `https`, and the address without the
  protocol. A KAS cronjob requests a URL; it does not run a command.
- **`Minute`**, **`Hour`**, **`DayOfMonth`**, **`Month`**, **`DayOfWeek`** —
  the schedule: a number, `*`, or a step such as `*/15`. Empty is sent as `*`.
- **`HTTPUser`**, **`HTTPPassword`** — HTTP basic auth. The password is
  write-only, and `Update` sends the pair only when both are set, so a job
  read with `Get` keeps its stored password when written back.
- **`MailAddress`** — receives the output of each run.
- **`MailCondition`** — no mail when the output contains this word.
- **`MailSubject`** — `default` or `comment`.
- **`Active`** — sent as given, so the zero value is an inactive job.

### DDNSUser

`DDNS` (`List`, `Get`, `Create`, `Update`, `UpdatePassword`, `Delete`). kascli:
`ddnsusers` (`ddns`).

- **`Login`** — KAS-assigned, e.g. `dyn0123456`; the identifier.
- **`Zone`**, **`Label`** — the host the user controls, `Label.Zone`. Both are
  fixed at creation. `Host()` returns the full name.
- **`Comment`** — free text. KAS requires one.
- **`TargetIP`** — the initial IPv4 address on create. Afterwards the DDNS
  client sets it.
- **`TargetIPv6`** — *read-only*; only the DDNS client sets it.
- **`DualStack`** — lets the host carry an A and an AAAA record.

### DNSRecord

`DNS` (`List`, `Get`, `Create`, `Update`, `Delete`). kascli: `dnsrecords`
(`dns`).

- **`ID`** — KAS-assigned; the identifier.
- **`Zone`**, **`Name`**, **`Type`**, **`Data`**, **`Aux`** — the record.
  `Type` is fixed at creation; `Aux` holds the MX priority.
- **`Changeable`**, **`Deletable`** — *read-only*. System records such as the
  default NS entries are neither.

## TLS and Let's Encrypt

`TLS.Update` installs a certificate you bring and sets the HTTPS redirect and
HSTS of a host. Certificate and key are checked before they leave the
process: they must form a pair, and the certificate must name the host.

**The API cannot request a Let's Encrypt certificate.** `update_ssl` has no
ACME parameter. The issuance KAS offers is a panel feature (Domain → Edit →
SSL protection → Let's Encrypt) with no counterpart in the API, so neither
the library nor `kascli` can switch it on. What the API does report is the
result: `HostTLS.LetsEncrypt()` tells whether a host serves a certificate
issued that way.

To automate issuance, run an ACME client against the DNS-01 challenge —
`DNS.Create` writes the `_acme-challenge` TXT record — and install the
certificate with `TLS.Update`. For Kubernetes,
[cert-manager-webhook-all-inkl](https://github.com/johnnycube/cert-manager-webhook-all-inkl)
does the DNS-01 part.

## Usage

```go
client, err := kasapi.New(kasapi.Config{
    Login:    os.Getenv("KAS_LOGIN"),
    Password: os.Getenv("KAS_PASSWORD"),
})
if err != nil {
    return err
}

records, err := client.DNS.List(ctx, "example.com")

// A redirecting subdomain on a chosen PHP version.
err = client.Subdomains.CreateWithSettings(ctx, "go", "example.com", kasapi.HostSettings{
    Path:           "https://example.org",
    RedirectStatus: new(301),
    PHPVersion:     "8.4",
})

// An FTP login that may read and list, nothing else.
login, err := client.FTP.Create(ctx, kasapi.FTPUser{
    Path: "/logs/", Comment: "log reader", Read: true, List: true,
}, password)

// Any action without a typed wrapper:
ret, err := client.Exec(ctx, "get_mailinglists", map[string]any{})
```

Structs that describe a whole object — `FTPUser`, `Cronjob` — are sent as
given. Their zero value grants no permission and leaves a cronjob inactive,
so set what the object needs.

## kascli

A kubectl-style command-line client ships in `cmd/kascli`. Accounts are
contexts in a kubeconfig-like file at `~/.config/kasapi/config` (override with
`$KASCONFIG`; written with mode `0600`).

```sh
go build -o kascli ./cmd/kascli

# contexts, one per account
kascli config set-context prod --login w0123456 --current
kascli config set-context staging --login w0999999
kascli config get-contexts
kascli config use-context staging
kascli config view                  # YAML, passwords redacted (--raw to show)

# kubectl verbs and output conventions
kascli api-resources                           # resource types and their verbs
kascli get domains -o wide                     # redirect, PHP, TLS state
kascli get dnsrecords --zone example.com -o wide
kascli get mailaccounts -o yaml
kascli get subdomains --no-headers
kascli get dns --zone example.com -o name      # dnsrecord/12345
kascli get tls blog.example.com
kascli --context prod get mailforwards -o json
kascli delete dnsrecord 12345

# create and update; an update changes only the flags that are given
kascli create dnsrecord --zone example.com --name www --type A --data 203.0.113.10
kascli create subdomain --name go --domain example.com \
    --path https://example.org --redirect 301 --php 8.4
kascli create ftpuser --path /logs/ --comment "log reader" --write=false
kascli create database --comment shop --allowed-host 203.0.113.7
kascli create cronjob --url example.com/cron.php --comment nightly --hour 3 --minute 30
kascli create ddnsuser --zone example.com --label home --target-ip 203.0.113.4 \
    --comment "at home"
kascli update subdomain blog.example.com --php 8.4
kascli update mailaccount m0123456 --responder on --responder-text "Back on Monday." \
    --responder-from 2026-12-24 --responder-until 2027-01-04
kascli update tls example.com --cert fullchain.pem --key privkey.pem --force-https
kascli update cronjob 325208 --active=false

# raw escape hatch for any KAS action
kascli exec get_mailinglists
kascli exec add_dns_settings zone_host=example.com. record_type=TXT \
    record_name=_test record_data=hello record_aux=0
```

Resource short names: `dns`, `do`, `sub`, `ma`, `mf`, `mfi`, `ftp`, `db`,
`cj`, `ddns`. Output formats: `table` (default), `wide`, `json`, `yaml`,
`name`; `--no-headers` for scripting.

Passwords are never flag values — they would land in the shell history and
the process list. Commands that set one ask for it at the terminal, or read
it from stdin with `--password-stdin`.

`kascli update tls` installs a certificate from PEM files. It has no flag
that orders a Let's Encrypt certificate, because the API has none — see
[TLS and Let's Encrypt](#tls-and-lets-encrypt).

Credentials resolve like kubectl: `--context` selects the context, otherwise
`current-context` applies. `KAS_LOGIN` / `KAS_PASSWORD` override the context's
values, and a missing password is prompted for interactively (echo disabled
where the terminal allows it). For an account with two-factor authentication,
mark the context with `kascli config set-context NAME --two-factor` and
`kascli` asks for the one-time PIN on login; `--otp` or `KAS_OTP` supply it
without a prompt. Storing a password in the config file is
optional and warned about — the environment variable or the prompt avoid it.

The raw `exec` verb doubles as the way to confirm KAS field names against a
real account. Request parameters follow the
[KAS API documentation](https://kasapi.kasserver.com/dokumentation/phpdoc/);
response fields follow recorded KAS responses. Neither is checked against a
live account yet, so the verification notes in the source stay. The same
holds for `session_2fa`: it is documented for `add_session` and sent to
`KasAuth` on that basis.

`kascli` is built on [cobra](https://github.com/spf13/cobra) (commands,
`--help` trees and shell completion via `kascli completion <shell>`),
[gopkg.in/yaml.v3](https://gopkg.in/yaml.v3) (config and `-o yaml`) and
[`golang.org/x/term`](https://pkg.go.dev/golang.org/x/term) (the password
prompt). These dependencies live only under `cmd/kascli` and `internal/`; the
core `kasapi` package stays standard-library-only regardless.

## Testing

```sh
go test -race ./...        # unit tests + the kasapitest fake server
make cover                 # coverage summary
```

The suite covers the SOAP decoder, the auth handshake with and without a
one-time PIN, session reuse and re-authentication, flood backoff, every
method of every service with its request parameters and fault handling, and
every `kascli` command. `kasapitest` provides an in-process fake KAS server
for use in downstream tests without credentials; set `Server.OTP` to make it
require a one-time PIN.

## Extending

A new resource type is one file. Add a typed service over `Client.Exec`
mirroring the existing ones:

```go
type MailingListService struct{ c *Client }

func (s *MailingListService) Create(ctx context.Context, name, domain, password string) error {
    _, err := s.c.Exec(ctx, "add_mailinglist", map[string]any{
        "mailinglist_name":     name,
        "mailinglist_domain":   domain,
        "mailinglist_password": password,
    })
    return err
}
```

Register it in `New()` (`c.MailingLists = &MailingListService{c: c}`) and add
tests against `kasapitest`. The helpers in `params.go` cover the recurring
parts: `list` and `getOne` for `get_*` actions, `update` and `remove` for the
fault codes that mean "unchanged" or "absent".

KAS actions without a typed service: mailing lists (`*_mailinglist`),
directory protection (`*_directoryprotection`), network drive users
(`*_sambauser`), software installs, symlinks, the statistics (`get_space`,
`get_traffic`) and the account actions for resellers.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
