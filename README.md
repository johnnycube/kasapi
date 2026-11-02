# kasapi

[![check](https://github.com/johnnycube/kasapi/actions/workflows/check.yml/badge.svg)](https://github.com/johnnycube/kasapi/actions/workflows/check.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/johnnycube/kasapi.svg)](https://pkg.go.dev/github.com/johnnycube/kasapi)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Go client for the all-inkl.com KAS hosting API. The KAS panel is exposed as
a SOAP service; this package wraps it in typed methods for the resources worth
automating — DNS records, mailboxes, forwards, mailing lists, domains and
subdomains, TLS certificates, FTP and network drive users, directory
protection, databases, cronjobs, dynamic DNS, subaccounts and the account's
statistics — over a transport
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
  structures into `map[string]any` / `[]any`. SHA1 is what the KAS protocol
  mandates, not a security property: the digest is as good as the password,
  and TLS carries the security.
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
| `MailingLists` | Majordomo mailing lists | `get_mailinglists`, `add/update/delete_mailinglist` |
| `DirectoryProtection` | HTTP basic auth on a directory | `get/add/update/delete_directoryprotection` |
| `Samba`      | network drive users | `get_sambausers`, `add/update/delete_sambauser` |
| `Accounts`   | subaccounts, the own account's settings and resources, SSH access, server information | `get_accounts`, `add/update/delete_account`, `get/update_accountsettings`, `get_accountresources`, `update_superusersettings`, `get_server_information` |
| `Statistics` | storage and traffic, read-only | `get_space`, `get_space_usage`, `get_traffic` |

Three conventions hold across the services:

- **Host settings.** Domains and subdomains share `HostSettings`: document
  root, redirect (`0`, `301`, `302`, `307`), PHP version and the active flag.
  Unset fields are not sent. A subdomain created without a PHP version gets
  the KAS default, which the API documents as 7.1 — set one.
- **Updates are idempotent.** KAS answers an update that changes nothing with
  the fault `nothing_to_do`. The desired state is reached, so update methods
  return success.
- **Secrets are write-only.** KAS returns mailbox, FTP, database, DDNS,
  mailing list, directory, network drive and account passwords and the TLS
  private key in its `get_*` responses. The services deliberately do not map
  them.

KAS has no standalone mail-alias objects: sender aliases are a mailbox
property, receiving aliases are forwards.

TLS 1.2 is the floor on the default HTTP client, which also refuses
redirects, so credentials never go to another host, and takes the proxy
settings of the environment. Endpoints must be https; the loopback interface
is the exception, for fakes such as `kasapitest`. Responses are size-limited
and parsed strictly. The client is safe for concurrent use — calls serialize
because the API requires it, and a call waiting for its turn stops when its
context ends. `Client.Logout` ends the session with `delete_session`; the
next call logs in again.

Errors follow one rule: a KAS fault is an `*APIError` carrying its code, a
missing object is `ErrNotFound`, and errors kasapi creates start with
`kasapi:`. Service methods wrap them with the operation, e.g.
`listing domains: kasapi: zone_not_found`. `ErrNotFound` comes from the fault
codes that name the addressed object (`record_id_not_found`,
`ftp_login_not_found`, …); a fault about a missing prerequisite such as
`email_domain_doesnt_exist` or `kas_login_not_found` stays an `*APIError`, so
a consumer that drops state on `ErrNotFound` is never misled.

## Objects

One section per object: the type, the service that manages it, its `kascli`
resource and its fields. Fields marked *read-only* are reported by KAS and
ignored on writes.

### Domain and Subdomain

`Domains` (`List`, `Get`, `Update`) and `Subdomains` (`List`, `Get`, `Create`,
`Update`, `UpdatePath`, `Delete`). kascli: `domains` (`do`), `subdomains`
(`sub`).

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
- **`HTTPUser`** — the HTTP basic auth user. Its password is an argument of
  `Create` and `Update`, never part of the object. `Update` sends the pair
  only when the password is given, so a job read with `Get` keeps its stored
  password when written back.
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

### MailingList

`MailingLists` (`List`, `Get`, `Create`, `Update`, `Delete`). kascli:
`mailinglists` (`ml`).

- **`Name`** — KAS-assigned from the address, e.g. `announce-example-com` for
  `announce@example.com`; the identifier. `Create` returns it.
- **`Domain`** — the domain of the address, fixed at creation.
- **`Active`** — whether the list accepts mail.
- **`InProgress`** — *read-only*.
- **`Subscribers`**, **`RestrictPost`**, **`Config`** — the subscriber
  addresses, the addresses allowed to post (empty: anyone) and the complete
  Majordomo configuration file. Only `Get` reports them; `List` leaves them
  empty.

`Update` takes a `MailingListUpdate` whose fields are pointers, so that an
unset list stays as it is and an empty list removes all entries. KAS takes
both address lists newline-separated, so an address with a line break is
rejected.

### DirectoryProtection

`DirectoryProtection` (`List`, `Get`, `Create`, `Update`, `Delete`). kascli:
`directoryprotections` (`dp`), identified as `<path>:<user>`.

- **`Path`**, **`User`** — the protected directory and the login; together the
  identifier. A user name cannot contain a colon — htpasswd separates user and
  password with one.
- **`AuthName`** — the realm the login prompt shows; the KAS docs call it the
  comment. KAS requires it.
- **`InProgress`** — *read-only*.

`Update` sends realm and password together: the KAS docs list the password
as required on update, and it cannot be read back.

### SambaUser

`Samba` (`List`, `Get`, `Create`, `Update`, `UpdatePassword`, `Delete`).
kascli: `sambausers` (`smb`).

- **`Login`** — KAS-assigned, e.g. `s0123456`; the identifier.
- **`Path`** — the directory the network drive exposes.
- **`Comment`** — free text. KAS requires one.
- **`InProgress`** — *read-only*.

### Subaccount and AccountChange

`Accounts` (`List`, `Get`, `Create`, `Update`, `UpdatePassword`, `UpdateSSH`,
`Delete`). kascli: `accounts` (`acc`). Subaccounts exist below a main or
reseller account; `get_accounts` lists those of the logged-in account.

`Subaccount` is what KAS reports:

- **`Login`** — e.g. `w0123456`; the identifier.
- **`Comment`**, **`ContactMail`**.
- **`Limits`** — a map from `AccountLimit` (`LimitDomains`, `LimitWebspace`
  in MB, …; `AccountLimits()` lists them) to the allowed count.
  `get_accounts` names two limits differently from the requests
  (`max_mail_list`, `max_databases`); the map uses the request names.
- **`DirectoryProtection`**, **`SoftwareInstall`**, **`DNSSettings`**,
  **`KASAccessForbidden`**, **`SSHAccess`** — what the account may do.
- **`Logging`** (`LogFull`, `LogShort`, `LogNoIP`, `LogNone`), **`LogAge`**
  in days, **`Statistics`**, **`ShowPassword`**.
- **`TwoFactor`**, **`InProgress`**.

`AccountChange` creates or changes one. Its fields are pointers, and
`Limits` sends only the given entries, so an update changes exactly what is
set — a limit missing from a response is never sent back as 0. `Create`
also takes an `AccountHost` (`Kind` `"domain"`, `"subdomain"` or `""`, with
`Label`, `Parent` and `Path`) and the KAS and FTP passwords of the new
account. `UpdateSSH` turns SSH access on or off and replaces the public keys;
only a main account may call it.

### AccountSettings, AccountResource and ServerComponent

`Accounts` (`Settings`, `UpdateSettings`, `UpdateOwnPassword`, `Resources`,
`ServerInfo`). kascli: `accountsettings`, `accountresources`, `serverinfo`.

- **`AccountSettings`** — the logged-in account: the `Subaccount` settings
  plus `Superuser`, `Server`, `SSHKeys` and `SSHHostKeys`, the fingerprints of
  the server's SSH host keys. `UpdateSettings` takes the `AccountOptions`
  part of `AccountChange`. `UpdateOwnPassword` changes the KAS password; the
  client logs in with the new one from then on.
- **`AccountResource`** — per `AccountLimit`: `Max`, `Used`, `Created`,
  `Reserved`, `Free` and `Exceeded`. `Max` and `Free` are `-1` when
  unlimited.
- **`ServerComponent`** — one entry of the server information: a PHP version
  with the `FileExtension` that selects it (e.g. `php82`), the database
  server, or the operating system.

### Statistics

`Statistics` (`Space`, `SpaceUsage`, `Traffic`), read-only. kascli: `space`,
`spaceusage`, `traffic`.

- **`AccountSpace`** — the storage of an account in kB: `Webspace` in total
  and its parts `HTDocs`, `Chroot`, `Databases`, `MailAccounts`, against
  `MaxWebspace`. `Space(ctx, true)` reports the subaccounts instead.
- **`DirectoryUsage`** — the directories below one directory, in bytes, with
  the number of entries and whether each has subdirectories.
- **`Traffic`** — HTTP and FTP bytes and hits of a month. `Day` is `0` for the
  month total and set for the daily entries.

`Calculated` is when KAS last measured; storage figures lag behind by that.

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
err = client.Subdomains.Create(ctx, "go", "example.com", kasapi.HostSettings{
    Path:           "https://example.org",
    RedirectStatus: new(301),
    PHPVersion:     "8.4",
})

// An FTP login that may read and list, nothing else.
login, err := client.FTP.Create(ctx, kasapi.FTPUser{
    Path: "/logs/", Comment: "log reader", Read: true, List: true,
}, password)

// Any action without a typed wrapper:
ret, err := client.Exec(ctx, "get_softwareinstall", map[string]any{})
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
kascli create mailinglist --address announce@example.com
kascli update mailinglist announce-example-com --subscriber a@example.org,b@example.org
kascli create directoryprotection --path /example.com/admin/ --user alice --auth-name Admin
kascli update account w0123456 --limit subdomain=10,webspace=8192 --ssh-access
kascli get accountresources -o wide
kascli get traffic --year 2026 --month 10
kascli get spaceusage /example.com/

# raw escape hatch for any KAS action
kascli exec get_softwareinstall
kascli exec add_dns_settings zone_host=example.com. record_type=TXT \
    record_name=_test record_data=hello record_aux=0
```

Resource short names: `dns`, `do`, `sub`, `ma`, `mf`, `mfi`, `ml`, `ftp`,
`smb`, `dp`, `db`, `cj`, `ddns`, `acc`. `get` takes a name for `tls` (the
host), `mailinglists` (one list with its subscribers) and `spaceusage` (the
directory). Output formats: `table` (default), `wide`, `json`, `yaml`,
`name`; `--no-headers` for scripting.

Passwords are never flag values — they would land in the shell history and
the process list. Commands that set one ask for it at the terminal, or read
it from stdin with `--password-stdin`. `create account` needs two — the KAS
password, then the FTP password, one line each.

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
real account. It redacts the passwords and the TLS private key KAS returns in
`get_*` responses; `--raw` prints them. Request parameters follow the
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
make cover                 # coverage, fails below 95%
make check                 # everything CI runs (make tools installs the linters)
```

The suite covers the SOAP decoder (a fuzz test included), the auth handshake
with and without a one-time PIN, session reuse and re-authentication, flood
backoff, every method of every service with its request parameters and fault
handling, and every `kascli` command. `kasapitest` provides an in-process
fake KAS server for use in downstream tests without credentials; it answers
in the layout of a real response, request echo included. Set `Server.OTP` to
make it require a one-time PIN and `Server.FloodDelay` to change the delay
it reports.

## Extending

A new resource type is one file. Add a typed service over `Client.Exec`
mirroring the existing ones:

```go
type SymlinkService struct{ c *Client }

func (s *SymlinkService) Create(ctx context.Context, name, target string) error {
    _, err := s.c.Exec(ctx, "add_symlink", map[string]any{
        "symlink_name":   name,
        "symlink_target": target,
    })
    return err
}
```

Register it in `New()` (`c.Symlinks = &SymlinkService{c: c}`) and add tests
against `kasapitest`. The helpers in `params.go` cover the recurring
parts: `list` and `getOne` for `get_*` actions, `update` and `remove` for the
fault codes that mean "unchanged" or "absent".

KAS actions without a typed service are those that start an operation
rather than describe an object the API can read back:

- **`add_symlink`** — creates a symlink; KAS has no action to list or delete
  one.
- **`get_softwareinstall`**, **`add_softwareinstall`** — the installer
  catalog and a one-time installation.
- **`update_chown`** — sets the owner of a path once.
- **`reset_dns_settings`** — resets a zone to the KAS defaults.
- **`move_domain`**, **`move_subdomain`** — move a host between accounts.
- **`add_domain`**, **`delete_domain`**, **`get_topleveldomains`** —
  adding a domain can order one, so domain lifecycle stays in the panel.
- **`add_session`** — `KasAuth` creates the session; `Client.Logout` uses
  `delete_session`.

All of them run through `Client.Exec` and `kascli exec`.

## Compatibility

Releases follow semantic versioning. The promise covers the exported API of
`kasapi` and `kasapitest`; `internal/` and the `kascli` command line are
outside it. The library builds with the two most recent Go releases; the
`go` directive in `go.mod` names the older one, which is the minimum for
modules that import it.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
