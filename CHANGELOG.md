# Changelog

## Unreleased

Seven additions to the library, write verbs for `kascli`, and tests for every
function. Two behaviors change for existing callers; both are listed under
"Changed".

Library:

- **Host settings.** `HostSettings` carries document root, redirect status,
  PHP version and the active flag for domains and subdomains.
  `Subdomains.CreateWithSettings`, `Subdomains.Update` and `Domains.Update`
  send the set fields only. `Subdomain` and `Domain` report the same settings
  plus `PHPDeprecated`, `InProgress` and the TLS state. `Subdomains.Create`
  sends no PHP version, so the host gets the KAS default, which the API
  documents as 7.1 — `CreateWithSettings` chooses one.
- **TLS.** `TLS.Update` installs a certificate and sets the HTTPS redirect
  and HSTS (`update_ssl`); `TLS.Get` reads the state of a host. Certificate
  and key are validated before the request: they must form a pair and name
  the host. The API has no parameter that requests a Let's Encrypt
  certificate — that switch exists in the KAS panel only.
  `HostTLS.LetsEncrypt` reports whether a host uses one.
- **Two-factor authentication.** `Config.OTP` supplies the one-time PIN,
  sent as `session_2fa` on every session handshake.
- **Mail.** `UpdateResponder` sets the autoresponder, with an optional time
  window. `UpdateState`, `UpdateAllowNets` and `UpdateWebmailAutologin`
  control activation, allowed clients and the panel's webmail login.
  `AvailableFilters`, `SetFilters` and `DeleteFilters` manage the standard
  filters. `MailAccount` reports all of it; `CreateAccount` sends an active
  responder and the allowed clients.
- **New services.** `FTP`, `Databases`, `Cronjobs` and `DDNS`, each with
  `List`, `Get`, `Create`, `Update` and `Delete`; `UpdatePassword` where the
  object has a password.
- `DNSRecord.Deletable`, `MailForward.SpamFilters` and
  `MailForward.InProgress`.
- `kasapitest.Server.OTP` makes the fake server require a one-time PIN;
  `Server.SessionLifetime` records the requested session lifetime.

CLI:

- Verbs `create` and `update` for every resource that has them; `update`
  changes only the flags that are given. `kascli api-resources` lists the
  verbs per resource.
- Resources `ftpusers`, `databases`, `cronjobs`, `ddnsusers`, `mailfilters`
  and `tls`. `get domains` and `get subdomains` show redirect, PHP version
  and TLS state in `-o wide`; `get mailaccounts -o wide` shows state, allowed
  clients and filters.
- Passwords are read from the terminal or, with `--password-stdin`, from
  stdin. No command takes one as a flag value.
- `--otp`, `KAS_OTP` and `config set-context --two-factor` for accounts with
  two-factor authentication.

Changed:

- Update methods treat the fault `nothing_to_do` as success. KAS sends it
  when an update matches the current state; returning it as an error made
  every idempotent caller handle it. This covers the existing `DNS.Update`,
  `Mail.Update*`, `Mail.UpdateForward` and `Subdomains.UpdatePath`.
- `Get` methods filter on the server (`record_id`, `domain_name`,
  `subdomain_name`, `mail_login`, `mail_forward`) instead of reading the full
  list. They still match the entry they asked for, so a response that
  ignores the filter cannot return the wrong object.
- List methods treat the fault `empty_list` as an empty result.
- `Subdomains.UpdatePath` and `Subdomains.Delete` recognize the API's
  `subdomain_doenst_exist` as `ErrNotFound`.
- `SessionLifetime` is capped at 30000 seconds, the documented maximum,
  instead of 3600. The default stays 1800.
- `kascli delete domain` answers "cannot be deleted" instead of "read-only":
  domains now have `update`.

Dependencies:

- `github.com/spf13/pflag` 1.0.10, now a direct dependency of `cmd/kascli`.
- Renovate proposes upgrades of the `go` directive, gated by approval in the
  Dependency Dashboard. Its default is not to propose them.

## v0.2.0 — 2026-07-16

Mail sender aliases, and two parameter fixes verified against the KAS API
documentation. KAS has no standalone mail-alias objects: sender aliases are a
mailbox property (`mail_sender_alias`), receiving aliases are forwards.

- `MailAccount.SenderAliases` and `MailService.UpdateSenderAliases`: the
  addresses a mailbox may use in the FROM header when sending. Read from
  `get_mailaccounts`, set on create and update. `kascli get mailaccounts`
  shows them in `-o wide` and as `senderAliases` in json/yaml.
- Fixed: copy addresses are sent as the single comma-separated `copy_adress`
  parameter, not `copy_adress_0..N`.
- Fixed: forward targets are sent as `target_0..target_9` (0-indexed), not
  `target_1..N`, which silently dropped one of ten targets. Forwards now
  reject more than 10 targets, and account actions validate copy addresses
  and sender aliases before calling the API.

## v0.1.0 — 2026-06-16

First release.

Library (package `kasapi`, standard library only):

- `KasAuth` sessions (SHA1 or plain), transparent re-authentication,
  flood-protection-aware with bounded retries, TLS 1.2 floor.
- `Client.Exec` for any KAS action; typed services for DNS, mail accounts, mail
  forwards, subdomains, and domains (read-only).
- `kasapitest`: an in-process fake KAS server for downstream tests.

CLI (`cmd/kascli`, kubectl-style, built on cobra):

- Contexts in a kubeconfig-like file (`~/.config/kasapi/config`, `$KASCONFIG`):
  `config get-contexts | current-context | use-context | set-context |
  delete-context | view`. `view` redacts passwords; `--raw` shows them.
- Verbs `get`, `delete`, `exec`, `api-resources`, `version`. Resource short
  names and output formats `table | wide | json | yaml | name`, `--no-headers`.
- `--help` for every command and `completion` for bash/zsh/fish/powershell.
- The password prompt disables terminal echo via `golang.org/x/term`; config and
  `-o yaml` use `gopkg.in/yaml.v3`.

Known limitations:

- Mail and subdomain field names follow the KAS panel documentation; verify them
  once against a real account. Verification notes are in the source.
