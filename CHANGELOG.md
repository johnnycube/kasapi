# Changelog

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
