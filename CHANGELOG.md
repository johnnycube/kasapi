# Changelog

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
