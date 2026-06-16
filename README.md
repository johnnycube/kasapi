# kasapi

[![CI](https://github.com/johnnycube/kasapi/actions/workflows/ci.yml/badge.svg)](https://github.com/johnnycube/kasapi/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/johnnycube/kasapi.svg)](https://pkg.go.dev/github.com/johnnycube/kasapi)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Go client for the all-inkl.com KAS hosting API. The KAS panel is exposed as
a SOAP service; this package wraps it in typed methods for the resources worth
automating — DNS records, mailboxes, forwards, subdomains — over a transport
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
- **Flood protection.** Every KAS response carries a `KasFloodDelay` that must
  elapse before the next request. The client honors it, serializes calls, and
  retries `flood_protection` faults with bounded backoff. Large batches apply
  slowly by design — that is the API's constraint, not the client's.
- **`Client.Exec`.** One entry point that runs any KAS action with raw
  parameters. Every typed service is a thin wrapper over it, and it is the
  escape hatch for actions that have no wrapper yet.
- **Typed services.** `DNS`, `Mail` (accounts and forwards), `Subdomains`,
  `Domains` (read-only). Adding one is a single file over `Exec`.

TLS 1.2 is the floor on the default HTTP client, responses are size-limited,
and the client is safe for concurrent use — calls serialize because the API
requires it.

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

// Any action without a typed wrapper:
ret, err := client.Exec(ctx, "get_ftpusers", map[string]any{})
```

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
kascli get domains
kascli get dnsrecords --zone example.com -o wide
kascli get mailaccounts -o yaml
kascli get subdomains --no-headers
kascli get dns --zone example.com -o name      # dnsrecord/12345
kascli --context prod get mailforwards -o json
kascli delete dnsrecord 12345

# raw escape hatch for any KAS action
kascli exec get_ftpusers
kascli exec add_dns_settings zone_host=example.com. record_type=TXT \
    record_name=_test record_data=hello record_aux=0
```

Resource short names: `dns`, `ma`, `mf`, `sub`, `do`. Output formats: `table`
(default), `wide`, `json`, `yaml`, `name`; `--no-headers` for scripting.

Credentials resolve like kubectl: `--context` selects the context, otherwise
`current-context` applies. `KAS_LOGIN` / `KAS_PASSWORD` override the context's
values, and a missing password is prompted for interactively (echo disabled
where the terminal allows it). Storing a password in the config file is
optional and warned about — the environment variable or the prompt avoid it.

The raw `exec` verb doubles as the way to confirm KAS field names against a
real account before relying on the typed services. The mail and subdomain
parameter names follow the KAS panel documentation and carry verification
notes in the source until checked against live responses.

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

The suite covers the SOAP decoder, the auth handshake, session reuse and
re-authentication, flood backoff, and the field mappings of every service.
`kasapitest` provides an in-process fake KAS server for use in downstream
tests without credentials.

## Extending

A new resource type is one file. Add a typed service over `Client.Exec`
mirroring the existing ones:

```go
type FTPService struct{ c *Client }

func (s *FTPService) Create(ctx context.Context, user, password, path string) error {
    _, err := s.c.Exec(ctx, "add_ftpuser", map[string]any{
        "ftp_user":     user,
        "ftp_password": password,
        "ftp_path":     path,
    })
    return err
}
```

Register it in `New()` (`c.FTP = &FTPService{c: c}`) and add tests against
`kasapitest`. The KAS actions for the common cases already exist:
`get_ftpusers` / `add_ftpuser` / …, `get_databases` / `add_database` / …,
`get_cronjobs` / `add_cronjob` / …

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
