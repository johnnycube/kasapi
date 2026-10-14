# Architecture

kasapi is a Go client for the all-inkl.com KAS SOAP API and `kascli`, a
kubectl-style command line built on it. This page describes the components,
their boundaries, how a request flows through them, and the decisions that
shaped them. The services and their KAS actions are listed in the README
under [Design](../README.md#design).

## Components

- **`kasapi` (repository root)** — the library. Transport (`soap.go`,
  `auth.go`, `flood.go`), the generic entry point `Client.Exec`
  (`client.go`), shared helpers for parameters and fault codes (`params.go`,
  `convert.go`) and one typed service per resource (`dns.go`, `mail.go`,
  `subdomain.go`, `domain.go`, `host.go`, `tls.go`, `ftp.go`, `database.go`,
  `cronjob.go`, `ddns.go`).
- **`kasapitest`** — an in-process fake KAS server. It speaks the same SOAP
  envelope, checks credentials and the one-time PIN, and hands each action to
  a handler the test supplies. Downstream modules use it to test without an
  account.
- **`internal/kasconfig`** — the kubeconfig-style context file of `kascli`
  (`~/.config/kasapi/config` or `$KASCONFIG`), written with mode 0600.
- **`cmd/kascli`** — the CLI. Cobra commands for `get`, `create`, `update`,
  `delete`, `exec`, `api-resources` and `config`; `get` and `delete` dispatch
  through per-resource tables, output goes through one printer for table,
  wide, JSON, YAML and name.

## Boundaries

The library imports the standard library only — consumers such as
terraform-provider-allinkl and cert-manager-webhook-all-inkl get no transitive
dependencies from it. `cmd/kascli` and `internal/` may use community libraries
(cobra, `gopkg.in/yaml.v3`, `golang.org/x/term`); nothing in the library
imports them.

Typed services never talk SOAP. Each one builds a parameter map and calls
`Client.Exec`, then maps the generic result onto its structs. A KAS action
without a service is reachable through the same `Exec`, from code and from
`kascli exec`.

## Request flow

1. A service method validates its input and builds the request parameters.
   Invalid input fails before any request is sent.
2. `Client.Exec` takes the client mutex. Calls serialize because the API
   requires it: every response carries a `KasFloodDelay` the next request
   must wait for.
3. The client waits out the flood window, then creates or reuses a session.
   `KasAuth` returns a token; `Config.OTP` supplies the PIN on each handshake
   of a two-factor account.
4. `soapCall` posts the JSON payload inside a SOAP envelope, reads a
   size-limited response and decodes it into a generic tree: apache maps become
   `map[string]any`, SOAP-ENC arrays `[]any`, scalars `string`.
5. A SOAP fault becomes an `*APIError`. An expired session triggers one
   re-authentication and a retry; `flood_protection` is retried with bounded
   backoff. `params.go` maps the fault codes that mean "absent" to
   `ErrNotFound` and `nothing_to_do` to success.
6. The service converts the generic value into its typed result.

## Decisions

- **One generic decoder instead of a type per response.** KAS answers with
  SOAP-encoded PHP structures whose shape varies by action. Decoding into a
  generic tree and converting per service keeps the transport small and makes
  a new service a single file.
- **Serialized calls inside the client.** The flood delay is per account, so
  parallel calls would only collide with it. The client owns the wait, so
  callers do not need to know the rule.
- **Secrets are write-only.** KAS returns passwords and the TLS private key in
  `get_*` responses. The services do not map them, so they cannot leak into
  logs, Terraform state or `kascli get -o yaml`.
