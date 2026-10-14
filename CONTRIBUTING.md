# Contributing to kasapi

Contributions are welcome. A few rules keep the licensing and quality clear.

## License of contributions

The project is Apache-2.0. By submitting a contribution you agree it is licensed
under the same terms — this also follows from Section 5 of the Apache License.
There is no CLA.

All commits must be signed off (`git commit -s`), which adds a
`Signed-off-by: Your Name <you@example.com>` trailer and asserts the
[Developer Certificate of Origin](https://developercertificate.org/): that you
have the right to submit the change under the project license.

## File headers

Every Go file carries this header; add it to new files:

```go
// Copyright 2026 The kasapi Authors
// SPDX-License-Identifier: Apache-2.0
```

## Working rules

- The core `kasapi` package is standard-library-only by design — do not add
  dependencies there. `cmd/kascli` and `internal/` may use well-maintained
  community libraries; they currently use cobra, `gopkg.in/yaml.v3` and
  `golang.org/x/term`.
- `make check` must pass: format, golangci-lint, `go vet`, tests with the race
  detector, a 95% coverage floor, govulncheck, the license allowlist, a tidy
  module graph, gitleaks, the build and fleetlint. CI runs the same target.
  `make tools` installs the pinned tools; gitleaks comes from its own release.
- `prek install` sets up the git hooks in `.pre-commit-config.yaml`: hygiene
  and secret checks and conventional commit messages on commit, `make check`
  before push.
- A new KAS use case is a typed service over `Client.Exec` with tests against
  the `kasapitest` fake server, mirroring the existing services.
- Verify KAS request/response field names with `kascli exec <action>` against a
  real account where possible. Where a name is unverified, keep its verification
  note rather than removing it.

## Prose

Documentation follows [STYLE.md](../STYLE.md): declarative, on point, no
marketing words, explain the why.
