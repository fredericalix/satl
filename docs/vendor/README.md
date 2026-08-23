# Vendored assets for `docs/api.html`

`docs/api.html` renders `docs/openapi.js` with Redoc, and it has to work from a
`file://` URL on a machine with no network -- that is the whole reason these
files are checked in rather than pulled from a CDN at page load.

## `redoc.standalone.js`

| | |
|---|---|
| Upstream | <https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js> |
| Version | Redoc 2.5.3 (the `latest` bundle, `last-modified: Fri, 29 May 2026 10:07:37 GMT`) |
| Size | 1097271 bytes |
| sha256 | `1320f442151c57c447d3b70c7ffc6c4f86d08464020fe34c8cc5d3164e9944f0` |
| Fetched | 2026-08-19 |
| License | MIT -- `redoc.LICENSE` (Redoc itself) and `redoc.standalone.js.LICENSE.txt` (the bundled third-party notices the file's own header points at) |

Re-fetch and verify:

```sh
curl -fsSL -o docs/vendor/redoc.standalone.js \
    https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js
sha256 docs/vendor/redoc.standalone.js
```

`latest` is a moving target: a re-fetch that changes the digest is a version
bump, and this table has to move with it.

These are data files, not sources. `make check`'s `license-check` scans only
`crates`/`tests` `*.rs`, `proto/*.proto`, `rc.d/satld`, `Makefile`, `*.sh` and
`hack/**/*.c`, so nothing here needs an SPDX header; `packaging/pkg-plist.in`
ships binaries, rc.d, the sample config, man pages and the license directory,
none of them under `docs/`, so nothing here reaches a package either.
