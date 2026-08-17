# Integration tests

Single-node integration tests (`#[ignore]`-gated, run via `make integration`
as root on FreeBSD).

## Test images

All container images come from the **local test registry** at
`http://127.0.0.1:5000` (plain HTTP, loopback only) — tests must never pull
from Docker Hub. Full details — upstream sources, digests, registry service
setup, reset procedure, and the nginx image build — live in
[`docs/image-sources.md`](../../docs/image-sources.md).

Available references:

- `127.0.0.1:5000/satl-test/freebsd-runtime:15.1` — FreeBSD base (OCI index: freebsd/amd64 + arm64)
- `127.0.0.1:5000/satl-test/freebsd-nginx:latest` — nginx serving `satl-test-ok` on port 80, entrypoint runs foreground (`daemon off;`)
- `127.0.0.1:5000/satl-test/alpine:latest` — linux/amd64 (musl) for linuxulator tests
- `127.0.0.1:5000/satl-test/debian:stable-slim` — linux/amd64 (glibc) for linuxulator tests

Preflight check before running the suite:

```sh
service docker_registry status                     # registry is running
curl -s http://127.0.0.1:5000/v2/_catalog          # lists the four satl-test/ repos
```

If the registry is empty or missing images, re-seed per
`docs/image-sources.md` §3 and rebuild the nginx image with
`hack/images/build-freebsd-nginx.sh`.
