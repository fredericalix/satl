# Test image sources

Resolves `docs/architecture.md` §17 open question #5: *where do FreeBSD OCI
images for tests come from?*

**Decision:** use the FreeBSD project's official OCI images from Docker Hub
(`docker.io/freebsd/*`), mirrored into a **local, loopback-only registry** on
the dev machine, plus one locally built `freebsd-nginx` image on top of
`freebsd-runtime`. Integration tests reference `127.0.0.1:5000` only — never
Docker Hub — so they are immune to Hub outages, rate limits, and upstream tag
churn.

Surveyed / seeded on 2026-08-09 on the FreeBSD 15.1-RELEASE-p2 dev host.

## 1. Upstream survey: the `freebsd/` org on Docker Hub

The FreeBSD project publishes pkgbase-derived OCI images (no
`freebsd-base`/`freebsd-minimal` repos exist despite older docs; the actual
repositories are):

| Repository | Contents | Relevant tags |
|---|---|---|
| `freebsd/freebsd-runtime` | `FreeBSD-runtime` pkgbase set: core userland (`/bin`, `/sbin`, `/lib`, `/rescue`), pkg bootstrap, rc. One ~12.6 MB gzip layer. **Our base image.** | `15.1`, `14.3`, `14.2`, betas/RCs, `15.snap`, `16.snap` |
| `freebsd/freebsd-static` | Near-empty image for static binaries | `15.1`, `14.3`, … |
| `freebsd/freebsd-dynamic` | Minimal image for dynamically linked binaries (clibs only) | `15.1`, `14.3`, … |
| `freebsd/freebsd-notoolchain` | Larger userland without compiler | `15.1`, … |
| `freebsd/freebsd-toolchain` | Userland + toolchain (big) | `15.1`, … |
| `freebsd/freebsd` | Empty placeholder, **no tags** | — |

**Chosen tag: `freebsd-runtime:15.1`** — exact userland match for our 15.1
hosts. (A 14.x userland in a jail on a 15.1 kernel is also supported — older
userland on a newer kernel is the supported direction — so `14.3` is a valid
fallback and useful for version-skew testing, but with `15.1` published there
is no reason to default to it.)

Digests as observed 2026-08-09 (upstream tags are mutable — rebuilt for patch
releases — so these pin what we mirrored, they are not eternal):

```
docker.io/freebsd/freebsd-runtime:15.1
  index (OCI image index):  sha256:d9beae9d6b13999ef697507b2144afd57cb1e2b4aedf0cefb94f9f1afde34604
  freebsd/amd64 manifest:   sha256:7673c9e4106e295d22da6b91b6b7570dd48814e0d71811cd9d0ea1ae5be3ef96
  freebsd/arm64 manifest:   sha256:6b3b15d0fc37ca45a2636f3aaea695bfb42cc1b02c895ee939bdfef87521fbd7
  amd64 layer (tar+gzip):   sha256:78d645ce98ae2543c092fbe626468f4bea0adf1282d75b86546a10f43ea438ea (12,577,610 B)
  amd64 config:             sha256:90c4936754299295608ecf3e932f20611790420b3149e5b2b74b047c473f6a0d (Cmd: /bin/sh)

docker.io/freebsd/freebsd-runtime:14.3
  index:                    sha256:3a5ffe995405b5f6300797b38d87328a267bbeeb550d3707c9c5e0a76827a978

docker.io/library/alpine:latest        (linux/amd64 + 7 other platforms)
  index:                    sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

docker.io/library/debian:stable-slim   (linux/amd64 + 7 other platforms)
  index:                    sha256:0d97731c59efdde181e19c4a5ec22d16e9eefcb73175598b9b7bae712c7214eb
```

Notes:
- `platform."os.version"` is **not set** in the freebsd indexes or configs —
  platform selection can only match on `os`/`architecture`.
- The freebsd images are plain two-entry OCI indexes; alpine/debian indexes
  also carry `unknown/unknown` attestation manifests (kept by our mirror since
  we copy with `--all`; platform selection must skip `os == "unknown"`).

## 2. Local registry (dev machine)

Package `docker-registry` (registry 2.8.3) from pkg, plus `skopeo` (1.22) for
copying. Quirks of the FreeBSD package worth knowing:

- rc.d script: `/usr/local/etc/rc.d/docker_registry` → service name is
  **`docker_registry`** (underscore), rcvar `docker_registry_enable`.
  Inside the script `name=registry`, so `service docker_registry status`
  reports "registry is running".
- Config knob: `docker_registry_config`, default
  `/usr/local/etc/docker-registry/config.yml` (a `.sample` ships with
  htpasswd auth enabled — we do not use it).
- Log: `docker_registry_logfile`, default `/var/log/docker-registry.log`.
  Runs under daemon(8), pidfile `/var/run/docker-registry.pid`.

Our `/usr/local/etc/docker-registry/config.yml`: listens on
**`127.0.0.1:5000`** (loopback only), filesystem storage rooted at
**`/var/db/satl-test-registry`** (deliberately *not* under `zroot/satl` —
this is test infrastructure, not satld state), blob deletion enabled, **no
auth, no TLS**. Because it is plain HTTP, every skopeo command against it
needs `--src-tls-verify=false` / `--dest-tls-verify=false`, and satld/tests
must treat `127.0.0.1:5000` as an insecure (HTTP) registry.

Setup (already done on the dev host; repeat on a fresh machine):

```sh
sudo pkg install -y docker-registry skopeo
# write /usr/local/etc/docker-registry/config.yml as described above
sudo sysrc docker_registry_enable=YES
sudo service docker_registry start
curl http://127.0.0.1:5000/v2/          # -> {}
```

Reset to empty:

```sh
sudo service docker_registry stop
sudo rm -rf /var/db/satl-test-registry/*
sudo service docker_registry start
# then re-seed (below) and re-run hack/images/build-freebsd-nginx.sh
```

## 3. Seeding (mirror upstream → local)

`skopeo copy --all` copies the *entire* index (all platforms + attestation
manifests), so the local top-level digest is byte-identical to upstream —
verified for all three mirrored images.

```sh
skopeo copy --all --dest-tls-verify=false \
    docker://docker.io/freebsd/freebsd-runtime:15.1 \
    docker://127.0.0.1:5000/satl-test/freebsd-runtime:15.1
skopeo copy --all --dest-tls-verify=false \
    docker://docker.io/library/alpine:latest \
    docker://127.0.0.1:5000/satl-test/alpine:latest
skopeo copy --all --dest-tls-verify=false \
    docker://docker.io/library/debian:stable-slim \
    docker://127.0.0.1:5000/satl-test/debian:stable-slim
```

## 4. The `freebsd-nginx` test image

Built by **`hack/images/build-freebsd-nginx.sh`** (idempotent, re-execs via
sudo, cleans up after itself). Rebuild any time with:

```sh
hack/images/build-freebsd-nginx.sh
```

Pipeline: pull `satl-test/freebsd-runtime:15.1` (freebsd/amd64) from the
local registry into an OCI layout → untar layers in order → `pkg -o
ABI=FreeBSD:15:amd64 --rootdir <rootfs> install -y nginx` → minimal
`nginx.conf` + static `satl-test-ok` index page → `chroot rootfs ldconfig` →
`chroot rootfs nginx -t` gate → repack as a single squashed tar+gzip layer
with hand-built OCI config/manifest (os=freebsd, architecture=amd64,
`Entrypoint: ["/usr/local/sbin/nginx","-g","daemon off;"]`, ExposedPorts
80/tcp) → `skopeo copy oci: → docker://127.0.0.1:5000/satl-test/freebsd-nginx:latest`
→ inspect-and-assert platform fields.

Findings / quirks (learned once, don't relearn):

- **`pkg --rootdir` just works** with the host's pkg (2.7.5): no need to copy
  `/usr/share/keys` into the rootfs, no `-o REPOS_DIR` — host repo config and
  trust anchors are used; `-o ABI=` pins the target ABI. It resolves deps
  (pcre2) and reuses the `www` user already present in the base image's
  `/etc/passwd`. First run needs network to the FreeBSD pkg mirror; repo
  catalogs and the pkg cache land *inside* the rootfs (`/var/db/pkg/repos`,
  `/var/cache/pkg`) and are stripped before repacking (`local.sqlite` is
  kept, so `pkg info` works inside the container).
- **`ld-elf.so.hints` gotcha:** jails never run rc, and rc is what runs
  ldconfig at boot. Without `/var/run/ld-elf.so.hints` the runtime linker
  does not search `/usr/local/lib`, and nginx dies with
  `Shared object "libpcre2-8.so.0" not found`. The build bakes the hints file
  via `chroot rootfs /sbin/ldconfig /lib /usr/lib /usr/local/lib`. Any future
  image built on freebsd-runtime with pkg needs the same step.
- **schg file flags:** the upstream runtime layer records `schg` on ~10 files
  (`/sbin/init`, `/libexec/ld-elf.so.1`, `/lib/libc.so.7`, …). Extracting as
  root restores them, so `rm -rf` of an unpacked rootfs fails until
  `chflags -R noschg`. Relevant to satl-storage too whenever it removes
  unpacked files with rm (`zfs destroy` of a clone is unaffected).
- **Not bit-reproducible:** the layer embeds a build timestamp and floating
  package versions (nginx 1.30.4, pcre2 10.47 at time of writing) —
  reference this image **by tag**, never by pinned digest.

Env overrides: `SATL_TEST_REGISTRY`, `SATL_BASE_REF`, `SATL_DEST_REF`,
`SATL_PKG_ABI` (e.g. to build a 14.3-based variant).

## 5. What integration tests reference

| Reference | Platform(s) | Purpose |
|---|---|---|
| `127.0.0.1:5000/satl-test/freebsd-runtime:15.1` | freebsd/amd64, freebsd/arm64 (index) | base FreeBSD image; manifest-list platform selection; `satl run … /bin/sh` |
| `127.0.0.1:5000/satl-test/freebsd-nginx:latest` | freebsd/amd64 (single manifest) | M1 DoD: `satl run -d -p 8080:80 …` then `curl` → body `satl-test-ok` |
| `127.0.0.1:5000/satl-test/alpine:latest` | linux/amd64 + others (index) | linuxulator; linux/amd64 fallback selection from a manifest list |
| `127.0.0.1:5000/satl-test/debian:stable-slim` | linux/amd64 + others (index) | linuxulator, glibc-based (alpine is musl — exercise both) |

Scope: this covers the single-node dev machine. The three OVH cluster VMs
(`tests/cluster/inventory.toml`) will need the same seeding — same packages,
same steps — when M3 cluster tests start pulling images; that wiring is out of
scope here.

## 6. `satl build` (M6f): images without the hand-written scripts

The `hack/images/build-*.sh` scripts are replaced by `satl build`, which reads
a `Satlfile` — the pkg-shaped subset of Dockerfile verbs:

```text
FROM 127.0.0.1:5000/satl-test/freebsd-runtime:15.1
PKG postgresql17-server
EXPOSE 5432/tcp
ENTRYPOINT ["/usr/local/bin/postgres", "-D", "/var/db/postgres/data"]
```

`FROM` (one, mandatory), `PKG`, `COPY`, `RUN`, `ENV`, `LABEL`, `WORKDIR`,
`EXPOSE`, `ENTRYPOINT`/`CMD` (JSON exec form only — the shell form would
promise a shell the image may not have).

`COPY` and `RUN` arrived in M7b, with two deliberate shapes:

- the **build context is the Satlfile's own directory** — no positional
  `PATH` argument. Sources are context-relative; `..`, absolute paths and
  symlink escapes are refused, and a directory source copies its *contents*,
  as Docker's COPY does. A relative destination resolves against `WORKDIR`.
- **`RUN` executes in a `chroot` of the assembled rootfs**, on the build
  host's kernel — `/bin/sh -c` with the Satlfile's `ENV` and `WORKDIR`, and
  the host's `resolv.conf` if the image has none (the controller rewrites it
  per container at start anyway). Build on the FreeBSD major you deploy.

All `PKG` steps run before the first `COPY`/`RUN` (a package must be
installed before a step can use it: `PKG node24`, then `RUN npm …`); the
`COPY`/`RUN` steps themselves execute in file order.

The pipeline is what the scripts proved, moved into `crates/satl-build`:
pull the base into the local content store, unpack its layers into a temp
rootfs (`satl-storage`'s unpacker, diff IDs verified), `chflags -R noschg`
(the base layer carries schg flags), `pkg -o ABI=... --rootdir install`,
drop the pkg residue (repo catalogs and cache; `local.sqlite` stays so
`pkg info` works), bake `/var/run/ld-elf.so.hints` with `chroot ldconfig`
(no rc in a jail — without the hints, pkg-installed binaries die on missing
shared objects), run the COPY/RUN steps, and repack.

Since M8b the repack is **multi-layer with an incremental cache**: the image
is the base's layers plus one layer per mutating step (the PKG group, each
COPY, each RUN), diffed from the rootfs between steps with OCI whiteouts
for deletions. Each step's layer is content-addressed in
`/var/db/satl/build-cache/` — key = the parent chain ID plus the step's
inputs (sorted packages, COPY source content hashes, the RUN command and
env) — so a rebuild with no changed input executes nothing at all, and a
changed file only re-runs the steps *after* it. A cache hit still applies
the cached layer to the rootfs (a later miss needs the real tree), and the
unpacker verifies its diff ID, so a corrupt blob is a loud error, not a
poisoned image. `--no-cache` disables it; `--cache-dir` relocates it. The
cache's honesty caveat is Docker's own: a step's outputs are assumed to
depend only on its inputs — a `RUN` that reads the network is cached on
the command string, and `--no-cache` is how you say "not this time".

M8c adds **`FROM scratch` and multi-stage builds**. `FROM scratch` is the
empty base — the image is exactly its step layers, nothing else. Several
`FROM` lines define several stages, named with `AS`:

```text
FROM freebsd-runtime:15.1 AS builder
PKG llvm
COPY src/ /src/
RUN make -C /src

FROM scratch
COPY --from=builder /src/out /usr/local/bin/out
ENTRYPOINT ["/usr/local/bin/out"]
```

Every stage builds fully (a failure in any stage fails the build), and only
the last one is repacked — which is the whole point: the toolchain stays in
the builder stage. `COPY --from=<stage>` reads the earlier stage's finished
rootfs, by alias or by index (`--from=0`), case-insensitive; `..` and
symlink escapes are refused the same as context sources, a directory copies
its contents, and a cross-stage copy is cache-keyed on the copied content,
so a changed builder output invalidates the final stage. Copying out of an
*image* (`COPY --from=registry/x:1`) is refused plainly — name or index a
stage instead.

```sh
sudo satl build -t 127.0.0.1:5000/satl-test/freebsd-postgres:latest
```

Notes:

- it runs **on the daemon's host**, client-side, against the local content
  store (`--store` to point elsewhere) — and it needs root (pkg's rootdir,
  the ldconfig chroot, the store itself);
- the image lands in *that node's* store. For several nodes, build on each,
  or tag the result for a shared registry and push it (`satl tag` +
  `satl push` — pushing needs the reference to name the target registry),
  then pull normally on the other nodes;
- this is not Docker's `POST /build`: a Satlfile is not a Dockerfile and
  the build does not happen in the daemon (docs/api-compat.md).
