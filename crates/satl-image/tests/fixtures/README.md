# Fixture provenance

Real registry responses captured with `curl` from Docker Hub
(`registry-1.docker.io`) on 2026-08-09. Each file's sha256 matches the
registry-reported `Docker-Content-Digest` at capture time; the JSON is
byte-for-byte as served (do not reformat — tests verify digests).

| File | Origin | Digest (sha256 of file) |
|---|---|---|
| `alpine-index.json` | `docker.io/library/alpine:3.20` OCI image index (`application/vnd.oci.image.index.v1+json`); includes buildx attestation entries with `unknown/unknown` platforms | `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc` |
| `alpine-manifest.json` | linux/amd64 entry of the above (`application/vnd.oci.image.manifest.v1+json`) | `sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e` |
| `alpine-config.json` | config blob referenced by `alpine-manifest.json` | `sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731` |
| `busybox-list.json` | `docker.io/library/busybox:1.31` Docker manifest list (`application/vnd.docker.distribution.manifest.list.v2+json`) | `sha256:95cf004f559831017cdf4628aaf1bb30133677be8702a8c5f2994629f637a209` |
| `busybox-manifest.json` | linux/amd64 entry of the above (`application/vnd.docker.distribution.manifest.v2+json`, layers `application/vnd.docker.image.rootfs.diff.tar.gzip`) | `sha256:fd4a8673d0344c3a7f427fe4440d4b8dfd4fa59cfabbd9098f9eb0cb4ba905d0` |
