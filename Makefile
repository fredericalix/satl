# SPDX-License-Identifier: BSD-2-Clause
# SatL — FreeBSD make(1) (bmake) compatible.

CARGO?=		cargo
PREFIX?=	/usr/local
DESTDIR?=

.PHONY: check build release install integration cluster-test clean license-check

check: license-check
	${CARGO} fmt --all --check
	${CARGO} clippy --workspace --all-targets -- -D warnings
	${CARGO} test --workspace

# Every source file carries its SPDX header as line 1 (line 2 after a
# shebang). This is the only gate — there is no CI. Fixture data files
# (captured command output the parsing tests diff byte-for-byte) are data,
# not source, and stay headerless.
license-check:
	@missing=0; \
	for f in `find crates tests -name '*.rs' -not -path '*/target/*' -not -path '*/fixtures/*'` \
	    proto/*.proto rc.d/satld Makefile \
	    `find . -name '*.sh' -not -path './target/*' -not -path './.git/*'` \
	    `find hack -name '*.c' -not -path './target/*'`; do \
	    if ! head -2 "$$f" | grep -q 'SPDX-License-Identifier'; then \
	        echo "license-check: $$f lacks an SPDX header"; missing=1; \
	    fi; \
	done; \
	[ "$$missing" -eq 0 ]

build:
	${CARGO} build --workspace

release:
	${CARGO} build --workspace --release

# `install` needs root to write under ${PREFIX}, so its build runs as root too —
# and `sudo make install` used to build into target/release, leaving root-owned
# artifacts there that broke every later unprivileged `make check`/`make build`
# with "Operation not permitted". Same disease `integration` below cures the same
# way: root builds into a target directory of its own, so the one an unprivileged
# build and tests/cluster/deploy.sh use stays owned by the developer.
#
# The cost is that `sudo make install` does not share `make release`'s artifacts
# and compiles again. That is the trade integration already accepted, and the
# alternative — an install target that does not build — would silently install
# whatever stale binary happened to be lying around.
INSTALL_TARGET_DIR?=	target/install

install:
	${CARGO} build --workspace --release --target-dir ${INSTALL_TARGET_DIR}
	install -d ${DESTDIR}${PREFIX}/bin ${DESTDIR}${PREFIX}/sbin
	install -d ${DESTDIR}${PREFIX}/etc/rc.d ${DESTDIR}${PREFIX}/etc/satl
	install -m 0755 ${INSTALL_TARGET_DIR}/release/satl ${DESTDIR}${PREFIX}/bin/satl
	install -m 0755 ${INSTALL_TARGET_DIR}/release/satld ${DESTDIR}${PREFIX}/sbin/satld
	install -m 0755 rc.d/satld ${DESTDIR}${PREFIX}/etc/rc.d/satld
	install -m 0644 etc/satld.toml.sample ${DESTDIR}${PREFIX}/etc/satl/satld.toml.sample

# A distributable package: `make package` writes dist/satl-<version>.pkg,
# installable anywhere with `pkg add` — no repository needed. The staging
# layout mirrors `install` exactly, so the package and a source install put
# the same files in the same places. The ocijail dependency version is read
# from the package repo at build time. CHECKSUM.SHA512 is written next to the
# package in sha512sum(1) format, so a consumer verifies it with
# `sha512sum -c CHECKSUM.SHA512` from inside dist/. It names only the package
# this run built, and is rewritten on every `make package`.
PKG_VERSION!=	awk -F'"' '/^version = / { print $$2; exit }' Cargo.toml
PKG_STAGE=	target/package
DISTDIR?=	${.CURDIR}/dist

package: release
	rm -rf ${PKG_STAGE}
	mkdir -p ${PKG_STAGE}/root${PREFIX}/bin ${PKG_STAGE}/root${PREFIX}/sbin \
	    ${PKG_STAGE}/root${PREFIX}/etc/rc.d ${PKG_STAGE}/root${PREFIX}/etc/satl \
	    ${DISTDIR}
	install -m 0755 target/release/satl ${PKG_STAGE}/root${PREFIX}/bin/satl
	install -m 0755 target/release/satld ${PKG_STAGE}/root${PREFIX}/sbin/satld
	install -m 0755 rc.d/satld ${PKG_STAGE}/root${PREFIX}/etc/rc.d/satld
	install -m 0644 etc/satld.toml.sample \
	    ${PKG_STAGE}/root${PREFIX}/etc/satl/satld.toml.sample
	sed -e 's/@VERSION@/${PKG_VERSION}/' \
	    -e "s/@ABI@/`pkg config ABI`/" \
	    -e "s/@OCIJAIL_VERSION@/`pkg rquery %v ocijail | tail -1`/" \
	    packaging/+MANIFEST.in > ${PKG_STAGE}/+MANIFEST
	pkg create -M ${PKG_STAGE}/+MANIFEST -r ${PKG_STAGE}/root \
	    -p packaging/pkg-plist -o ${DISTDIR}
	cd ${DISTDIR} && sha512sum satl-${PKG_VERSION}.pkg > CHECKSUM.SHA512
	@echo "wrote ${DISTDIR}/satl-${PKG_VERSION}.pkg"
	@echo "wrote ${DISTDIR}/CHECKSUM.SHA512"

# Root + FreeBSD required; tests are #[ignore]-gated. Run as root:
#     sudo make integration
#
# Two flags here are load-bearing, not preferences:
#
# --test-threads=1: these tests mutate global host state (jails, network
#   interfaces, ZFS datasets, pf anchors) and audit it for leftovers
#   afterwards. Run in parallel, one test's interfaces turn up in another
#   test's leftover audit and fail it spuriously.
#
# a separate target dir: cargo invoked under sudo writes root-owned artifacts,
#   which then break every unprivileged `make check`/`make build` until the
#   tree is chowned back. Keeping root's build products apart costs disk and
#   buys never having to think about it.
INTEGRATION_TARGET_DIR?=	target/integration

integration:
	${CARGO} test --workspace --target-dir ${INTEGRATION_TARGET_DIR} \
	    -- --ignored --test-threads=1

cluster-test:
	sh tests/cluster/run.sh

clean:
	${CARGO} clean
