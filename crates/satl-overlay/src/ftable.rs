// SPDX-License-Identifier: BSD-2-Clause
//! Static VXLAN forwarding entries: the ioctl `ifconfig`(8) does not expose.
//!
//! `ifconfig`'s vxlan parameter list ends at `vxlanflush`/`vxlanflushall`
//! (`docs/vxlan.md` §3): there is no `vxlanroute`, no `ftable add`, no
//! command-line path to a static (inner MAC → remote VTEP) mapping at all —
//! although the kernel has supported it since the driver was written. Since
//! SatL's overlay is unicast with learning off, **every** frame to a remote
//! endpoint is delivered by one of these entries, so this is the one place in
//! SatL's networking where a wrapper around an external command is not
//! available and the driver ioctl has to be issued directly.
//!
//! The alternative — shipping the `hack/experiments/vxlan/vxlan-ftable.c`
//! helper as a real binary — was rejected: it would mean another artefact to
//! build, install, version and keep in step with the daemon, plus a process
//! spawn per FDB entry on a path that runs once per remote endpoint per
//! network per node.
//!
//! ## Where the `unsafe` is
//!
//! The workspace sets `unsafe_code = "deny"`. In this module the exemption is
//! the [`sys`] submodule and nothing else: it holds the three `#[repr(C)]`
//! payload types, the two ioctl request numbers, and one function that opens a
//! socket and issues the ioctl. Everything outside it — [`Ftable`],
//! [`FtableEntry`], [`FtableReader`] — is ordinary safe Rust. The submodule is
//! deliberately small enough to audit in one sitting, and its layout assumptions
//! are asserted against numbers measured from the C headers of this exact kernel
//! (`sizeof`/`offsetof`, in [`sys`]'s tests).
//!
//! This was the crate's only `unsafe` until [`crate::lltable`], which programs
//! in-jail ARP through a routing socket, needed the same treatment; that module
//! follows exactly this discipline and is the only other exemption.
//!
//! ## Reading the table back
//!
//! `VXLAN_CMD_GET_CONFIG` is the driver's **only** copy-out command and it
//! returns the entry *count*, not the entries ([`Ftable::config`]). The entries
//! themselves are only reachable through `net.link.vxlan.<unit>.ftable.dump`,
//! a sysctl keyed by the **clone unit** — and nothing maps a unit back to an
//! interface name (`docs/vxlan.md` §2 point 3). [`FtableReader`] closes that
//! gap two ways: it remembers nothing, but [`FtableReader::resolve_unit`]
//! identifies an interface's unit by installing a reserved probe entry through
//! the ioctl (which *is* name-based) and finding which unit's dump contains it.
//! That makes a full read-back possible even for an interface adopted after a
//! daemon restart, which is what [`crate::program`] wants for a real diff.
//!
//! ## Lifetime of what this module installs
//!
//! Verified in `docs/vxlan.md` §3: static entries survive a `down`/`up` flap
//! and a plain `vxlanflush`, never age out, and are lost only to
//! `vxlanflushall` or `destroy`. So an interface flap needs no re-programming
//! and a destroy/create cycle needs a full re-push.
//!
//! The ioctl is per-interface and carries no port: a VTEP on a custom
//! `vxlanlocalport` (encrypted networks, M6) programs its FDB exactly like
//! one on the default 4789. Verified by the ESP experiment, whose VTEPs
//! lived on UDP/4790 with their static entries installed through this same
//! ioctl (`hack/experiments/esp/README.md` §1).

use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

use satl_core::MacAddr;

use crate::runner::{CommandOutput, CommandRunner, Failure, SystemRunner, render_argv};

/// Default location of the `sysctl` binary on FreeBSD.
pub const DEFAULT_SYSCTL_BINARY: &str = "/sbin/sysctl";

/// The sysctl subtree the per-interface vxlan nodes live under.
pub const VXLAN_SYSCTL_ROOT: &str = "net.link.vxlan";

/// Entry flag the driver stamps on everything this module installs
/// (`VXLAN_FE_FLAG_STATIC`, `net/if_vxlan.c`).
pub const VXLAN_FE_FLAG_STATIC: u8 = 0x02;

/// Entry flag on a learned entry (`VXLAN_FE_FLAG_DYNAMIC`).
pub const VXLAN_FE_FLAG_DYNAMIC: u8 = 0x01;

/// MAC reserved for [`FtableReader::resolve_unit`]'s unit probe.
///
/// `02:53:41:54:4c:00` — locally administered, unicast, and `53 41 54 4c` is
/// `SATL` in ASCII. It can never collide with an endpoint MAC, because those
/// are `02:42:<the four octets of the IPv4 address>`
/// ([`satl_core::MacAddr::from_ipv4`]).
pub const UNIT_PROBE_MAC: MacAddr = MacAddr::from_octets([0x02, 0x53, 0x41, 0x54, 0x4c, 0x00]);

// ---------------------------------------------------------------------------
// The isolated unsafe surface
// ---------------------------------------------------------------------------

/// Raw `SIOCSDRVSPEC`/`SIOCGDRVSPEC` plumbing for vxlan(4) — **the only
/// `unsafe` in this module** (the crate's other one is
/// [`crate::lltable`]'s `sys`).
///
/// Three payload types mirroring `net/if_vxlan.h`, two ioctl request numbers
/// computed the way `<sys/ioccom.h>` computes them, and one function that
/// performs the call. Nothing here interprets a value; the safe layer above
/// does that.
#[allow(unsafe_code)]
mod sys {
    use std::ffi::c_void;
    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    /// `IFNAMSIZ` — kernel interface-name buffer, NUL included.
    pub const IFNAMSIZ: usize = 16;

    // VXLAN_CMD_* from net/if_vxlan.h.
    pub const VXLAN_CMD_GET_CONFIG: u64 = 0;
    pub const VXLAN_CMD_FTABLE_ENTRY_ADD: u64 = 13;
    pub const VXLAN_CMD_FTABLE_ENTRY_REM: u64 = 14;
    pub const VXLAN_CMD_FLUSH: u64 = 15;

    /// `VXLAN_CMD_FLAG_FLUSH_ALL` — flush static entries too, not just the
    /// learned ones.
    pub const VXLAN_CMD_FLAG_FLUSH_ALL: u32 = 0x0001;

    // ---- ioctl request numbers, per <sys/ioccom.h> -------------------------
    //
    //   #define IOCPARM_MASK   0x1fff
    //   #define IOC_OUT        0x40000000
    //   #define IOC_IN         0x80000000
    //   #define _IOC(inout,group,num,len) \
    //       (inout | ((len & IOCPARM_MASK) << 16) | (group << 8) | num)
    //   #define SIOCSDRVSPEC  _IOW ('i', 123, struct ifdrv)
    //   #define SIOCGDRVSPEC  _IOWR('i', 123, struct ifdrv)
    //
    // The resulting values are asserted against the ones the C preprocessor
    // produces on this kernel in the tests below.
    const IOCPARM_MASK: u64 = 0x1fff;
    const IOC_OUT: u64 = 0x4000_0000;
    const IOC_IN: u64 = 0x8000_0000;

    const fn ioc(inout: u64, group: u64, num: u64, len: usize) -> u64 {
        inout | (((len as u64) & IOCPARM_MASK) << 16) | (group << 8) | num
    }

    const IFDRV_LEN: usize = size_of::<libc::ifdrv>();

    /// `_IOW('i', 123, struct ifdrv)` — the setter side (add/remove/flush).
    pub const SIOCSDRVSPEC: u64 = ioc(IOC_IN, b'i' as u64, 123, IFDRV_LEN);
    /// `_IOWR('i', 123, struct ifdrv)` — the copy-out side (`GET_CONFIG`).
    pub const SIOCGDRVSPEC: u64 = ioc(IOC_IN | IOC_OUT, b'i' as u64, 123, IFDRV_LEN);

    /// `union vxlan_sockaddr`, as an IPv4 command uses it.
    ///
    /// The C union is as large as its `struct sockaddr_in6` member — 28 bytes,
    /// 4-byte aligned — so the IPv4 form is a `sockaddr_in` followed by 12
    /// bytes the caller leaves zeroed. Spelling it as a struct rather than a
    /// Rust `union` keeps every field access safe; the size and alignment are
    /// asserted below.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct VxlanSockaddr {
        /// The IPv4 form. `sin_family` says whether the kernel filled it in.
        pub in4: libc::sockaddr_in,
        /// Tail of the union (`sockaddr_in6` is 12 bytes longer).
        pub tail: [u8; 12],
    }

    impl VxlanSockaddr {
        /// An all-zero sockaddr slot (`sa_family == AF_UNSPEC`).
        pub const fn zeroed() -> Self {
            Self {
                // No `unsafe` and none needed: every field is a plain
                // integer, so the all-zero value is a valid `sockaddr_in`
                // (family AF_UNSPEC), which is exactly what an unset slot
                // is. Writing it out beats `MaybeUninit::zeroed` because it
                // is checked by the compiler.
                in4: libc::sockaddr_in {
                    sin_len: 0,
                    sin_family: 0,
                    sin_port: 0,
                    sin_addr: libc::in_addr { s_addr: 0 },
                    sin_zero: [0; 8],
                },
                tail: [0; 12],
            }
        }
    }

    /// `struct ifvxlancmd` — the payload of every setter command.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct IfVxlanCmd {
        pub flags: u32,
        pub vni: u32,
        pub ftable_timeout: u32,
        pub ftable_max: u32,
        pub port: u16,
        pub port_min: u16,
        pub port_max: u16,
        pub mac: [u8; 6],
        pub ttl: u8,
        pub sa: VxlanSockaddr,
        pub ifname: [u8; IFNAMSIZ],
    }

    impl IfVxlanCmd {
        pub const fn zeroed() -> Self {
            Self {
                flags: 0,
                vni: 0,
                ftable_timeout: 0,
                ftable_max: 0,
                port: 0,
                port_min: 0,
                port_max: 0,
                mac: [0; 6],
                ttl: 0,
                sa: VxlanSockaddr::zeroed(),
                ifname: [0; IFNAMSIZ],
            }
        }
    }

    /// `struct ifvxlancfg` — what `VXLAN_CMD_GET_CONFIG` copies out.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct IfVxlanCfg {
        pub vni: u32,
        pub local_sa: VxlanSockaddr,
        pub remote_sa: VxlanSockaddr,
        pub mc_ifindex: u32,
        pub ftable_cnt: u32,
        pub ftable_max: u32,
        pub ftable_timeout: u32,
        pub port_min: u16,
        pub port_max: u16,
        pub learn: u8,
        pub ttl: u8,
    }

    impl IfVxlanCfg {
        pub const fn zeroed() -> Self {
            Self {
                vni: 0,
                local_sa: VxlanSockaddr::zeroed(),
                remote_sa: VxlanSockaddr::zeroed(),
                mc_ifindex: 0,
                ftable_cnt: 0,
                ftable_max: 0,
                ftable_timeout: 0,
                port_min: 0,
                port_max: 0,
                learn: 0,
                ttl: 0,
            }
        }
    }

    /// Render `iface` into a kernel name buffer, or `EINVAL`/`ENAMETOOLONG`.
    pub fn name_buffer(iface: &str) -> io::Result<[libc::c_char; IFNAMSIZ]> {
        let bytes = iface.as_bytes();
        if bytes.contains(&0) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // The buffer must hold a NUL terminator: `ifd_name` is read with
        // strlcpy semantics on the kernel side.
        if bytes.len() >= IFNAMSIZ {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        let mut out = [0; IFNAMSIZ];
        for (slot, byte) in out.iter_mut().zip(bytes) {
            // `c_char` is `i8` on amd64 and `u8` on arm64, so `as` is the only
            // conversion that compiles on both; a fixed-size name buffer wants
            // exactly this byte-for-byte reinterpretation.
            #[allow(clippy::cast_possible_wrap)]
            {
                *slot = *byte as libc::c_char;
            }
        }
        Ok(out)
    }

    /// Issue one driver-specific ioctl for `iface`, with `payload` as
    /// `ifd_data`.
    ///
    /// `copy_out` selects `SIOCGDRVSPEC` (the kernel writes back into
    /// `payload`) over `SIOCSDRVSPEC`. `ifd_len` is always
    /// `size_of::<T>()`, which `vxlan_ioctl_drvspec()` requires to equal the
    /// size of the command's own payload type exactly — anything else is
    /// `EINVAL`.
    ///
    /// This function is safe to call for any `T`: the worst a mismatched `T`
    /// can do is make the kernel reject the request, because `ifd_len` is
    /// derived from `T` itself rather than asserted by the caller.
    pub fn drvspec<T>(iface: &str, cmd: u64, payload: &mut T, copy_out: bool) -> io::Result<()> {
        let ifd_name = name_buffer(iface)?;

        // SAFETY: `socket(2)` with a constant domain/type/protocol triple is
        // always sound to call; it either returns a fresh descriptor or -1 and
        // sets errno. No pointers are involved.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a descriptor `socket(2)` just returned and that
        // nothing else in this process owns, so transferring ownership to
        // `OwnedFd` is sound and gives it exactly one owner. The `OwnedFd`
        // closes it on every exit path below, including the early return.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut ifd = libc::ifdrv {
            ifd_name,
            ifd_cmd: cmd,
            ifd_len: size_of::<T>(),
            ifd_data: std::ptr::from_mut(payload).cast::<c_void>(),
        };
        let request = if copy_out { SIOCGDRVSPEC } else { SIOCSDRVSPEC };

        // SAFETY: three invariants make this call sound.
        //   1. `fd` is a live `AF_INET`/`SOCK_DGRAM` socket owned by `fd`
        //      above, so the descriptor is valid for the whole call.
        //   2. `&mut ifd` points to a live, fully initialized `libc::ifdrv`
        //      that outlives the call, and so does the `T` behind
        //      `ifd.ifd_data` — `payload` is a `&mut T` borrowed for the
        //      duration of this function, so the kernel's read (and, for
        //      `SIOCGDRVSPEC`, its write) stays inside one live allocation.
        //   3. `ifd.ifd_len` is `size_of::<T>()`, so the kernel copies
        //      exactly as many bytes as `payload` owns, in either direction.
        //      `vxlan_ioctl_drvspec()` additionally rejects any length that
        //      is not its command's own payload size, which is why a wrong
        //      `T` fails with `EINVAL` instead of corrupting memory.
        // The `&mut T` borrow also rules out any concurrent access to
        // `payload` while the kernel has the pointer.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, std::ptr::from_mut(&mut ifd)) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The numbers below were produced by a C program compiled against
        /// this host's `/usr/include` (FreeBSD 15.1-RELEASE-p2, amd64):
        ///
        /// ```text
        /// IFNAMSIZ = 16
        /// SIOCSDRVSPEC = 0x8028697b   SIOCGDRVSPEC = 0xc028697b
        /// sizeof(struct ifdrv) = 40
        ///   ifd_name=0 ifd_cmd=16 ifd_len=24 ifd_data=32
        /// sizeof(union vxlan_sockaddr) = 28 align=4
        /// sizeof(struct ifvxlancmd) = 76 align=4
        ///   flags=0 vni=4 ftable_timeout=8 ftable_max=12 port=16
        ///   port_min=18 port_max=20 mac=22 ttl=28 sa=32 ifname=60
        /// sizeof(struct ifvxlancfg) = 84 align=4
        ///   vni=0 local_sa=4 remote_sa=32 mc_ifindex=60 ftable_cnt=64
        ///   ftable_max=68 ftable_timeout=72 port_min=76 port_max=78
        ///   learn=80 ttl=81
        /// ```
        ///
        /// If any assertion here ever fails, the Rust declarations have
        /// drifted from the kernel's and **the ioctl must not be issued** —
        /// which is the point of asserting rather than hoping.
        #[test]
        fn ioctl_request_numbers_match_the_c_preprocessor() {
            assert_eq!(IFDRV_LEN, 40, "sizeof(struct ifdrv)");
            assert_eq!(SIOCSDRVSPEC, 0x8028_697b);
            assert_eq!(SIOCGDRVSPEC, 0xc028_697b);
        }

        #[test]
        fn ifdrv_layout_matches_the_kernel() {
            assert_eq!(size_of::<libc::ifdrv>(), 40);
            let value = libc::ifdrv {
                ifd_name: [0; IFNAMSIZ],
                ifd_cmd: 0,
                ifd_len: 0,
                ifd_data: std::ptr::null_mut(),
            };
            let base = std::ptr::from_ref(&value).addr();
            assert_eq!(std::ptr::from_ref(&value.ifd_name).addr() - base, 0);
            assert_eq!(std::ptr::from_ref(&value.ifd_cmd).addr() - base, 16);
            assert_eq!(std::ptr::from_ref(&value.ifd_len).addr() - base, 24);
            assert_eq!(std::ptr::from_ref(&value.ifd_data).addr() - base, 32);
        }

        #[test]
        fn vxlan_sockaddr_layout_matches_the_union() {
            assert_eq!(size_of::<VxlanSockaddr>(), 28);
            assert_eq!(align_of::<VxlanSockaddr>(), 4);
            assert_eq!(size_of::<libc::sockaddr_in>(), 16);
            assert_eq!(size_of::<libc::sockaddr_in6>(), 28);
        }

        #[test]
        fn ifvxlancmd_layout_matches_the_kernel() {
            assert_eq!(size_of::<IfVxlanCmd>(), 76, "ifd_len must be exactly this");
            assert_eq!(align_of::<IfVxlanCmd>(), 4);
            let value = IfVxlanCmd::zeroed();
            let base = std::ptr::from_ref(&value).addr();
            let at = |offset: usize, actual: usize| assert_eq!(actual - base, offset);
            at(0, std::ptr::from_ref(&value.flags).addr());
            at(4, std::ptr::from_ref(&value.vni).addr());
            at(8, std::ptr::from_ref(&value.ftable_timeout).addr());
            at(12, std::ptr::from_ref(&value.ftable_max).addr());
            at(16, std::ptr::from_ref(&value.port).addr());
            at(18, std::ptr::from_ref(&value.port_min).addr());
            at(20, std::ptr::from_ref(&value.port_max).addr());
            at(22, std::ptr::from_ref(&value.mac).addr());
            at(28, std::ptr::from_ref(&value.ttl).addr());
            at(32, std::ptr::from_ref(&value.sa).addr());
            at(60, std::ptr::from_ref(&value.ifname).addr());
        }

        #[test]
        fn ifvxlancfg_layout_matches_the_kernel() {
            assert_eq!(size_of::<IfVxlanCfg>(), 84);
            assert_eq!(align_of::<IfVxlanCfg>(), 4);
            let value = IfVxlanCfg::zeroed();
            let base = std::ptr::from_ref(&value).addr();
            let at = |offset: usize, actual: usize| assert_eq!(actual - base, offset);
            at(0, std::ptr::from_ref(&value.vni).addr());
            at(4, std::ptr::from_ref(&value.local_sa).addr());
            at(32, std::ptr::from_ref(&value.remote_sa).addr());
            at(60, std::ptr::from_ref(&value.mc_ifindex).addr());
            at(64, std::ptr::from_ref(&value.ftable_cnt).addr());
            at(68, std::ptr::from_ref(&value.ftable_max).addr());
            at(72, std::ptr::from_ref(&value.ftable_timeout).addr());
            at(76, std::ptr::from_ref(&value.port_min).addr());
            at(78, std::ptr::from_ref(&value.port_max).addr());
            at(80, std::ptr::from_ref(&value.learn).addr());
            at(81, std::ptr::from_ref(&value.ttl).addr());
        }

        #[test]
        fn name_buffer_terminates_and_rejects() {
            let buffer = name_buffer("satl-vx4096").unwrap();
            assert_eq!(buffer[11], 0, "must be NUL-terminated");
            // 15 characters plus the terminator is the longest that fits.
            assert!(name_buffer("123456789012345").is_ok());
            assert_eq!(
                name_buffer("1234567890123456").unwrap_err().raw_os_error(),
                Some(libc::ENAMETOOLONG)
            );
            assert_eq!(
                name_buffer("satl\0vx").unwrap_err().raw_os_error(),
                Some(libc::EINVAL)
            );
        }

        #[test]
        fn drvspec_reports_enxio_for_a_missing_interface() {
            // Exercises the whole unsafe path (socket + ioctl) without
            // privileges and without touching any real interface: the kernel
            // fails the lookup before checking anything else.
            let mut cfg = IfVxlanCfg::zeroed();
            let err = drvspec("satl-vx-absent", VXLAN_CMD_GET_CONFIG, &mut cfg, true).unwrap_err();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::ENXIO),
                "expected ENXIO for a nonexistent interface, got {err}"
            );
        }

        #[test]
        fn drvspec_reports_einval_for_a_non_vxlan_interface() {
            let mut cfg = IfVxlanCfg::zeroed();
            let err = drvspec("lo0", VXLAN_CMD_GET_CONFIG, &mut cfg, true).unwrap_err();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::EINVAL),
                "expected EINVAL on lo0, got {err}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// One static forwarding entry: an inner MAC and the VTEP that owns it.
///
/// Both halves are pure functions of control-plane state — the MAC of an
/// endpoint's overlay address ([`satl_core::MacAddr::from_ipv4`]) and the
/// address of the node hosting it — so an entry can be computed with no
/// read-back of anything the kernel generated (`docs/vxlan.md` §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FtableEntry {
    /// Inner (endpoint) MAC.
    pub mac: MacAddr,
    /// Underlay address of the node hosting that endpoint.
    pub vtep: Ipv4Addr,
}

impl FtableEntry {
    /// An entry for an endpoint at `ip` hosted by the node whose VTEP is
    /// `vtep`.
    #[must_use]
    pub fn for_endpoint(ip: Ipv4Addr, vtep: Ipv4Addr) -> Self {
        Self {
            mac: MacAddr::from_ipv4(ip),
            vtep,
        }
    }

    /// Rejects destinations the kernel refuses with a bare `EINVAL`, so the
    /// error names the reason.
    fn validate(&self) -> Result<(), FtableError> {
        if self.vtep.is_unspecified() || self.vtep.is_multicast() || self.vtep.is_broadcast() {
            return Err(FtableError::InvalidEntry {
                mac: self.mac,
                vtep: self.vtep,
                reason: "the remote VTEP must be a concrete unicast address; the \
                         kernel rejects INADDR_ANY and multicast"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

impl std::fmt::Display for FtableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.mac, self.vtep)
    }
}

/// What [`Ftable::flush`] removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushScope {
    /// Learned entries only (`vxlanflush`). SatL has none, so this is a no-op
    /// on a correctly configured interface — useful only to prove that.
    Dynamic,
    /// Everything, static entries included (`vxlanflushall`).
    All,
}

/// One row of `net.link.vxlan.<unit>.ftable.dump`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FtableRecord {
    /// The entry itself.
    pub entry: FtableEntry,
    /// Raw entry flags: [`VXLAN_FE_FLAG_STATIC`] for anything SatL installed.
    pub flags: u8,
}

impl FtableRecord {
    /// Whether this entry was installed by the control plane rather than
    /// learned. A dynamic entry on a SatL interface means `-vxlanlearn` was
    /// lost.
    #[must_use]
    pub fn is_static(&self) -> bool {
        self.flags & VXLAN_FE_FLAG_STATIC != 0
    }
}

/// What `VXLAN_CMD_GET_CONFIG` reports — the programmatic form of the
/// `vxlan vni ... local ... remote ...` line, plus the FDB counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtepInfo {
    /// VXLAN network identifier.
    pub vni: u32,
    /// Local VTEP address; `None` when unset.
    pub local: Option<SocketAddrV4>,
    /// Default remote (or multicast group); `None` when unset — the interface
    /// then never initialized (`docs/vxlan.md` §2).
    pub remote: Option<SocketAddrV4>,
    /// Whether the driver is learning. SatL wants `false`.
    pub learn: bool,
    /// Outer-header TTL.
    pub ttl: u8,
    /// `vxlandev` interface index; non-zero only for a multicast segment.
    pub mc_ifindex: u32,
    /// **The read-back the ioctl offers**: how many entries the FDB holds.
    pub ftable_count: u32,
    /// Per-interface entry ceiling (`vxlanmaxaddr`).
    pub ftable_max: u32,
    /// Dynamic-entry expiry in seconds; irrelevant with learning off.
    pub ftable_timeout: u32,
    /// Source-port range for the outer UDP header.
    pub port_range: (u16, u16),
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error from FDB programming or read-back.
#[derive(Debug, thiserror::Error)]
pub enum FtableError {
    /// An entry was rejected before the ioctl was issued.
    #[error("vxlan FDB: refusing to program {mac} -> {vtep}: {reason}")]
    InvalidEntry {
        /// Inner MAC of the rejected entry.
        mac: MacAddr,
        /// Remote VTEP of the rejected entry.
        vtep: Ipv4Addr,
        /// Why it was rejected.
        reason: String,
    },

    /// The driver ioctl failed. The message names the command, the interface
    /// and — for the errnos that have a known cause — what to do about it.
    #[error(
        "vxlan FDB: {op} on interface '{iface}' failed \
         ({ioctl}, VXLAN_CMD_{command} = {command_num}): {source}{hint}"
    )]
    Ioctl {
        /// Human description of the operation, entry included.
        op: String,
        /// The interface the ioctl named.
        iface: String,
        /// Which ioctl was used.
        ioctl: &'static str,
        /// Symbolic command name.
        command: &'static str,
        /// Numeric command.
        command_num: u64,
        /// What to do about this errno, when known (starts with `; `).
        hint: String,
        /// The raw OS error.
        #[source]
        source: io::Error,
    },

    /// `sysctl` could not be spawned.
    #[error("vxlan FDB ({context}): failed to spawn `{argv}`: {source}")]
    Spawn {
        /// What was being attempted.
        context: String,
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// `sysctl` ran but failed.
    #[error("vxlan FDB ({context}): {failure}")]
    Failed {
        /// What was being attempted.
        context: String,
        /// The failed command with argv, exit status and stderr.
        failure: Failure,
    },

    /// A dump row could not be parsed.
    #[error(
        "vxlan FDB (read {oid}): cannot parse forwarding-table row {row:?}: \
         {reason}; raw output: {raw:?}"
    )]
    BadDump {
        /// The sysctl that was read.
        oid: String,
        /// The offending row.
        row: String,
        /// Why it was rejected.
        reason: String,
        /// The whole raw output.
        raw: String,
    },

    /// The dump sysctl returned fewer entries than the interface actually holds.
    ///
    /// **Measured on FreeBSD 15.1**
    /// (`hack/experiments/jail-arp/captures/40-ftable-dump-ceiling.txt`):
    ///
    /// ```text
    ///  installed count(ioctl)   dump lines  dump bytes verdict
    ///         81         81            81        4052 ok
    ///         82         82            81        4052 TRUNCATED
    ///       2500       2500            81        4052 TRUNCATED
    /// ```
    ///
    /// `vxlan_ftable_sysctl_dump()` builds into
    /// `sbuf_new(&sb, NULL, PAGE_SIZE, SBUF_FIXEDLEN)` and backs the partial
    /// trailing line out, so the output stays **well formed and carries no
    /// marker of loss**. An IPv6 remote widens each line from 50 to 80 bytes and
    /// lowers the ceiling to about 51.
    ///
    /// The count from `VXLAN_CMD_GET_CONFIG` keeps telling the truth past that
    /// point, which is the only reason this is detectable at all.
    #[error(
        "vxlan FDB: the read-back of interface '{iface}' is truncated: {oid} \
         listed {rows} entries but VXLAN_CMD_GET_CONFIG reports {expected}. The \
         dump sysctl is a fixed one-page buffer (about 81 IPv4 entries) and \
         silently stops, so this table cannot be diffed against; flush it and \
         re-push the full desired set instead"
    )]
    DumpTruncated {
        /// The interface whose table could not be read.
        iface: String,
        /// The sysctl that was read.
        oid: String,
        /// What the ioctl says the table holds.
        expected: u32,
        /// How many rows the dump actually yielded.
        rows: usize,
    },

    /// The clone unit of an interface could not be determined, so the dump
    /// sysctl is unreachable.
    #[error(
        "vxlan FDB: cannot determine the clone unit of interface '{iface}' \
         ({reason}). The per-interface sysctl tree is keyed by clone unit and \
         nothing maps a unit back to a name (docs/vxlan.md section 2), so the \
         forwarding table cannot be read back; flush it and re-push instead"
    )]
    UnitUnknown {
        /// The interface whose unit is unknown.
        iface: String,
        /// What went wrong while probing.
        reason: String,
    },
}

impl FtableError {
    /// Whether this is the kernel refusing to add an entry whose MAC is already
    /// in the table (`EEXIST`).
    ///
    /// Worth a predicate of its own because it is the one errno a reconciler
    /// acts on rather than reports: `FTABLE_ENTRY_ADD` does **not** overwrite,
    /// so a changed VTEP has to be removed first (see [`FtableOps::replace`]).
    #[must_use]
    pub fn is_already_exists(&self) -> bool {
        matches!(self, Self::Ioctl { source, .. } if source.raw_os_error() == Some(libc::EEXIST))
    }

    /// Whether the forwarding table could not be read back completely
    /// ([`Self::DumpTruncated`]).
    ///
    /// The other errno a reconciler acts on rather than reports: a truncated
    /// read-back is not a diffable state, so the only safe response is to flush
    /// and re-push ([`crate::program::Programmer::reconcile`] does).
    #[must_use]
    pub fn is_dump_truncated(&self) -> bool {
        matches!(self, Self::DumpTruncated { .. })
    }
}

/// Errno-specific advice, so an operator is not left with `Invalid argument`.
fn hint_for(err: &io::Error, command: &'static str) -> String {
    let advice = match err.raw_os_error() {
        Some(libc::EPERM) => {
            Some("the driver gates every setter behind PRIV_NET_VXLAN, so satld must run as root")
        }
        Some(libc::ENOENT) => Some("there is no such entry in the forwarding table"),
        Some(libc::ENXIO) => Some("no such interface"),
        Some(libc::EAFNOSUPPORT) => Some(
            "the entry's address family must equal the interface's vxlanremote family; \
             an interface with no remote has none, which means the driver never \
             initialized it (docs/vxlan.md section 2)",
        ),
        Some(libc::EEXIST) => Some("the entry already exists"),
        // ENOSPC cannot come from the static-entry path at all: the count check
        // and ftable_nospace++ live in vxlan_ftable_update_locked(), which is
        // gated behind VXLAN_FLAG_LEARN, and vxlan_ctrl_ftable_entry_add() has
        // no count check (measured: 2500 static entries on an interface whose
        // max is 2000, ftable_nospace still 0 -- see crate::vxlan::FTABLE_MAX).
        // So the old advice, "raise vxlanmaxaddr", was both unfollowable (2000
        // is a hard maximum) and about a condition that cannot occur here.
        Some(libc::ENOSPC) => Some(
            "the driver reported the forwarding table full, which it should \
             never do for a static entry with learning off -- vxlanmaxaddr is \
             not consulted on this path. Check that the interface really has \
             -vxlanlearn (ifconfig <if>, and VtepInfo::learn), because a \
             learning interface has an FDB SatL cannot reconcile",
        ),
        Some(libc::EINVAL) if command == "GET_CONFIG" => {
            Some("the interface is not a vxlan(4) interface")
        }
        Some(libc::EINVAL) => Some(
            "the kernel rejected the payload: the remote must be a concrete unicast \
             address (not INADDR_ANY, not multicast) and ifd_len must be exactly \
             sizeof(struct ifvxlancmd)",
        ),
        _ => None,
    };
    advice.map_or_else(String::new, |text| format!("; {text}"))
}

// ---------------------------------------------------------------------------
// The safe API
// ---------------------------------------------------------------------------

/// The FDB operations, as a trait so a reconciler can be tested without a
/// kernel. [`Ftable`] is the real implementation.
///
/// Deliberately synchronous: these are in-kernel table updates behind a
/// short-lived rwlock, with no I/O to wait on — unlike the process spawns the
/// rest of this crate does. [`crate::program::Programmer`] still runs a whole
/// batch inside one `spawn_blocking` so the async runtime never sees a
/// syscall (CLAUDE.md invariant 4).
pub trait FtableOps: Send + Sync {
    /// Install one static entry.
    ///
    /// **The kernel does not overwrite.** `VXLAN_CMD_FTABLE_ENTRY_ADD` on a MAC
    /// already in the table fails with `EEXIST`, whether or not the VTEP
    /// matches — measured on FreeBSD 15.1:
    ///
    /// ```text
    /// # vxlan-ftable add ovtest-vxA 02:42:0a:4f:00:15 10.2.1.50
    /// ovtest-vxA: static ftable entry 02:42:0a:4f:00:15 -> 10.2.1.50
    /// # vxlan-ftable add ovtest-vxA 02:42:0a:4f:00:15 10.2.3.124
    /// vxlan-ftable: ... FTABLE_ENTRY_ADD ...: File exists
    /// ```
    ///
    /// `docs/vxlan.md` §7 states the opposite ("`add` on an existing entry
    /// replaces it"); it is wrong, and [`FtableOps::replace`] exists because of
    /// it. Note the contrast with `arp -s`, which *does* replace.
    fn add(&self, iface: &str, entry: FtableEntry) -> Result<(), FtableError>;

    /// Remove the entry for `mac`; `Ok(false)` when there was none.
    ///
    /// The kernel returns `ENOENT` for an absent entry; tolerating it here is
    /// what makes the reconciler idempotent without a read-back
    /// (`docs/vxlan.md` §7).
    fn remove(&self, iface: &str, mac: MacAddr) -> Result<bool, FtableError>;

    /// Point an already-programmed MAC at a different VTEP: remove, then add.
    ///
    /// Returns whether a previous entry was actually removed. This is the only
    /// way to change an entry, because [`FtableOps::add`] refuses; it is
    /// provided here, once, so the two-step sequence is not spelled out at
    /// every call site and the (very short) window in which the MAC is
    /// unreachable is confined to one place.
    fn replace(&self, iface: &str, entry: FtableEntry) -> Result<bool, FtableError> {
        let existed = self.remove(iface, entry.mac)?;
        self.add(iface, entry)?;
        Ok(existed)
    }

    /// Flush the table.
    fn flush(&self, iface: &str, scope: FlushScope) -> Result<(), FtableError>;

    /// Read the interface's configuration and entry count by **name** — the
    /// only copy-out the driver offers.
    fn config(&self, iface: &str) -> Result<VtepInfo, FtableError>;
}

/// So a shared handle can be moved into `spawn_blocking` (and a test fake can
/// be observed after the batch has run).
impl<T: FtableOps + ?Sized> FtableOps for std::sync::Arc<T> {
    fn add(&self, iface: &str, entry: FtableEntry) -> Result<(), FtableError> {
        (**self).add(iface, entry)
    }

    fn remove(&self, iface: &str, mac: MacAddr) -> Result<bool, FtableError> {
        (**self).remove(iface, mac)
    }

    fn replace(&self, iface: &str, entry: FtableEntry) -> Result<bool, FtableError> {
        (**self).replace(iface, entry)
    }

    fn flush(&self, iface: &str, scope: FlushScope) -> Result<(), FtableError> {
        (**self).flush(iface, scope)
    }

    fn config(&self, iface: &str) -> Result<VtepInfo, FtableError> {
        (**self).config(iface)
    }
}

/// The real FDB, driven through `SIOCSDRVSPEC`/`SIOCGDRVSPEC`.
///
/// Zero-sized: it holds no descriptor, because each call opens and closes its
/// own throwaway `AF_INET` socket exactly as the kernel's own `ifconfig` does.
/// A long-lived socket would buy nothing and would have to be re-opened after
/// any error anyway.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ftable;

impl Ftable {
    /// A handle to the kernel's forwarding tables.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn ioctl_error(
        op: String,
        iface: &str,
        copy_out: bool,
        command: &'static str,
        command_num: u64,
        source: io::Error,
    ) -> FtableError {
        FtableError::Ioctl {
            op,
            iface: iface.to_owned(),
            ioctl: if copy_out {
                "SIOCGDRVSPEC"
            } else {
                "SIOCSDRVSPEC"
            },
            command,
            command_num,
            hint: hint_for(&source, command),
            source,
        }
    }
}

impl FtableOps for Ftable {
    #[tracing::instrument(skip(self), fields(entry = %entry))]
    fn add(&self, iface: &str, entry: FtableEntry) -> Result<(), FtableError> {
        entry.validate()?;
        let mut cmd = sys::IfVxlanCmd::zeroed();
        cmd.mac = entry.mac.octets();
        cmd.sa.in4.sin_len = u8::try_from(size_of::<libc::sockaddr_in>()).unwrap_or(16);
        cmd.sa.in4.sin_family = u8::try_from(libc::AF_INET).unwrap_or(2);
        // Port 0 makes the kernel inherit the interface's own remote port,
        // which is what a SatL deployment always wants (docs/vxlan.md §3).
        cmd.sa.in4.sin_port = 0;
        cmd.sa.in4.sin_addr.s_addr = u32::from_ne_bytes(entry.vtep.octets());

        sys::drvspec(iface, sys::VXLAN_CMD_FTABLE_ENTRY_ADD, &mut cmd, false).map_err(
            |source| {
                Self::ioctl_error(
                    format!("add static entry {entry}"),
                    iface,
                    false,
                    "FTABLE_ENTRY_ADD",
                    sys::VXLAN_CMD_FTABLE_ENTRY_ADD,
                    source,
                )
            },
        )?;
        tracing::info!(iface = %iface, "programmed static VXLAN FDB entry");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(mac = %mac))]
    fn remove(&self, iface: &str, mac: MacAddr) -> Result<bool, FtableError> {
        let mut cmd = sys::IfVxlanCmd::zeroed();
        cmd.mac = mac.octets();
        match sys::drvspec(iface, sys::VXLAN_CMD_FTABLE_ENTRY_REM, &mut cmd, false) {
            Ok(()) => {
                tracing::info!(iface = %iface, "removed static VXLAN FDB entry");
                Ok(true)
            }
            // An absent entry is the idempotent case, not a failure.
            Err(source) if source.raw_os_error() == Some(libc::ENOENT) => {
                tracing::debug!(iface = %iface, "FDB entry was already absent");
                Ok(false)
            }
            Err(source) => Err(Self::ioctl_error(
                format!("remove entry {mac}"),
                iface,
                false,
                "FTABLE_ENTRY_REM",
                sys::VXLAN_CMD_FTABLE_ENTRY_REM,
                source,
            )),
        }
    }

    #[tracing::instrument(skip(self))]
    fn flush(&self, iface: &str, scope: FlushScope) -> Result<(), FtableError> {
        let mut cmd = sys::IfVxlanCmd::zeroed();
        if scope == FlushScope::All {
            cmd.flags |= sys::VXLAN_CMD_FLAG_FLUSH_ALL;
        }
        sys::drvspec(iface, sys::VXLAN_CMD_FLUSH, &mut cmd, false).map_err(|source| {
            Self::ioctl_error(
                format!("flush {scope:?} entries"),
                iface,
                false,
                "FLUSH",
                sys::VXLAN_CMD_FLUSH,
                source,
            )
        })?;
        tracing::info!(iface = %iface, ?scope, "flushed VXLAN FDB");
        Ok(())
    }

    fn config(&self, iface: &str) -> Result<VtepInfo, FtableError> {
        let mut cfg = sys::IfVxlanCfg::zeroed();
        sys::drvspec(iface, sys::VXLAN_CMD_GET_CONFIG, &mut cfg, true).map_err(|source| {
            Self::ioctl_error(
                "read configuration".to_owned(),
                iface,
                true,
                "GET_CONFIG",
                sys::VXLAN_CMD_GET_CONFIG,
                source,
            )
        })?;
        Ok(VtepInfo {
            vni: cfg.vni,
            local: sockaddr_v4(&cfg.local_sa),
            remote: sockaddr_v4(&cfg.remote_sa),
            learn: cfg.learn != 0,
            ttl: cfg.ttl,
            mc_ifindex: cfg.mc_ifindex,
            ftable_count: cfg.ftable_cnt,
            ftable_max: cfg.ftable_max,
            ftable_timeout: cfg.ftable_timeout,
            port_range: (cfg.port_min, cfg.port_max),
        })
    }
}

/// Interpret a sockaddr slot the kernel filled in; `None` unless it is IPv4.
///
/// An IPv6 VTEP reads as `None` rather than being misparsed — SatL assigns no
/// IPv6 VTEP yet, and silently truncating one would be worse than reporting
/// nothing.
fn sockaddr_v4(sa: &sys::VxlanSockaddr) -> Option<SocketAddrV4> {
    if u32::from(sa.in4.sin_family) != u32::try_from(libc::AF_INET).unwrap_or(2) {
        return None;
    }
    Some(SocketAddrV4::new(
        Ipv4Addr::from(sa.in4.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(sa.in4.sin_port),
    ))
}

// ---------------------------------------------------------------------------
// Reading the table back: the dump sysctl and the unit probe
// ---------------------------------------------------------------------------

/// Reader for `net.link.vxlan.<unit>.ftable.dump`, the only path to the FDB's
/// actual contents.
///
/// `man 4 vxlan` documents the sysctl correctly, but it is registered
/// `CTLFLAG_SKIP`, so it does **not** appear in a `sysctl net.link.vxlan`
/// listing and can only be read by its exact name (`docs/vxlan.md` §3).
/// Reading it needs no privileges; the unit probe does.
#[derive(Debug, Clone)]
pub struct FtableReader<R = SystemRunner> {
    sysctl: PathBuf,
    runner: R,
}

impl FtableReader<SystemRunner> {
    /// Reader that executes the real `sysctl` binary.
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for FtableReader<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> FtableReader<R> {
    /// Reader using `runner` to execute `sysctl` (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            sysctl: PathBuf::from(DEFAULT_SYSCTL_BINARY),
            runner,
        }
    }

    /// Override the `sysctl` binary path.
    #[must_use]
    pub fn with_sysctl(mut self, binary: impl Into<PathBuf>) -> Self {
        self.sysctl = binary.into();
        self
    }

    async fn sysctl(
        &self,
        context: &str,
        args: Vec<String>,
    ) -> Result<(String, CommandOutput), FtableError> {
        let rendered = render_argv(&self.sysctl, &args);
        tracing::debug!(command = %rendered, "running sysctl");
        let output = self
            .runner
            .run(&self.sysctl, &args)
            .await
            .map_err(|source| FtableError::Spawn {
                context: context.to_owned(),
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    /// Every vxlan clone unit currently present, from `sysctl -N
    /// net.link.vxlan` (`docs/vxlan.md` §2 point 3).
    pub async fn units(&self) -> Result<Vec<u32>, FtableError> {
        let context = format!("enumerate {VXLAN_SYSCTL_ROOT} clone units");
        let (argv, output) = self
            .sysctl(
                &context,
                vec!["-N".to_owned(), VXLAN_SYSCTL_ROOT.to_owned()],
            )
            .await?;
        if !output.success() {
            return Err(FtableError::Failed {
                context,
                failure: Failure::new(argv, &output),
            });
        }
        Ok(parse_units(&output.stdout))
    }

    /// The forwarding table of clone unit `unit`, keyed by inner MAC.
    ///
    /// `Ok(None)` when the unit does not exist (`sysctl: unknown oid`), which
    /// is what a destroyed interface looks like.
    pub async fn dump(
        &self,
        unit: u32,
    ) -> Result<Option<BTreeMap<MacAddr, FtableRecord>>, FtableError> {
        let oid = format!("{VXLAN_SYSCTL_ROOT}.{unit}.ftable.dump");
        let context = format!("read {oid}");
        let (argv, output) = self
            .sysctl(&context, vec!["-n".to_owned(), oid.clone()])
            .await?;
        if !output.success() {
            if output.stderr.contains("unknown oid") {
                return Ok(None);
            }
            return Err(FtableError::Failed {
                context,
                failure: Failure::new(argv, &output),
            });
        }
        parse_dump(&oid, &output.stdout).map(Some)
    }

    /// The forwarding table of `iface`, **checked against the entry count the
    /// ioctl reports**.
    ///
    /// [`Self::dump`] alone cannot be trusted: the dump sysctl is a fixed
    /// one-page buffer that silently stops at about 81 IPv4 entries and leaves
    /// no marker (see [`FtableError::DumpTruncated`] for the measurement). Since
    /// `VXLAN_CMD_GET_CONFIG` reports the true count *by name*, the two together
    /// are a complete read-back or a definite "unreadable" — never a plausible
    /// lie.
    ///
    /// `Ok(None)` when the unit's sysctl node is gone, i.e. the interface was
    /// destroyed.
    ///
    /// The count is read **after** the dump: the dump is the slower of the two
    /// (a process spawn), so anything that changed the table during it shows up
    /// as a disagreement rather than being missed.
    pub async fn dump_verified(
        &self,
        ftable: &impl FtableOps,
        iface: &str,
        unit: u32,
    ) -> Result<Option<BTreeMap<MacAddr, FtableRecord>>, FtableError> {
        let Some(table) = self.dump(unit).await? else {
            return Ok(None);
        };
        let expected = ftable.config(iface)?.ftable_count;
        if usize::try_from(expected).unwrap_or(usize::MAX) != table.len() {
            return Err(FtableError::DumpTruncated {
                iface: iface.to_owned(),
                oid: format!("{VXLAN_SYSCTL_ROOT}.{unit}.ftable.dump"),
                expected,
                rows: table.len(),
            });
        }
        Ok(Some(table))
    }

    /// Determine the clone unit backing `iface`.
    ///
    /// The kernel offers no unit → name mapping, so this **probes**: it
    /// installs [`UNIT_PROBE_MAC`] through the (name-based) ioctl, dumps every
    /// unit until one contains that MAC, then removes the probe again. The
    /// probe's remote VTEP is the interface's own default remote, read back
    /// with `GET_CONFIG`, so nothing has to be invented and the entry is
    /// always acceptable to the kernel.
    ///
    /// Needs root (the ioctl is gated behind `PRIV_NET_VXLAN`). Costs two
    /// ioctls plus one sysctl read per unit, and is meant to run once per
    /// interface at adoption time — not per reconciliation pass.
    pub async fn resolve_unit(
        &self,
        ftable: &impl FtableOps,
        iface: &str,
    ) -> Result<u32, FtableError> {
        let info = ftable.config(iface)?;
        let Some(remote) = info.remote else {
            return Err(FtableError::UnitUnknown {
                iface: iface.to_owned(),
                reason: "the interface has no remote address, so no probe entry \
                         can be installed on it"
                    .to_owned(),
            });
        };
        let probe = FtableEntry {
            mac: UNIT_PROBE_MAC,
            vtep: *remote.ip(),
        };
        ftable.add(iface, probe)?;
        let found = self.find_unit_with(probe.mac).await;
        // Always withdraw the probe, even if the search failed.
        if let Err(err) = ftable.remove(iface, probe.mac) {
            tracing::error!(
                iface = %iface,
                error = %err,
                "could not withdraw the FDB unit probe; it will be flushed with \
                 the interface"
            );
        }
        match found? {
            Some(unit) => {
                tracing::debug!(iface = %iface, unit, "resolved vxlan clone unit by probe");
                Ok(unit)
            }
            None => Err(FtableError::UnitUnknown {
                iface: iface.to_owned(),
                reason: format!(
                    "the probe entry {} was not visible in any of the \
                     {VXLAN_SYSCTL_ROOT}.<unit>.ftable.dump nodes",
                    probe.mac
                ),
            }),
        }
    }

    async fn find_unit_with(&self, mac: MacAddr) -> Result<Option<u32>, FtableError> {
        for unit in self.units().await? {
            if let Some(table) = self.dump(unit).await?
                && table.contains_key(&mac)
            {
                return Ok(Some(unit));
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Pure parsers
// ---------------------------------------------------------------------------

/// Pull clone units out of `sysctl -N net.link.vxlan` output by looking for
/// the `<unit>.ftable.count` leaf every interface has.
fn parse_units(stdout: &str) -> Vec<u32> {
    let prefix = format!("{VXLAN_SYSCTL_ROOT}.");
    let mut units: Vec<u32> = stdout
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix(&prefix))
        .filter_map(|rest| rest.strip_suffix(".ftable.count"))
        .filter_map(|unit| unit.parse().ok())
        .collect();
    units.sort_unstable();
    units.dedup();
    units
}

/// Parse `net.link.vxlan.<unit>.ftable.dump`:
///
/// ```text
/// S 0x02 02:42:0A:64:00:0B       10.2.2.47 00040577
/// ```
///
/// Columns: `S`/`D` (static/dynamic), entry flags, inner MAC (upper case), the
/// remote VTEP, and an internal age counter. Blank lines — the output always
/// starts with one — are skipped.
fn parse_dump(oid: &str, stdout: &str) -> Result<BTreeMap<MacAddr, FtableRecord>, FtableError> {
    let mut table = BTreeMap::new();
    for row in stdout.lines() {
        let row = row.trim();
        if row.is_empty() {
            continue;
        }
        let bad = |reason: &str| FtableError::BadDump {
            oid: oid.to_owned(),
            row: row.to_owned(),
            reason: reason.to_owned(),
            raw: stdout.to_owned(),
        };
        let mut fields = row.split_whitespace();
        let (Some(kind), Some(flags), Some(mac), Some(vtep)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(bad("expected 5 whitespace-separated columns"));
        };
        if kind != "S" && kind != "D" {
            return Err(bad("first column must be 'S' (static) or 'D' (dynamic)"));
        }
        let flags = flags
            .strip_prefix("0x")
            .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            .ok_or_else(|| bad("second column must be hex entry flags like 0x02"))?;
        // The dump prints MACs upper-case; MacAddr's parser is case-insensitive.
        let mac: MacAddr = mac
            .parse()
            .map_err(|_| bad("third column must be a MAC address"))?;
        let vtep: Ipv4Addr = vtep
            .parse()
            .map_err(|_| bad("fourth column must be an IPv4 VTEP address"))?;
        table.insert(
            mac,
            FtableRecord {
                entry: FtableEntry { mac, vtep },
                flags,
            },
        );
    }
    Ok(table)
}

/// An in-memory [`FtableOps`] for tests in this crate — the seam that lets a
/// whole reconciliation pass run with no kernel and no privileges.
#[cfg(test)]
pub(crate) mod testing {
    use super::{FlushScope, FtableEntry, FtableError, FtableOps, VtepInfo};
    use satl_core::MacAddr;
    use std::collections::BTreeMap;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Mutex;

    /// The error `FTABLE_ENTRY_ADD` produces, rendered the same way the real
    /// wrapper renders it.
    fn add_failed(iface: &str, entry: FtableEntry, errno: i32) -> FtableError {
        FtableError::Ioctl {
            op: format!("add static entry {entry}"),
            iface: iface.to_owned(),
            ioctl: "SIOCSDRVSPEC",
            command: "FTABLE_ENTRY_ADD",
            command_num: 13,
            hint: super::hint_for(&io::Error::from_raw_os_error(errno), "FTABLE_ENTRY_ADD"),
            source: io::Error::from_raw_os_error(errno),
        }
    }

    /// Recording, in-memory forwarding table.
    #[derive(Debug, Default)]
    pub(crate) struct FakeFtable {
        tables: Mutex<BTreeMap<String, BTreeMap<MacAddr, Ipv4Addr>>>,
        calls: Mutex<Vec<String>>,
        /// What `config()` reports as the interface's default remote.
        remote: Option<SocketAddrV4>,
        /// When set, every `add` fails with this errno.
        fail_add: Option<i32>,
        /// When set, every `flush` fails with this errno.
        fail_flush: Option<i32>,
    }

    impl FakeFtable {
        pub(crate) fn new() -> Self {
            Self {
                remote: Some(SocketAddrV4::new(Ipv4Addr::new(10, 2, 255, 254), 4789)),
                ..Self::default()
            }
        }

        /// A table whose interface reports no default remote — what a vxlan
        /// interface the driver refused looks like.
        pub(crate) fn without_remote() -> Self {
            Self {
                remote: None,
                ..Self::default()
            }
        }

        /// A table whose every `add` fails with `errno`.
        pub(crate) fn failing_add(errno: i32) -> Self {
            Self {
                fail_add: Some(errno),
                ..Self::new()
            }
        }

        /// A table whose every `flush` fails with `errno`.
        pub(crate) fn failing_flush(errno: i32) -> Self {
            Self {
                fail_flush: Some(errno),
                ..Self::new()
            }
        }

        /// Every call made so far, rendered.
        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        /// The current table of `iface`.
        pub(crate) fn table(&self, iface: &str) -> BTreeMap<MacAddr, Ipv4Addr> {
            self.tables
                .lock()
                .unwrap()
                .get(iface)
                .cloned()
                .unwrap_or_default()
        }

        /// Seed entries without recording calls.
        pub(crate) fn preload(&self, iface: &str, entries: &[(MacAddr, Ipv4Addr)]) {
            let mut tables = self.tables.lock().unwrap();
            let table = tables.entry(iface.to_owned()).or_default();
            for (mac, vtep) in entries {
                table.insert(*mac, *vtep);
            }
        }
    }

    impl FtableOps for FakeFtable {
        fn add(&self, iface: &str, entry: FtableEntry) -> Result<(), FtableError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("add {iface} {entry}"));
            if let Some(errno) = self.fail_add {
                return Err(add_failed(iface, entry, errno));
            }
            let mut tables = self.tables.lock().unwrap();
            let table = tables.entry(iface.to_owned()).or_default();
            // Faithful to the kernel: FTABLE_ENTRY_ADD never overwrites.
            if table.contains_key(&entry.mac) {
                return Err(add_failed(iface, entry, libc::EEXIST));
            }
            table.insert(entry.mac, entry.vtep);
            Ok(())
        }

        fn remove(&self, iface: &str, mac: MacAddr) -> Result<bool, FtableError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("remove {iface} {mac}"));
            Ok(self
                .tables
                .lock()
                .unwrap()
                .entry(iface.to_owned())
                .or_default()
                .remove(&mac)
                .is_some())
        }

        fn flush(&self, iface: &str, scope: FlushScope) -> Result<(), FtableError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("flush {iface} {scope:?}"));
            if let Some(errno) = self.fail_flush {
                let source = io::Error::from_raw_os_error(errno);
                return Err(FtableError::Ioctl {
                    op: format!("flush {scope:?} entries"),
                    iface: iface.to_owned(),
                    ioctl: "SIOCSDRVSPEC",
                    command: "FLUSH",
                    command_num: 15,
                    hint: super::hint_for(&source, "FLUSH"),
                    source,
                });
            }
            if scope == FlushScope::All {
                self.tables.lock().unwrap().remove(iface);
            }
            Ok(())
        }

        fn config(&self, iface: &str) -> Result<VtepInfo, FtableError> {
            self.calls.lock().unwrap().push(format!("config {iface}"));
            Ok(VtepInfo {
                vni: 4096,
                local: Some(SocketAddrV4::new(Ipv4Addr::new(10, 2, 2, 47), 4789)),
                remote: self.remote,
                learn: false,
                ttl: 64,
                mc_ifindex: 0,
                ftable_count: u32::try_from(self.table(iface).len()).unwrap_or(u32::MAX),
                ftable_max: 2000,
                ftable_timeout: 1200,
                port_range: (10000, 65535),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeFtable;
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_DUMP: &str = include_str!("../tests/fixtures/ftable_dump.txt");
    const FIXTURE_DUMP_EMPTY: &str = include_str!("../tests/fixtures/ftable_dump_empty.txt");
    const FIXTURE_UNITS: &str = include_str!("../tests/fixtures/sysctl_vxlan_names.txt");
    const FIXTURE_UNKNOWN_OID: &str = include_str!("../tests/fixtures/sysctl_unknown_oid.txt");

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("valid MAC")
    }

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("valid address")
    }

    #[test]
    fn entry_mac_is_derived_from_the_endpoint_address() {
        let entry = FtableEntry::for_endpoint(ip("10.100.0.11"), ip("10.2.2.47"));
        assert_eq!(entry.mac, mac("02:42:0a:64:00:0b"));
        assert_eq!(entry.to_string(), "02:42:0a:64:00:0b -> 10.2.2.47");
    }

    #[test]
    fn entry_validation_rejects_what_the_kernel_would() {
        let bad = |vtep: &str| {
            FtableEntry {
                mac: mac("02:42:0a:64:00:0b"),
                vtep: ip(vtep),
            }
            .validate()
            .unwrap_err()
            .to_string()
        };
        assert!(bad("0.0.0.0").contains("unicast"));
        assert!(bad("224.0.0.1").contains("unicast"));
        assert!(bad("255.255.255.255").contains("unicast"));
        assert!(
            FtableEntry::for_endpoint(ip("10.100.0.11"), ip("10.2.2.47"))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn parse_dump_reads_real_output() {
        let table = parse_dump("test", FIXTURE_DUMP).unwrap();
        assert_eq!(table.len(), 3);
        let entry = table[&mac("02:42:0a:64:00:0b")];
        assert_eq!(entry.entry.vtep, ip("10.2.2.47"));
        assert_eq!(entry.flags, VXLAN_FE_FLAG_STATIC);
        assert!(entry.is_static());
        assert_eq!(
            table[&mac("02:42:0a:64:00:0d")].entry.vtep,
            ip("10.2.3.124")
        );
        // Keying by MAC makes the dump order irrelevant, which matters: the
        // kernel prints hash-bucket order, not insertion order.
        assert_eq!(
            table.keys().copied().collect::<Vec<_>>(),
            [
                mac("02:42:0a:64:00:0b"),
                mac("02:42:0a:64:00:0c"),
                mac("02:42:0a:64:00:0d"),
            ]
        );
    }

    #[test]
    fn parse_dump_reads_an_empty_table() {
        // The sysctl emits a single blank line for an empty table.
        assert!(parse_dump("test", FIXTURE_DUMP_EMPTY).unwrap().is_empty());
        assert!(parse_dump("test", "").unwrap().is_empty());
    }

    #[test]
    fn parse_dump_recognizes_a_learned_entry() {
        let table = parse_dump(
            "test",
            "\nD 0x01 58:9C:FC:10:C0:E2       10.2.1.50 00032912\n",
        )
        .unwrap();
        let entry = table[&mac("58:9c:fc:10:c0:e2")];
        assert_eq!(entry.flags, VXLAN_FE_FLAG_DYNAMIC);
        assert!(!entry.is_static(), "a learned entry is not SatL's");
    }

    #[test]
    fn parse_dump_rejects_garbage_with_the_raw_output() {
        for bad in [
            "X 0x02 02:42:0A:64:00:0B 10.2.2.47 00040577\n",
            "S 02 02:42:0A:64:00:0B 10.2.2.47 00040577\n",
            "S 0x02 not-a-mac 10.2.2.47 00040577\n",
            "S 0x02 02:42:0A:64:00:0B not-an-ip 00040577\n",
            "S 0x02 02:42:0A:64:00:0B\n",
        ] {
            let err = parse_dump("net.link.vxlan.0.ftable.dump", bad).unwrap_err();
            let text = err.to_string();
            assert!(text.contains("net.link.vxlan.0.ftable.dump"), "{text}");
            assert!(text.contains("cannot parse"), "{bad:?} -> {text}");
        }
    }

    #[test]
    fn parse_units_from_real_sysctl_names() {
        assert_eq!(parse_units(FIXTURE_UNITS), [0, 1]);
        assert!(parse_units("net.link.vxlan.max_nesting\n").is_empty());
        assert!(parse_units("").is_empty());
    }

    #[tokio::test]
    async fn dump_builds_the_exact_oid_and_parses_it() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_DUMP, "");
        let reader = FtableReader::with_runner(&mock);
        let table = reader.dump(7).await.unwrap().unwrap();
        assert_eq!(table.len(), 3);
        assert_eq!(
            mock.calls(),
            ["/sbin/sysctl -n net.link.vxlan.7.ftable.dump"]
        );
    }

    #[tokio::test]
    async fn dump_maps_unknown_oid_to_none() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_UNKNOWN_OID);
        let reader = FtableReader::with_runner(&mock);
        assert!(reader.dump(9).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dump_reports_other_sysctl_failures() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "sysctl: permission denied\n");
        let reader = FtableReader::with_runner(&mock);
        let err = reader.dump(0).await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("net.link.vxlan.0.ftable.dump"), "{text}");
        assert!(text.contains("permission denied"), "{text}");
    }

    #[tokio::test]
    async fn units_enumerates_from_names() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_UNITS, "");
        let reader = FtableReader::with_runner(&mock);
        assert_eq!(reader.units().await.unwrap(), [0, 1]);
        assert_eq!(mock.calls(), ["/sbin/sysctl -N net.link.vxlan"]);
    }

    #[tokio::test]
    async fn resolve_unit_probes_and_withdraws_the_probe() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_UNITS, ""); // units -> 0, 1
        mock.push_output(0, FIXTURE_DUMP, ""); // unit 0: probe not here
        mock.push_output(
            0,
            "\nS 0x02 02:53:41:54:4C:00       10.2.255.254 00040577\n",
            "",
        ); // unit 1: found
        let reader = FtableReader::with_runner(&mock);
        let fake = FakeFtable::new();
        let unit = reader.resolve_unit(&fake, "satl-vx4096").await.unwrap();
        assert_eq!(unit, 1);
        assert_eq!(
            fake.calls(),
            [
                "config satl-vx4096",
                "add satl-vx4096 02:53:41:54:4c:00 -> 10.2.255.254",
                "remove satl-vx4096 02:53:41:54:4c:00",
            ]
        );
        assert!(
            fake.table("satl-vx4096").is_empty(),
            "the probe entry must not be left behind"
        );
    }

    #[tokio::test]
    async fn resolve_unit_withdraws_the_probe_even_when_no_unit_matches() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_UNITS, "");
        mock.push_output(0, FIXTURE_DUMP_EMPTY, "");
        mock.push_output(0, FIXTURE_DUMP_EMPTY, "");
        let reader = FtableReader::with_runner(&mock);
        let fake = FakeFtable::new();
        let err = reader.resolve_unit(&fake, "satl-vx4096").await.unwrap_err();
        assert!(err.to_string().contains("not visible in any"), "{err}");
        assert!(
            fake.calls()
                .contains(&"remove satl-vx4096 02:53:41:54:4c:00".to_owned())
        );
    }

    #[tokio::test]
    async fn resolve_unit_refuses_an_interface_with_no_remote() {
        let mock = MockRunner::new();
        let reader = FtableReader::with_runner(&mock);
        let fake = FakeFtable::without_remote();
        let err = reader
            .resolve_unit(&fake, "satl-vx-norem")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("no remote address"), "{text}");
        assert!(text.contains("docs/vxlan.md"), "{text}");
    }

    #[test]
    fn probe_mac_can_never_collide_with_an_endpoint_mac() {
        // Endpoint MACs are 02:42:<a>:<b>:<c>:<d>; the probe's second octet
        // is 0x53, so no address can produce it.
        assert_ne!(UNIT_PROBE_MAC.octets()[1], 0x42);
        for ip in [
            "0.0.0.0",
            "255.255.255.255",
            "10.100.0.11",
            "83.65.84.76", // == 0x53 0x41 0x54 0x4c, the probe's tail
        ] {
            assert_ne!(MacAddr::from_ipv4(ip.parse().unwrap()), UNIT_PROBE_MAC);
        }
    }

    #[test]
    fn add_refuses_an_existing_mac_and_replace_is_the_way_round_it() {
        let fake = FakeFtable::new();
        let first = FtableEntry::for_endpoint(ip("10.100.0.21"), ip("10.2.1.50"));
        let moved = FtableEntry::for_endpoint(ip("10.100.0.21"), ip("10.2.3.124"));
        fake.add("satl-vx4096", first).unwrap();
        // The kernel returns EEXIST whether or not the VTEP matches.
        for entry in [first, moved] {
            let err = fake.add("satl-vx4096", entry).unwrap_err();
            assert!(err.is_already_exists(), "{err}");
            assert!(err.to_string().contains("already exists"), "{err}");
        }
        assert!(fake.replace("satl-vx4096", moved).unwrap());
        assert_eq!(fake.table("satl-vx4096")[&moved.mac], ip("10.2.3.124"));
        // ...and replacing something absent still installs it.
        let fresh = FtableEntry::for_endpoint(ip("10.100.0.22"), ip("10.2.1.50"));
        assert!(!fake.replace("satl-vx4096", fresh).unwrap());
        assert_eq!(fake.table("satl-vx4096").len(), 2);
    }

    #[test]
    fn errno_hints_name_the_cause() {
        let hint = |errno: i32, command: &'static str| {
            hint_for(&io::Error::from_raw_os_error(errno), command)
        };
        assert!(hint(libc::EPERM, "FTABLE_ENTRY_ADD").contains("root"));
        assert!(hint(libc::ENOENT, "FTABLE_ENTRY_REM").contains("no such entry"));
        assert!(hint(libc::EAFNOSUPPORT, "FTABLE_ENTRY_ADD").contains("vxlanremote"));
        assert!(hint(libc::EINVAL, "GET_CONFIG").contains("not a vxlan(4)"));
        assert!(hint(libc::EINVAL, "FTABLE_ENTRY_ADD").contains("ifd_len"));
        assert!(hint(libc::ENXIO, "GET_CONFIG").contains("no such interface"));
        assert!(hint(libc::EIO, "FLUSH").is_empty());
    }

    #[test]
    fn ioctl_error_message_names_command_interface_and_hint() {
        let err = Ftable::ioctl_error(
            "add static entry 02:42:0a:64:00:0b -> 10.2.2.47".to_owned(),
            "satl-vx4096",
            false,
            "FTABLE_ENTRY_ADD",
            13,
            io::Error::from_raw_os_error(libc::EPERM),
        );
        let text = err.to_string();
        assert!(text.contains("satl-vx4096"), "{text}");
        assert!(text.contains("SIOCSDRVSPEC"), "{text}");
        assert!(text.contains("VXLAN_CMD_FTABLE_ENTRY_ADD = 13"), "{text}");
        assert!(text.contains("PRIV_NET_VXLAN"), "{text}");
    }

    // ---- live, unprivileged exercise of the safe wrapper -------------------

    #[test]
    fn config_on_a_missing_interface_is_a_typed_error() {
        let err = Ftable::new().config("satl-vx-absent").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("no such interface"), "{text}");
        assert!(text.contains("GET_CONFIG"), "{text}");
    }

    #[test]
    fn config_on_a_non_vxlan_interface_is_a_typed_error() {
        let err = Ftable::new().config("lo0").unwrap_err();
        assert!(
            err.to_string().contains("not a vxlan(4) interface"),
            "{err}"
        );
    }

    #[test]
    fn add_rejects_a_too_long_interface_name_before_the_kernel_does() {
        let err = Ftable::new()
            .add(
                "satl-vx-a-name-far-too-long",
                FtableEntry::for_endpoint(ip("10.100.0.11"), ip("10.2.2.47")),
            )
            .unwrap_err();
        assert!(err.to_string().contains("File name too long"), "{err}");
    }
}
