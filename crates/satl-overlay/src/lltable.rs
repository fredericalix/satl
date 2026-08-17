// SPDX-License-Identifier: BSD-2-Clause
//! The kernel's **link-layer table** — where ARP entries actually live — driven
//! directly through `jail_attach`(2) and a `PF_ROUTE` socket.
//!
//! This is the mechanism that replaces `jexec <jail> arp -s` (see
//! [`crate::arp::ArpError::MissingBinary`]). Everything here runs **in the
//! calling process's network stack**, so it is only ever correct in a
//! short-lived child that has already called [`attach`]: `jail_attach`(2) is
//! irreversible for the caller, and `satld` is multi-threaded. The process that
//! arranges that child is [`crate::arphelper`]; this module is the syscall layer
//! it drives.
//!
//! ## Why a routing socket and not a command
//!
//! Measured on FreeBSD 15.1 (`hack/experiments/jail-arp/`, capture
//! `captures/10-jexec-cannot-work.txt`), on a host running four real containers:
//!
//! ```text
//! # jexec 6 arp -an                        # a FreeBSD-less rootfs
//! jexec: execvp: arp: No such file or directory
//! # jexec 3 arp -an                        # a Linux image that *has* /sbin/arp
//! arp: can't open '/proc/net/arp': No such file or directory
//! # jexec 3 arp -s 10.79.0.12 02:42:0a:4f:00:0c
//! arp: ioctl 0x8955 failed: Invalid argument
//! ```
//!
//! So the binary is either missing or — worse — present and speaking Linux's ARP
//! ABI (`0x8955` is Linux's `SIOCSARP`) under the linuxulator. Materialising a
//! FreeBSD `arp`(8) in the image is out of the question: an operator must not
//! find files SatL put in their container, and read-only and distroless images
//! make it impossible anyway.
//!
//! `route`(8) has a `-j` flag and still cannot do it: a link-layer entry needs
//! `RTF_LLDATA` (`sys/net/rtsock.c`, `route_output()` dispatches to
//! `lla_rt_output()` on that flag alone) and `route`(8) never sets it.
//!
//! `ifconfig -j` and `route -j` exist; **`arp`(8) is the one tool with no `-j`**.
//! What it does internally is what this module does: on FreeBSD 15.1 `arp`(8)
//! prefers netlink (`usr.sbin/arp/arp_netlink.c`, `set_nl`/`delete_nl`) and
//! keeps the routing-socket path under `WITHOUT_NETLINK`
//! (`usr.sbin/arp/arp.c`, `set_rtsock`/`delete_rtsock`/`rtmsg`). The
//! routing-socket path is the one reproduced here: it is a fixed binary layout
//! from `<net/route.h>` rather than a netlink attribute encoder, and both reach
//! the same `lla_rt_output()`.
//!
//! ## The message sequence
//!
//! Per `usr.sbin/arp/arp.c` and `sys/net/if_llatbl.c`:
//!
//! 1. **`RTM_GET`** on the address. The reply's `RTA_GATEWAY` is a
//!    `sockaddr_dl` naming the interface the address is on-link for; that is
//!    where `sdl_index` and `sdl_type` come from. This step is what fails when
//!    the address is on no interface in the stack.
//! 2. **`RTM_ADD`** with `RTA_DST` = the address, `RTA_GATEWAY` = a
//!    `sockaddr_dl` carrying that index and the MAC, flags
//!    `RTF_HOST | RTF_STATIC | RTF_LLDATA`, `rtm_inits = RTV_EXPIRE` and
//!    `rmx_expire = 0`. Zero expiry is what makes the entry **permanent**
//!    (`lla_rt_output()`: `rmx_expire == 0` ⇒ `LLE_STATIC`).
//! 3. **`RTM_DELETE`** needs the `sockaddr_dl` too — the `AF_LINK` check in
//!    `lla_rt_output()` sits above its `switch`, so an interface index is
//!    required even to delete.
//!
//! Read-back is `sysctl(NET_RT_FLAGS, RTF_LLINFO)` ([`table`]); there is no
//! copy-out on the routing socket for the whole table.
//!
//! ## Measured semantics (`captures/30-premise-and-mechanism.txt`)
//!
//! | Operation | Result |
//! |---|---|
//! | add, then add the same again | succeeds |
//! | add an address already present, different MAC | **replaces** it, no `EEXIST` |
//! | delete a present entry | succeeds |
//! | delete an absent entry | `ENOENT` — the idempotent case |
//! | delete the jail's **own** address | `EPERM` (`LLE_IFADDR` is immutable) |
//! | add/delete an address that is not on-link | `ESRCH`, or `EHOSTUNREACH` when a default route swallowed the lookup |
//! | `jail_attach` with an unknown jid | `EINVAL` (**not** `ENOENT`) |
//!
//! Note the contrast with the VXLAN FDB, where `add` on an existing MAC is
//! `EEXIST` ([`crate::ftable::FtableOps::add`]). Here it replaces, so a moved
//! endpoint needs no delete first.
//!
//! ## Ownership: `RTF_PINNED` is the kernel's own marker
//!
//! An entry SatL installs has flags `0xc05`
//! (`RTF_UP|RTF_HOST|RTF_LLDATA|RTF_STATIC`). The kernel's permanent entry for
//! the jail's *own* address has `0x100c05` — the extra bit is `RTF_PINNED`, set
//! for `LLE_IFADDR`. That is a positive, kernel-provided way to tell the jail's
//! own address from a peer's, which `arp -an` does not print at all. See
//! [`crate::arp::ArpEntry::is_overlay_static`].
//!
//! ## Where the `unsafe` is
//!
//! The workspace sets `unsafe_code = "deny"`. The exemption is the [`sys`]
//! submodule and nothing else, exactly as in [`crate::ftable`]: it holds the two
//! `#[repr(C)]` message types `libc` does not declare for FreeBSD, the constants
//! `libc` is missing, and five functions that make syscalls. Every layout
//! assumption is asserted in [`sys`]'s tests against numbers printed by
//! `hack/experiments/jail-arp/layout.c`, compiled against this host's
//! `/usr/include`.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsFd as _;

use satl_core::MacAddr;

/// Ethernet address length, i.e. `sdl_alen` for every entry this module writes.
pub const ETHER_ADDR_LEN: u8 = 6;

/// How many other subscribers' routing messages one exchange will skip before
/// giving up on finding its own reply.
const MAX_REPLIES_SCANNED: usize = 256;

// ---------------------------------------------------------------------------
// The isolated unsafe surface
// ---------------------------------------------------------------------------

/// Raw `PF_ROUTE`, `jail_attach`(2) and `sysctl`(3) plumbing — **the only
/// `unsafe` in this module**.
///
/// Two `#[repr(C)]` types (`rt_msghdr` and `rt_metrics`, which `libc` declares
/// for Apple but not for FreeBSD), the constants `libc` is missing, and the five
/// syscalls: `jail_attach`, `socket`, `write`, `read`, `sysctl`, plus
/// `if_indextoname`. Nothing here interprets a value beyond bounds-checking it;
/// the safe layer above does that.
#[allow(unsafe_code)]
mod sys {
    use std::io;
    use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

    /// `RTV_EXPIRE` — "I am initialising `rmx_expire`". `libc` has no FreeBSD
    /// definition.
    pub const RTV_EXPIRE: u64 = 0x4;

    /// `IFT_ETHER`, `IFT_L2VLAN`, `IFT_BRIDGE` from `<net/if_types.h>` — the
    /// interface types `arp`(8)'s `valid_type()` accepts among those SatL can
    /// meet. Anything else has no ARP.
    pub const ARP_CAPABLE_IFTYPES: [u8; 3] = [0x06, 0x87, 0xd1];

    /// `struct rt_metrics` (`<net/route.h>`). Only `rmx_expire` is ever set.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct RtMetrics {
        pub locks: u64,
        pub mtu: u64,
        pub hopcount: u64,
        pub expire: u64,
        pub recvpipe: u64,
        pub sendpipe: u64,
        pub ssthresh: u64,
        pub rtt: u64,
        pub rttvar: u64,
        pub pksent: u64,
        pub weight: u64,
        pub nhidx: u64,
        pub filler: [u64; 2],
    }

    /// `struct rt_msghdr` (`<net/route.h>`).
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct RtMsghdr {
        pub msglen: u16,
        pub version: u8,
        pub r#type: u8,
        pub index: u16,
        pub spare1: u16,
        pub flags: i32,
        pub addrs: i32,
        pub pid: i32,
        pub seq: i32,
        pub errno: i32,
        pub fmask: i32,
        pub inits: u64,
        pub rmx: RtMetrics,
    }

    /// A routing message plus the space its sockaddrs occupy.
    ///
    /// 512 bytes of tail is what `arp`(8)'s own `m_rtmsg` uses. An `RTM_ADD`
    /// needs `SA_SIZE(sockaddr_in) + sizeof(sockaddr_dl)` = 16 + 54 = 70; a
    /// reply can carry up to `RTAX_MAX` sockaddrs and still fits.
    pub const RTMSG_SPACE: usize = 512;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct RtMsg {
        pub hdr: RtMsghdr,
        pub space: [u8; RTMSG_SPACE],
    }

    impl Default for RtMsg {
        fn default() -> Self {
            Self {
                hdr: RtMsghdr::default(),
                space: [0; RTMSG_SPACE],
            }
        }
    }

    /// `SA_SIZE` from `<net/route.h>`: `sa_len` rounded up to a multiple of
    /// `sizeof(long)`, with a minimum of `sizeof(long)`.
    #[must_use]
    pub const fn sa_size(sa_len: u8) -> usize {
        let word = size_of::<u64>();
        if sa_len == 0 {
            word
        } else {
            1 + (((sa_len as usize) - 1) | (word - 1))
        }
    }

    /// `jail_get`(2) by `name` — the syscall `jail_getid`(3) wraps, issued
    /// directly so nothing has to link `libjail` for forty lines of iovecs.
    ///
    /// Returns the jid. A name that matches no jail is `ENOENT`.
    pub fn jail_id_by_name(name: &str) -> io::Result<i32> {
        // jail_get takes the parameter *names* as NUL-terminated strings too.
        let key = c"name";
        let mut value = name.as_bytes().to_vec();
        if value.contains(&0) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        value.push(0);
        let mut iov = [
            libc::iovec {
                iov_base: key.as_ptr().cast::<libc::c_void>().cast_mut(),
                iov_len: key.count_bytes() + 1,
            },
            libc::iovec {
                iov_base: value.as_mut_ptr().cast::<libc::c_void>(),
                iov_len: value.len(),
            },
        ];
        // SAFETY: three invariants make this sound.
        //   1. `iov` is a live, exclusively borrowed array of exactly 2
        //      `iovec`s, and 2 is the count passed.
        //   2. each `iov_base` points into a live allocation that outlives the
        //      call — a `'static` C string literal and a local `Vec` — and each
        //      `iov_len` is that allocation's own length including its NUL, so
        //      the kernel's reads stay inside them.
        //   3. this is a pure lookup: `flags` is 0 and no output parameter is
        //      declared, so the kernel writes nothing back through `iov`. The
        //      jid comes out as the return value.
        let jid = unsafe { libc::jail_get(iov.as_mut_ptr(), 2, 0) };
        if jid < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(jid)
    }

    /// `jail_attach`(2): move this process into `jid`'s jail, **irreversibly**.
    ///
    /// An unknown jid is `EINVAL`, not `ENOENT` (measured).
    pub fn jail_attach(jid: i32) -> io::Result<()> {
        // SAFETY: `jail_attach` takes a plain `int` and touches no memory of
        // ours. It either returns 0 or -1 with errno set. The only lasting
        // effect is on this process's own credentials and network stack, which
        // is precisely what the caller asked for.
        if unsafe { libc::jail_attach(jid) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A `PF_ROUTE`/`SOCK_RAW` socket on the **current** stack.
    pub fn route_socket() -> io::Result<OwnedFd> {
        // SAFETY: `socket(2)` with a constant domain/type/protocol triple is
        // always sound to call; no pointers are involved. It returns a fresh
        // descriptor or -1 with errno set.
        let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a descriptor `socket(2)` just returned and that
        // nothing else in this process owns, so transferring ownership to
        // `OwnedFd` gives it exactly one owner, which closes it on drop.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    /// `write(2)` the first `len` bytes of `msg` to the routing socket.
    ///
    /// `len` is checked against `size_of::<RtMsg>()` here rather than trusted,
    /// so no caller can make the kernel read past the value.
    pub fn write_msg(fd: BorrowedFd<'_>, msg: &RtMsg, len: usize) -> io::Result<()> {
        if len > size_of::<RtMsg>() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // SAFETY: three invariants make this sound.
        //   1. `fd` is a live descriptor borrowed for the call.
        //   2. the pointer is derived from `&RtMsg`, a live, fully initialised
        //      value that outlives the call; the kernel only reads from it.
        //   3. `len <= size_of::<RtMsg>()` was just checked, so the read stays
        //      inside that one allocation.
        let written = unsafe {
            libc::write(
                fd.as_raw_fd(),
                std::ptr::from_ref(msg).cast::<libc::c_void>(),
                len,
            )
        };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `read(2)` one routing message into `msg`; returns the byte count.
    pub fn read_msg(fd: BorrowedFd<'_>, msg: &mut RtMsg) -> io::Result<usize> {
        // SAFETY: same three invariants as `write_msg`, with the direction
        // reversed: `&mut RtMsg` is a live, fully initialised, exclusively
        // borrowed allocation of exactly `size_of::<RtMsg>()` bytes, which is
        // the length passed, so the kernel's write stays inside it. `RtMsg` is
        // all integers, so any byte pattern the kernel leaves is a valid value.
        let read = unsafe {
            libc::read(
                fd.as_raw_fd(),
                std::ptr::from_mut(msg).cast::<libc::c_void>(),
                size_of::<RtMsg>(),
            )
        };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        // Infallible: `read` is non-negative here, and `isize -> usize` on a
        // non-negative value never truncates.
        Ok(read.unsigned_abs())
    }

    /// `sysctl(CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO)` — the
    /// whole IPv4 link-layer table of the current stack, as a sequence of
    /// `rt_msghdr`-prefixed records.
    ///
    /// Two calls, as `arp`(8) does it: one for the size, one for the data, with
    /// the second retried while it reports `ENOMEM` (the table can grow between
    /// them).
    pub fn lltable_dump() -> io::Result<Vec<u8>> {
        let mib: [libc::c_int; 6] = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            libc::AF_INET,
            libc::NET_RT_FLAGS,
            libc::RTF_LLINFO,
        ];
        let mut needed: libc::size_t = 0;
        // SAFETY: `mib` is a live array of exactly 6 `c_int`s and 6 is the
        // length passed. `oldp` is null, which is how `sysctl(3)` is asked for
        // the size only; `oldlenp` points at a live `size_t` the kernel writes.
        // `newp`/`newlen` are null/0, so nothing is set.
        let rc = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                6,
                std::ptr::null_mut(),
                &raw mut needed,
                std::ptr::null(),
                0,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if needed == 0 {
            return Ok(Vec::new());
        }
        // Bounded retry: a table that keeps growing must not loop forever.
        for _ in 0..8 {
            let mut buffer = vec![0u8; needed];
            let mut len = needed;
            // SAFETY: `buffer` is a live allocation of `needed` bytes and
            // `len == needed` is the capacity handed to the kernel, so its
            // write stays inside it; the kernel then lowers `len` to what it
            // actually wrote. `buffer` is `u8`, so every byte pattern is valid.
            let rc = unsafe {
                libc::sysctl(
                    mib.as_ptr(),
                    6,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    &raw mut len,
                    std::ptr::null(),
                    0,
                )
            };
            if rc == 0 {
                buffer.truncate(len);
                return Ok(buffer);
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOMEM) {
                return Err(err);
            }
            needed += needed / 8 + 1;
        }
        Err(io::Error::from_raw_os_error(libc::ENOMEM))
    }

    /// `if_indextoname`(3) on the current stack; `None` when the index is gone.
    pub fn if_name(index: u32) -> Option<String> {
        let mut buffer = [0u8; libc::IFNAMSIZ];
        // SAFETY: `buffer` is a live, exclusively borrowed array of exactly
        // `IFNAMSIZ` bytes, which is the buffer size `if_indextoname(3)` is
        // documented to write at most (name plus NUL). The cast between `u8`
        // and `c_char` is a reinterpretation of the same byte width. The
        // returned pointer is either null or `buffer`'s own, and is not used.
        let ok = unsafe { !libc::if_indextoname(index, buffer.as_mut_ptr().cast()).is_null() };
        if !ok {
            return None;
        }
        let end = buffer.iter().position(|byte| *byte == 0)?;
        String::from_utf8(buffer[..end].to_vec()).ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::fd::AsFd as _;

        /// The numbers below were printed by
        /// `hack/experiments/jail-arp/layout.c`, compiled against this host's
        /// `/usr/include` (FreeBSD 15.1-RELEASE-p2, amd64) —
        /// `captures/00-layout.txt`:
        ///
        /// ```text
        /// sizeof(struct rt_msghdr) = 152 align = 8
        ///   msglen=0 version=2 type=3 index=4 flags=8 addrs=12 pid=16
        ///   seq=20 errno=24 fmask=28 inits=32 rmx=40
        /// sizeof(struct rt_metrics) = 112 align = 8
        ///   locks=0 mtu=8 hopcount=16 expire=24 weight=80
        /// sizeof(struct sockaddr_dl) = 54 align = 2
        ///   len=0 family=1 index=2 type=4 nlen=5 alen=6 slen=7 data=8
        /// sizeof(struct sockaddr_in) = 16
        /// SA_SIZE(sockaddr_in) = 16   SA_SIZE(sockaddr_dl) = 56
        /// RTM_ADD message length = 224
        /// ```
        ///
        /// If any assertion here fails, these declarations have drifted from
        /// the kernel's and **no routing message may be written** — which is
        /// the point of asserting instead of hoping.
        #[test]
        fn rt_msghdr_layout_matches_the_kernel() {
            assert_eq!(size_of::<RtMsghdr>(), 152, "sizeof(struct rt_msghdr)");
            assert_eq!(align_of::<RtMsghdr>(), 8);
            let value = RtMsghdr::default();
            let base = std::ptr::from_ref(&value).addr();
            let at = |offset: usize, actual: usize| assert_eq!(actual - base, offset);
            at(0, std::ptr::from_ref(&value.msglen).addr());
            at(2, std::ptr::from_ref(&value.version).addr());
            at(3, std::ptr::from_ref(&value.r#type).addr());
            at(4, std::ptr::from_ref(&value.index).addr());
            at(8, std::ptr::from_ref(&value.flags).addr());
            at(12, std::ptr::from_ref(&value.addrs).addr());
            at(16, std::ptr::from_ref(&value.pid).addr());
            at(20, std::ptr::from_ref(&value.seq).addr());
            at(24, std::ptr::from_ref(&value.errno).addr());
            at(28, std::ptr::from_ref(&value.fmask).addr());
            at(32, std::ptr::from_ref(&value.inits).addr());
            at(40, std::ptr::from_ref(&value.rmx).addr());
        }

        #[test]
        fn rt_metrics_layout_matches_the_kernel() {
            assert_eq!(size_of::<RtMetrics>(), 112, "sizeof(struct rt_metrics)");
            assert_eq!(align_of::<RtMetrics>(), 8);
            let value = RtMetrics::default();
            let base = std::ptr::from_ref(&value).addr();
            let at = |offset: usize, actual: usize| assert_eq!(actual - base, offset);
            at(0, std::ptr::from_ref(&value.locks).addr());
            at(8, std::ptr::from_ref(&value.mtu).addr());
            at(16, std::ptr::from_ref(&value.hopcount).addr());
            at(24, std::ptr::from_ref(&value.expire).addr());
            at(80, std::ptr::from_ref(&value.weight).addr());
        }

        #[test]
        fn sockaddr_layouts_match_the_kernel() {
            assert_eq!(size_of::<libc::sockaddr_dl>(), 54);
            assert_eq!(align_of::<libc::sockaddr_dl>(), 2);
            assert_eq!(size_of::<libc::sockaddr_in>(), 16);
            let value = libc::sockaddr_dl {
                sdl_len: 0,
                sdl_family: 0,
                sdl_index: 0,
                sdl_type: 0,
                sdl_nlen: 0,
                sdl_alen: 0,
                sdl_slen: 0,
                sdl_data: [0; 46],
            };
            let base = std::ptr::from_ref(&value).addr();
            let at = |offset: usize, actual: usize| assert_eq!(actual - base, offset);
            at(0, std::ptr::from_ref(&value.sdl_len).addr());
            at(1, std::ptr::from_ref(&value.sdl_family).addr());
            at(2, std::ptr::from_ref(&value.sdl_index).addr());
            at(4, std::ptr::from_ref(&value.sdl_type).addr());
            at(5, std::ptr::from_ref(&value.sdl_nlen).addr());
            at(6, std::ptr::from_ref(&value.sdl_alen).addr());
            at(7, std::ptr::from_ref(&value.sdl_slen).addr());
            at(8, std::ptr::from_ref(&value.sdl_data).addr());
        }

        #[test]
        fn sa_size_rounds_the_way_the_macro_does() {
            assert_eq!(sa_size(0), 8, "the sa_len == 0 case");
            assert_eq!(sa_size(16), 16, "SA_SIZE(sockaddr_in)");
            assert_eq!(sa_size(54), 56, "SA_SIZE(sockaddr_dl)");
            assert_eq!(sa_size(1), 8);
            assert_eq!(sa_size(8), 8);
            assert_eq!(sa_size(9), 16);
        }

        #[test]
        fn constants_match_the_headers() {
            // From captures/00-layout.txt.
            assert_eq!(libc::RTM_VERSION, 5);
            assert_eq!(libc::RTM_ADD, 0x1);
            assert_eq!(libc::RTM_DELETE, 0x2);
            assert_eq!(libc::RTM_GET, 0x4);
            assert_eq!(libc::RTF_UP, 0x1);
            assert_eq!(libc::RTF_GATEWAY, 0x2);
            assert_eq!(libc::RTF_HOST, 0x4);
            assert_eq!(libc::RTF_LLDATA, 0x400);
            assert_eq!(libc::RTF_LLINFO, 0x400);
            assert_eq!(libc::RTF_STATIC, 0x800);
            assert_eq!(libc::RTF_PINNED, 0x0010_0000);
            assert_eq!(libc::RTA_DST, 0x1);
            assert_eq!(libc::RTA_GATEWAY, 0x2);
            assert_eq!(RTV_EXPIRE, 0x4);
            assert_eq!(libc::NET_RT_FLAGS, 2);
            assert_eq!(libc::CTL_NET, 4);
            assert_eq!(libc::PF_ROUTE, 17);
            assert_eq!(libc::AF_LINK, 18);
            assert_eq!(ARP_CAPABLE_IFTYPES, [6, 0x87, 0xd1]);
        }

        #[test]
        fn write_msg_refuses_a_length_beyond_the_value() {
            let socket = route_socket().expect("a PF_ROUTE socket needs no privileges");
            let msg = RtMsg::default();
            let err = write_msg(socket.as_fd(), &msg, size_of::<RtMsg>() + 1).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        }

        #[test]
        fn a_dump_of_the_hosts_own_table_parses_as_records() {
            // Unprivileged and read-only: proves the sysctl plumbing on every
            // developer machine, whatever the table happens to contain.
            let raw = lltable_dump().expect("NET_RT_FLAGS is readable unprivileged");
            assert_eq!(
                raw.len() % 4,
                0,
                "records are 4-byte aligned: {}",
                raw.len()
            );
        }

        #[test]
        fn if_name_resolves_real_indices_and_rejects_nonsense() {
            // Indices are not fixed (this host has ice0 at 1), so the assertion
            // is that lo0 exists *somewhere* in the low index space and that a
            // nonsense index resolves to nothing rather than to garbage.
            let names: Vec<String> = (1..256).filter_map(if_name).collect();
            assert!(
                names.iter().any(|name| name == "lo0"),
                "every stack has an lo0: {names:?}"
            );
            assert!(names.iter().all(|name| !name.is_empty()));
            assert_eq!(if_name(u32::MAX), None);
        }
    }
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// One row of the kernel's IPv4 link-layer table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlEntry {
    /// The address the entry resolves.
    pub ip: Ipv4Addr,
    /// Its MAC; `None` for an incomplete (unresolved) entry.
    pub mac: Option<MacAddr>,
    /// Index of the interface the entry hangs off.
    pub ifindex: u32,
    /// That interface's name in this stack, when it still resolves.
    pub iface: Option<String>,
    /// `rtm_flags`, verbatim. `0xc05` for an entry this crate installed,
    /// `0x100c05` for the kernel's entry for an interface's own address.
    pub flags: i32,
    /// `rmx_expire`; `0` means the entry never expires.
    pub expire: u64,
}

impl LlEntry {
    /// Whether the entry never expires and is never replaced by an ARP reply —
    /// `arp`(8) prints `permanent` on exactly this condition
    /// (`usr.sbin/arp/arp.c`, `print_entry`: `rtm_rmx.rmx_expire == 0`).
    #[must_use]
    pub fn permanent(&self) -> bool {
        self.expire == 0
    }

    /// Whether the kernel marked this entry immutable (`RTF_PINNED`, set for
    /// `LLE_IFADDR`): it is the stack's own address, cannot be deleted (`EPERM`)
    /// and is never SatL's to manage.
    #[must_use]
    pub fn pinned(&self) -> bool {
        self.flags & libc::RTF_PINNED != 0
    }
}

/// The interface an address is on-link for, as `RTM_GET` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkTarget {
    /// `sdl_index` — what `lla_rt_output()` requires to be non-zero.
    pub ifindex: u16,
    /// `sdl_type`, an `IFT_*` value.
    pub iftype: u8,
}

impl LinkTarget {
    /// The interface an existing entry hangs off, for [`RouteSocket::delete_on`].
    ///
    /// `IFT_ETHER` is assumed rather than read back: `lla_rt_output()` only uses
    /// `sdl_family` and `sdl_index` to find the table, and the type is not
    /// consulted on the delete path at all.
    #[must_use]
    pub fn of(entry: &LlEntry) -> Self {
        Self {
            ifindex: u16::try_from(entry.ifindex).unwrap_or(0),
            iftype: sys::ARP_CAPABLE_IFTYPES[0],
        }
    }
}

/// Error from the routing-socket layer.
///
/// Every variant names the operation, the address and the raw OS error: this is
/// the bottom of an SRE tool's stack, and a bare `Invalid argument` here is
/// useless three layers up.
#[derive(Debug, thiserror::Error)]
pub enum LlError {
    /// `jail_attach`(2) failed. An unknown jid is `EINVAL`, not `ENOENT`.
    #[error(
        "jail_attach({jid}) failed: {source}. An unknown jid reports EINVAL, so \
         this is what a task that exited before its ARP entries could be \
         programmed looks like"
    )]
    Attach {
        /// The jid that could not be entered.
        jid: i32,
        /// The raw OS error.
        #[source]
        source: io::Error,
    },

    /// `jail_get`(2) found no jail of that name.
    #[error("there is no jail named '{jail}' on this host: {source}")]
    NoSuchJail {
        /// The name that resolved to nothing.
        jail: String,
        /// The raw OS error.
        #[source]
        source: io::Error,
    },

    /// The `PF_ROUTE` socket could not be opened.
    #[error("could not open a PF_ROUTE socket: {source}")]
    Socket {
        /// The raw OS error.
        #[source]
        source: io::Error,
    },

    /// A routing message could not be written, or the kernel answered with
    /// `rtm_errno`.
    #[error("{op} for {ip} failed ({message} on a PF_ROUTE socket): {source}{hint}")]
    Rtsock {
        /// Human description, e.g. `install permanent ARP entry`.
        op: String,
        /// The routing message that carried it, e.g. `RTM_ADD`.
        message: &'static str,
        /// The address it was about.
        ip: Ipv4Addr,
        /// What to do about this errno, when known (starts with `; `).
        hint: String,
        /// The raw OS error.
        #[source]
        source: io::Error,
    },

    /// `RTM_GET` answered, but with something that is not an on-link Ethernet
    /// interface — so there is no ARP table to put an entry in.
    #[error(
        "{ip} is not on-link in this network stack ({reason}); a static ARP \
         entry needs the address to be covered by a directly attached prefix on \
         an Ethernet-like interface. Check that the task's epair holds an \
         address in the same subnet and is up (docs/vxlan.md section 4)"
    )]
    NotOnLink {
        /// The address that could not be placed.
        ip: Ipv4Addr,
        /// Which check failed.
        reason: String,
    },

    /// The link-layer table could not be read back.
    #[error(
        "could not read the link-layer table \
         (sysctl net.route.0.inet.flags.llinfo): {source}"
    )]
    Dump {
        /// The raw OS error.
        #[source]
        source: io::Error,
    },

    /// A record in the `sysctl` dump was malformed. Reported rather than
    /// skipped: this is a binary kernel interface, so a short record means the
    /// layout assumptions are wrong and nothing read from it can be trusted.
    #[error(
        "the link-layer table dump is malformed at byte {offset} of {total}: \
         {reason}"
    )]
    BadDump {
        /// Where parsing stopped.
        offset: usize,
        /// Total dump length.
        total: usize,
        /// Why it was rejected.
        reason: String,
    },
}

impl LlError {
    /// Whether this is `jail_attach`(2) failing because there is no such jail —
    /// i.e. the task exited between its assignment and this pass.
    ///
    /// As root an unknown jid is `EINVAL` (measured); `ENOENT` is accepted too
    /// because it is what the manual page describes. `EPERM` is deliberately
    /// **not** included: that is `satld` running without privilege, which must
    /// be reported, not absorbed as a benign race.
    #[must_use]
    pub fn jid_is_gone(&self) -> bool {
        match self {
            Self::Attach { source, .. } => {
                matches!(source.raw_os_error(), Some(libc::EINVAL | libc::ENOENT))
            }
            // A name that resolves to nothing is the same race, one step
            // earlier.
            Self::NoSuchJail { .. } => true,
            _ => false,
        }
    }
}

/// Errno-specific advice, so an operator is not left with `No such process`.
fn hint_for(err: &io::Error, message: &'static str) -> String {
    let advice = match err.raw_os_error() {
        Some(libc::ESRCH) => Some(
            "no route in this stack covers that address; from inside a task \
             jail that means the address is on no configured subnet",
        ),
        Some(libc::EHOSTUNREACH) => {
            Some("the address resolved through a gateway, so it is not on-link here")
        }
        Some(libc::ENOENT) if message == "RTM_DELETE" => {
            Some("there was no such entry, which is the idempotent case")
        }
        Some(libc::EPERM) if message == "RTM_DELETE" => Some(
            "the kernel refuses to delete an interface's own address \
             (LLE_IFADDR is immutable); this entry was never SatL's",
        ),
        Some(libc::EPERM) => Some("writing to a routing socket needs root"),
        Some(libc::EINVAL) => Some(
            "the kernel rejected the message: a link-layer entry needs \
             RTA_GATEWAY to be an AF_LINK sockaddr with a non-zero sdl_index",
        ),
        _ => None,
    };
    advice.map_or_else(String::new, |text| format!("; {text}"))
}

// ---------------------------------------------------------------------------
// The safe API
// ---------------------------------------------------------------------------

/// Move this process into `jid`'s jail — and therefore into its network stack.
///
/// **Irreversible.** Only ever call this in a process that exists to do one
/// batch of work and exit; [`crate::arphelper::child_main`] is that process.
pub fn attach(jid: i32) -> Result<(), LlError> {
    sys::jail_attach(jid).map_err(|source| LlError::Attach { jid, source })
}

/// Resolve a jail reference — a numeric jid or a jail name — to a jid.
///
/// A purely numeric string **is** a jid and is returned as-is, which is exactly
/// what `jail_getid`(3) does and what makes `ifconfig -j`, `route -j` and
/// `jexec` all accept either form. `satl-net` addresses jails by name, so
/// accepting both keeps one identifier flowing through the whole node-local
/// data plane.
pub fn resolve_jid(jail: &str) -> Result<i32, LlError> {
    if let Ok(jid) = jail.parse::<i32>() {
        return Ok(jid);
    }
    sys::jail_id_by_name(jail).map_err(|source| LlError::NoSuchJail {
        jail: jail.to_owned(),
        source,
    })
}

/// Resolve `jail` and attach to it, returning the jid entered.
pub fn attach_to(jail: &str) -> Result<i32, LlError> {
    let jid = resolve_jid(jail)?;
    attach(jid)?;
    Ok(jid)
}

/// The whole IPv4 link-layer table of the **current** stack.
pub fn table() -> Result<Vec<LlEntry>, LlError> {
    let raw = sys::lltable_dump().map_err(|source| LlError::Dump { source })?;
    parse_dump(&raw)
}

/// The framing of one routing message: which message it is, which sockaddrs it
/// carries, and how long it is.
#[derive(Debug, Clone, Copy)]
struct Wire {
    /// `RTM_*`.
    kind: u8,
    /// Its symbolic name, for the error message.
    message: &'static str,
    /// `RTA_*` bitmask of the sockaddrs written into the tail.
    addrs: i32,
    /// `rtm_msglen`: header plus those sockaddrs.
    len: usize,
}

impl Wire {
    fn new(kind: libc::c_int, message: &'static str, addrs: i32, tail: usize) -> Self {
        Self {
            // Infallible for every RTM_* this module uses (1, 2 and 4).
            kind: u8::try_from(kind).unwrap_or(0),
            message,
            addrs,
            len: size_of::<sys::RtMsghdr>() + tail,
        }
    }
}

/// A `PF_ROUTE` socket on the current stack, with the sequencing `arp`(8) uses.
///
/// Not `Clone` and not `Sync` on purpose: `rtm_seq` is per-socket state, and
/// two callers interleaving on one socket would read each other's replies.
#[derive(Debug)]
pub struct RouteSocket {
    fd: std::os::fd::OwnedFd,
    seq: i32,
    pid: i32,
}

impl RouteSocket {
    /// Open one. Reading needs no privileges; writing needs root.
    pub fn open() -> Result<Self, LlError> {
        let fd = sys::route_socket().map_err(|source| LlError::Socket { source })?;
        Ok(Self {
            fd,
            seq: 0,
            // `getpid` cannot fail and needs no `unsafe` through `std`.
            pid: i32::try_from(std::process::id()).unwrap_or(0),
        })
    }

    /// Write one message and read back the reply that belongs to it.
    fn exchange(
        &mut self,
        wire: Wire,
        op: &str,
        ip: Ipv4Addr,
        msg: &mut sys::RtMsg,
    ) -> Result<(), LlError> {
        let Wire {
            kind,
            message,
            addrs,
            len,
        } = wire;
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        msg.hdr.version = u8::try_from(libc::RTM_VERSION).unwrap_or(5);
        msg.hdr.r#type = kind;
        msg.hdr.addrs = addrs;
        msg.hdr.seq = seq;
        msg.hdr.msglen = u16::try_from(len).unwrap_or(u16::MAX);

        let fail = |source: io::Error| LlError::Rtsock {
            op: op.to_owned(),
            message,
            ip,
            hint: hint_for(&source, message),
            source,
        };

        sys::write_msg(self.fd.as_fd(), msg, len).map_err(fail)?;
        // The reply that matters is the one with our own pid and sequence
        // number: a routing socket is a broadcast bus and carries every other
        // subscriber's traffic too. Bounded rather than `loop`, so a child that
        // somehow never sees its own reply exits instead of hanging forever with
        // a jail attached.
        let mut matched = false;
        for _ in 0..MAX_REPLIES_SCANNED {
            let read = sys::read_msg(self.fd.as_fd(), msg).map_err(fail)?;
            if read == 0 {
                return Err(fail(io::Error::from_raw_os_error(libc::EIO)));
            }
            if msg.hdr.r#type == kind && msg.hdr.seq == seq && msg.hdr.pid == self.pid {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(fail(io::Error::from_raw_os_error(libc::ETIMEDOUT)));
        }
        if msg.hdr.errno != 0 {
            return Err(fail(io::Error::from_raw_os_error(msg.hdr.errno)));
        }
        Ok(())
    }

    /// `RTM_GET`: which interface is `ip` on-link for in this stack?
    ///
    /// This is the step that decides whether an entry can exist at all. The two
    /// ways it says no are both measured
    /// (`hack/experiments/jail-arp/captures/30-premise-and-mechanism.txt` §6):
    /// `ESRCH` when no route covers the address, and — in a jail that has a
    /// **default route**, which every production task does — a reply describing
    /// that gateway, which is caught by the `AF_LINK` check rather than by the
    /// lookup failing.
    pub fn resolve_link(&mut self, ip: Ipv4Addr) -> Result<LinkTarget, LlError> {
        let mut msg = sys::RtMsg::default();
        let dst = sockaddr_in(ip);
        let dst_size = write_sockaddr_in(&mut msg.space, 0, &dst);
        self.exchange(
            Wire::new(libc::RTM_GET, "RTM_GET", libc::RTA_DST, dst_size),
            &format!("look up the on-link interface for {ip}"),
            ip,
            &mut msg,
        )?;

        if msg.hdr.addrs & libc::RTA_GATEWAY == 0 {
            return Err(LlError::NotOnLink {
                ip,
                reason: format!(
                    "the RTM_GET reply carried no RTA_GATEWAY sockaddr \
                     (rtm_addrs = {:#x})",
                    msg.hdr.addrs
                ),
            });
        }
        // The reply lays its sockaddrs out in RTAX order, so RTA_GATEWAY starts
        // one SA_SIZE past RTA_DST — exactly as arp(8)'s set_rtsock() reads it.
        let reply_dst_len = msg.space.first().copied().unwrap_or(0);
        let sdl = read_sockaddr_dl(&msg.space, sys::sa_size(reply_dst_len)).ok_or_else(|| {
            LlError::NotOnLink {
                ip,
                reason: "the RTM_GET reply's RTA_GATEWAY sockaddr is truncated".to_owned(),
            }
        })?;

        if u32::from(sdl.sdl_family) != u32::try_from(libc::AF_LINK).unwrap_or(18) {
            return Err(LlError::NotOnLink {
                ip,
                reason: format!(
                    "the route to it has an address-family-{} gateway rather \
                     than an AF_LINK one, i.e. it resolves through a router \
                     (often the task's default route)",
                    sdl.sdl_family
                ),
            });
        }
        if msg.hdr.flags & libc::RTF_GATEWAY != 0 {
            return Err(LlError::NotOnLink {
                ip,
                reason: "the matching route is indirect (RTF_GATEWAY)".to_owned(),
            });
        }
        if sdl.sdl_index == 0 {
            return Err(LlError::NotOnLink {
                ip,
                reason: "the gateway sockaddr has no interface index, which \
                         lla_rt_output() requires"
                    .to_owned(),
            });
        }
        if !sys::ARP_CAPABLE_IFTYPES.contains(&sdl.sdl_type) {
            return Err(LlError::NotOnLink {
                ip,
                reason: format!(
                    "it is on interface type {} (IFT_*), which has no ARP",
                    sdl.sdl_type
                ),
            });
        }
        Ok(LinkTarget {
            ifindex: sdl.sdl_index,
            iftype: sdl.sdl_type,
        })
    }

    /// Install a **permanent** entry `ip -> mac`, replacing any existing one.
    ///
    /// Measured: `RTM_ADD` on an address already in the table replaces it and
    /// reports success, so a moved endpoint needs no delete first — the opposite
    /// of the VXLAN FDB's `EEXIST`.
    #[tracing::instrument(skip(self), fields(ip = %ip, mac = %mac))]
    pub fn add(&mut self, ip: Ipv4Addr, mac: MacAddr) -> Result<(), LlError> {
        let target = self.resolve_link(ip)?;
        let mut msg = sys::RtMsg::default();
        let dst = sockaddr_in(ip);
        let dst_size = write_sockaddr_in(&mut msg.space, 0, &dst);
        let gw = sockaddr_dl(target, Some(mac));
        let gw_size = write_sockaddr_dl(&mut msg.space, dst_size, &gw);

        msg.hdr.flags = libc::RTF_HOST | libc::RTF_STATIC | libc::RTF_LLDATA;
        // rmx_expire == 0 with RTV_EXPIRE set is what makes it LLE_STATIC, i.e.
        // never expiring and never replaced by an ARP reply.
        msg.hdr.inits = sys::RTV_EXPIRE;
        msg.hdr.rmx.expire = 0;

        self.exchange(
            Wire::new(
                libc::RTM_ADD,
                "RTM_ADD",
                libc::RTA_DST | libc::RTA_GATEWAY,
                dst_size + gw_size,
            ),
            &format!("install permanent ARP entry {ip} -> {mac}"),
            ip,
            &mut msg,
        )?;
        tracing::debug!("installed permanent link-layer entry");
        Ok(())
    }

    /// Remove the entry for `ip`, resolving its interface with `RTM_GET` first.
    ///
    /// Prefer [`Self::delete_on`] when the entry's own interface index is
    /// already known from a table read: `RTM_GET` needs the address to still be
    /// **on-link**, and an entry can outlive the address that made it so.
    #[tracing::instrument(skip(self), fields(ip = %ip))]
    pub fn delete(&mut self, ip: Ipv4Addr) -> Result<bool, LlError> {
        let target = self.resolve_link(ip)?;
        self.delete_on(ip, target)
    }

    /// Remove the entry for `ip` from the interface it is actually on;
    /// `Ok(false)` when there was none.
    ///
    /// `lla_rt_output()` requires an `AF_LINK` gateway with a non-zero
    /// `sdl_index` even to delete (the check sits above its `switch`), so the
    /// interface has to come from somewhere. Taking it from the entry itself —
    /// [`LlEntry::ifindex`], as [`table`] read it — rather than from a fresh
    /// route lookup makes deletion independent of the stack's current routing
    /// state, which matters during teardown.
    ///
    /// `ENOENT` is the idempotent case and is swallowed. `EPERM` is not: it means
    /// the address belongs to an interface in this stack and the kernel refuses
    /// to delete it, which the caller has to see.
    #[tracing::instrument(skip(self), fields(ip = %ip))]
    pub fn delete_on(&mut self, ip: Ipv4Addr, target: LinkTarget) -> Result<bool, LlError> {
        let mut msg = sys::RtMsg::default();
        let dst = sockaddr_in(ip);
        let dst_size = write_sockaddr_in(&mut msg.space, 0, &dst);
        // No MAC: lla_rt_output() only needs the AF_LINK family and the index
        // to find the table, and lltable_delete_addr() keys off the address.
        let gw = sockaddr_dl(target, None);
        let gw_size = write_sockaddr_dl(&mut msg.space, dst_size, &gw);
        msg.hdr.flags = libc::RTF_HOST | libc::RTF_STATIC | libc::RTF_LLDATA;

        match self.exchange(
            Wire::new(
                libc::RTM_DELETE,
                "RTM_DELETE",
                libc::RTA_DST | libc::RTA_GATEWAY,
                dst_size + gw_size,
            ),
            &format!("withdraw ARP entry {ip}"),
            ip,
            &mut msg,
        ) {
            Ok(()) => {
                tracing::debug!("withdrew link-layer entry");
                Ok(true)
            }
            Err(LlError::Rtsock { source, .. }) if source.raw_os_error() == Some(libc::ENOENT) => {
                tracing::debug!("link-layer entry was already absent");
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure message construction and parsing
// ---------------------------------------------------------------------------

fn sockaddr_in(ip: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        // Infallible: sizeof(sockaddr_in) is 16, asserted in sys's tests.
        sin_len: u8::try_from(size_of::<libc::sockaddr_in>()).unwrap_or(16),
        sin_family: u8::try_from(libc::AF_INET).unwrap_or(2),
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    }
}

fn sockaddr_dl(target: LinkTarget, mac: Option<MacAddr>) -> libc::sockaddr_dl {
    let mut data = [0; 46];
    let mut alen = 0;
    if let Some(mac) = mac {
        // sdl_nlen is 0, so LLADDR() is &sdl_data[0].
        for (slot, byte) in data.iter_mut().zip(mac.octets()) {
            *slot = cast_to_c_char(byte);
        }
        alen = ETHER_ADDR_LEN;
    }
    libc::sockaddr_dl {
        // Always the full struct: cleanup_xaddrs_lladdr() checks
        // offsetof(sdl_data) + sdl_nlen + sdl_alen <= sdl_len, and 8 + 0 + 6
        // fits in 54 with room to spare.
        sdl_len: u8::try_from(size_of::<libc::sockaddr_dl>()).unwrap_or(54),
        sdl_family: u8::try_from(libc::AF_LINK).unwrap_or(18),
        sdl_index: target.ifindex,
        sdl_type: target.iftype,
        sdl_nlen: 0,
        sdl_alen: alen,
        sdl_slen: 0,
        sdl_data: data,
    }
}

/// Copy a `sockaddr_in` into the message tail at `offset`; returns its
/// `SA_SIZE`.
///
/// Serialised field by field rather than transmuted: the layout is asserted in
/// [`sys`]'s tests, and writing it out means the compiler checks every offset.
fn write_sockaddr_in(
    space: &mut [u8; sys::RTMSG_SPACE],
    offset: usize,
    sa: &libc::sockaddr_in,
) -> usize {
    space[offset] = sa.sin_len;
    space[offset + 1] = sa.sin_family;
    // sin_port is already in network order, and is always 0 for a route.
    space[offset + 2..offset + 4].copy_from_slice(&sa.sin_port.to_ne_bytes());
    space[offset + 4..offset + 8].copy_from_slice(&sa.sin_addr.s_addr.to_ne_bytes());
    // sin_zero: eight bytes the kernel requires to be zero.
    space[offset + 8..offset + 16].fill(0);
    sys::sa_size(sa.sin_len)
}

/// Copy a `sockaddr_dl` into the message tail at `offset`; returns the number of
/// bytes the message must account for.
///
/// **Not** `SA_SIZE`: `arp`(8) writes `sizeof(struct sockaddr_dl)` for the
/// gateway (`NEXTADDR` advances by `SA_SIZE`, but the trailing message length is
/// computed from where the copy ended). 54 and 56 both work — the kernel reads
/// `sdl_len` — and 54 is what `arp`(8) sends, so it is what is sent here.
fn write_sockaddr_dl(
    space: &mut [u8; sys::RTMSG_SPACE],
    offset: usize,
    sa: &libc::sockaddr_dl,
) -> usize {
    space[offset] = sa.sdl_len;
    space[offset + 1] = sa.sdl_family;
    space[offset + 2..offset + 4].copy_from_slice(&sa.sdl_index.to_ne_bytes());
    space[offset + 4] = sa.sdl_type;
    space[offset + 5] = sa.sdl_nlen;
    space[offset + 6] = sa.sdl_alen;
    space[offset + 7] = sa.sdl_slen;
    let data = &mut space[offset + 8..offset + 8 + sa.sdl_data.len()];
    for (slot, byte) in data.iter_mut().zip(&sa.sdl_data) {
        *slot = cast_c_char(*byte);
    }
    size_of::<libc::sockaddr_dl>()
}

/// `c_char` is `i8` on amd64 and `u8` on arm64, so `as` is the only conversion
/// that compiles on both — and a link-level address wants exactly this
/// byte-for-byte reinterpretation, not a numeric conversion.
#[allow(clippy::cast_sign_loss)]
const fn cast_c_char(byte: libc::c_char) -> u8 {
    byte as u8
}

/// The inverse of [`cast_c_char`].
#[allow(clippy::cast_possible_wrap)]
const fn cast_to_c_char(byte: u8) -> libc::c_char {
    byte as libc::c_char
}

/// Read a `sockaddr_dl` out of a message tail, or `None` if it does not fit.
fn read_sockaddr_dl(space: &[u8], offset: usize) -> Option<libc::sockaddr_dl> {
    let bytes = space.get(offset..offset + 8)?;
    let mut data = [0; 46];
    if let Some(tail) = space.get(offset + 8..offset + 8 + data.len()) {
        for (slot, byte) in data.iter_mut().zip(tail) {
            *slot = cast_to_c_char(*byte);
        }
    }
    Some(libc::sockaddr_dl {
        sdl_len: bytes[0],
        sdl_family: bytes[1],
        sdl_index: u16::from_ne_bytes([bytes[2], bytes[3]]),
        sdl_type: bytes[4],
        sdl_nlen: bytes[5],
        sdl_alen: bytes[6],
        sdl_slen: bytes[7],
        sdl_data: data,
    })
}

/// Parse the `sysctl(NET_RT_FLAGS)` dump: a sequence of records, each an
/// `rt_msghdr` followed by a `sockaddr_in` (the address) and a `sockaddr_dl`
/// (the link-layer address), exactly as `arp`(8)'s `search()` walks them.
fn parse_dump(raw: &[u8]) -> Result<Vec<LlEntry>, LlError> {
    let header = size_of::<sys::RtMsghdr>();
    let mut entries = Vec::new();
    let mut offset = 0;
    let bad = |offset: usize, reason: &str| LlError::BadDump {
        offset,
        total: raw.len(),
        reason: reason.to_owned(),
    };
    while offset < raw.len() {
        let record = raw
            .get(offset..)
            .ok_or_else(|| bad(offset, "record starts past the end of the dump"))?;
        if record.len() < header {
            return Err(bad(
                offset,
                "fewer bytes left than one rt_msghdr; the header layout must \
                 have drifted from the kernel's",
            ));
        }
        // rtm_msglen is the first field, and rtm_flags/rtm_rmx.rmx_expire are
        // at the offsets asserted in sys's tests.
        let msglen = usize::from(u16::from_ne_bytes([record[0], record[1]]));
        if msglen < header || msglen > record.len() {
            return Err(bad(
                offset,
                &format!("rtm_msglen is {msglen}, which is not a whole record"),
            ));
        }
        let flags = i32::from_ne_bytes([record[8], record[9], record[10], record[11]]);
        let expire = u64::from_ne_bytes([
            record[64], record[65], record[66], record[67], record[68], record[69], record[70],
            record[71],
        ]);

        let tail = &record[header..msglen];
        let sin_len = *tail
            .first()
            .ok_or_else(|| bad(offset, "record has no RTA_DST sockaddr"))?;
        let s_addr = tail
            .get(4..8)
            .ok_or_else(|| bad(offset, "RTA_DST sockaddr is truncated"))?;
        let ip = Ipv4Addr::from([s_addr[0], s_addr[1], s_addr[2], s_addr[3]]);
        let sdl = read_sockaddr_dl(tail, sys::sa_size(sin_len))
            .ok_or_else(|| bad(offset, "record has no RTA_GATEWAY sockaddr"))?;

        // LLADDR() is &sdl_data[sdl_nlen]: the name, when present, comes first.
        let lladdr = usize::from(sdl.sdl_nlen);
        let mac = sdl
            .sdl_data
            .get(lladdr..lladdr + usize::from(ETHER_ADDR_LEN))
            .filter(|_| sdl.sdl_alen == ETHER_ADDR_LEN)
            .map(|bytes| {
                let mut octets = [0; 6];
                for (slot, byte) in octets.iter_mut().zip(bytes) {
                    *slot = cast_c_char(*byte);
                }
                MacAddr::from_octets(octets)
            });
        let ifindex = u32::from(sdl.sdl_index);
        entries.push(LlEntry {
            ip,
            mac,
            ifindex,
            iface: sys::if_name(ifindex),
            flags,
            expire,
        });
        offset += msglen;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("valid address")
    }

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("valid MAC")
    }

    // ---- message construction ---------------------------------------------

    #[test]
    fn a_dst_sockaddr_is_16_bytes_of_the_right_shape() {
        let mut space = [0u8; sys::RTMSG_SPACE];
        let size = write_sockaddr_in(&mut space, 0, &sockaddr_in(ip("10.79.0.12")));
        assert_eq!(size, 16, "SA_SIZE(sockaddr_in)");
        assert_eq!(space[0], 16, "sin_len");
        assert_eq!(space[1], 2, "sin_family == AF_INET");
        assert_eq!(&space[4..8], &[10, 79, 0, 12], "sin_addr, network order");
        assert!(space[16..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_gateway_sockaddr_carries_the_index_type_and_mac() {
        let mut space = [0u8; sys::RTMSG_SPACE];
        let target = LinkTarget {
            ifindex: 22,
            iftype: 6,
        };
        let size = write_sockaddr_dl(
            &mut space,
            16,
            &sockaddr_dl(target, Some(mac("02:42:0a:4f:00:0c"))),
        );
        assert_eq!(size, 54, "arp(8) sends sizeof(struct sockaddr_dl)");
        assert_eq!(space[16], 54, "sdl_len");
        assert_eq!(space[17], 18, "sdl_family == AF_LINK");
        assert_eq!(u16::from_ne_bytes([space[18], space[19]]), 22, "sdl_index");
        assert_eq!(space[20], 6, "sdl_type == IFT_ETHER");
        assert_eq!(space[21], 0, "sdl_nlen: no name, so LLADDR is sdl_data[0]");
        assert_eq!(space[22], 6, "sdl_alen");
        assert_eq!(&space[24..30], &[0x02, 0x42, 0x0a, 0x4f, 0x00, 0x0c]);
        // ...and it round-trips through the reader the reply path uses.
        let back = read_sockaddr_dl(&space, 16).expect("readable");
        assert_eq!(back.sdl_index, 22);
        assert_eq!(back.sdl_alen, 6);
    }

    #[test]
    fn a_delete_gateway_sockaddr_carries_no_mac() {
        let mut space = [0u8; sys::RTMSG_SPACE];
        write_sockaddr_dl(
            &mut space,
            0,
            &sockaddr_dl(
                LinkTarget {
                    ifindex: 7,
                    iftype: 6,
                },
                None,
            ),
        );
        assert_eq!(space[6], 0, "sdl_alen must be 0 with no link address");
        assert!(space[8..54].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn the_whole_add_message_is_the_length_the_c_reference_computes() {
        // layout.c: sizeof(rt_msghdr) 152 + SA_SIZE(sockaddr_in) 16 +
        // sizeof(sockaddr_dl) 54 = 222; with SA_SIZE(sockaddr_dl) it is 224.
        let mut space = [0u8; sys::RTMSG_SPACE];
        let dst = write_sockaddr_in(&mut space, 0, &sockaddr_in(ip("10.79.0.12")));
        let gw = write_sockaddr_dl(
            &mut space,
            dst,
            &sockaddr_dl(
                LinkTarget {
                    ifindex: 1,
                    iftype: 6,
                },
                Some(mac("02:42:0a:4f:00:0c")),
            ),
        );
        assert_eq!(size_of::<sys::RtMsghdr>() + dst + gw, 222);
        assert!(size_of::<sys::RtMsghdr>() + dst + gw < size_of::<sys::RtMsg>());
    }

    // ---- dump parsing against a synthesised record ------------------------

    /// Build one dump record the way the kernel lays it out, so the parser is
    /// tested on the exact byte positions `sys`'s assertions pin down.
    fn record(
        ip: Ipv4Addr,
        mac: Option<MacAddr>,
        ifindex: u16,
        flags: i32,
        expire: u64,
    ) -> Vec<u8> {
        let header = size_of::<sys::RtMsghdr>();
        let mut bytes = vec![0u8; header];
        let mut space = [0u8; sys::RTMSG_SPACE];
        let dst = write_sockaddr_in(&mut space, 0, &sockaddr_in(ip));
        let gw = write_sockaddr_dl(
            &mut space,
            dst,
            &sockaddr_dl(LinkTarget { ifindex, iftype: 6 }, mac),
        );
        bytes.extend_from_slice(&space[..dst + gw]);
        let msglen = u16::try_from(bytes.len()).expect("fits");
        bytes[0..2].copy_from_slice(&msglen.to_ne_bytes());
        bytes[8..12].copy_from_slice(&flags.to_ne_bytes());
        bytes[64..72].copy_from_slice(&expire.to_ne_bytes());
        bytes
    }

    #[test]
    fn parse_dump_reads_ours_the_kernels_and_an_incomplete_entry() {
        // The three shapes measured in captures/30-premise-and-mechanism.txt:
        // ours (0xc05, permanent), the stack's own address (0x100c05, pinned),
        // and an unresolved one (0x405, alen 0, non-zero expire).
        let mut raw = record(
            ip("10.79.9.12"),
            Some(mac("02:42:0a:4f:09:0c")),
            22,
            0xc05,
            0,
        );
        raw.extend(record(
            ip("10.79.9.11"),
            Some(mac("02:42:0a:4f:09:0b")),
            22,
            0x0010_0c05,
            0,
        ));
        raw.extend(record(ip("10.79.9.13"), None, 22, 0x405, 44115));

        let entries = parse_dump(&raw).expect("parses");
        assert_eq!(entries.len(), 3);

        let ours = &entries[0];
        assert_eq!(ours.ip, ip("10.79.9.12"));
        assert_eq!(ours.mac, Some(mac("02:42:0a:4f:09:0c")));
        assert_eq!(ours.ifindex, 22);
        assert!(ours.permanent());
        assert!(!ours.pinned(), "an entry we installed is not RTF_PINNED");

        let own = &entries[1];
        assert!(own.permanent());
        assert!(
            own.pinned(),
            "the stack's own address is RTF_PINNED (LLE_IFADDR)"
        );

        let incomplete = &entries[2];
        assert_eq!(incomplete.mac, None);
        assert!(!incomplete.permanent());
        assert!(!incomplete.pinned());
    }

    #[test]
    fn parse_dump_accepts_an_empty_table() {
        assert!(parse_dump(&[]).expect("empty is fine").is_empty());
    }

    #[test]
    fn parse_dump_rejects_a_truncated_or_lying_record() {
        let good = record(
            ip("10.79.9.12"),
            Some(mac("02:42:0a:4f:09:0c")),
            22,
            0xc05,
            0,
        );

        // Fewer bytes than one header.
        let err = parse_dump(&good[..40]).unwrap_err();
        assert!(err.to_string().contains("rt_msghdr"), "{err}");

        // rtm_msglen larger than what is there.
        let mut lying = good.clone();
        lying[0..2].copy_from_slice(&u16::MAX.to_ne_bytes());
        let err = parse_dump(&lying).unwrap_err();
        assert!(err.to_string().contains("rtm_msglen is 65535"), "{err}");

        // rtm_msglen smaller than the header.
        let mut tiny = good;
        tiny[0..2].copy_from_slice(&8u16.to_ne_bytes());
        let err = parse_dump(&tiny).unwrap_err();
        assert!(err.to_string().contains("not a whole record"), "{err}");
    }

    // ---- errors -----------------------------------------------------------

    #[test]
    fn errno_hints_name_the_cause() {
        let hint = |errno: i32, message: &'static str| {
            hint_for(&io::Error::from_raw_os_error(errno), message)
        };
        assert!(hint(libc::ESRCH, "RTM_GET").contains("no route"));
        assert!(hint(libc::EHOSTUNREACH, "RTM_GET").contains("gateway"));
        assert!(hint(libc::ENOENT, "RTM_DELETE").contains("idempotent"));
        assert!(hint(libc::EPERM, "RTM_DELETE").contains("LLE_IFADDR"));
        assert!(hint(libc::EPERM, "RTM_ADD").contains("root"));
        assert!(hint(libc::EINVAL, "RTM_ADD").contains("sdl_index"));
        assert!(hint(libc::EIO, "RTM_ADD").is_empty());
    }

    #[test]
    fn attach_to_a_nonexistent_jid_is_a_typed_error_naming_the_jid() {
        // The errno depends on who is asking, which is why the *parent* treats
        // EINVAL and ENOENT as "the jail is gone" and nothing else: as root,
        // jail_attach on an unknown jid is EINVAL (measured,
        // hack/experiments/jail-arp/captures/30-premise-and-mechanism.txt §6a);
        // unprivileged the privilege check fires first and it is EPERM. This
        // test therefore asserts the shape, and `jid_is_gone` asserts the
        // mapping.
        let err = attach(0x7fff_fffe).unwrap_err();
        let LlError::Attach { jid, source } = &err else {
            panic!("expected an Attach error, got {err:?}");
        };
        assert_eq!(*jid, 0x7fff_fffe);
        assert!(
            matches!(
                source.raw_os_error(),
                Some(libc::EINVAL | libc::ENOENT | libc::EPERM)
            ),
            "unexpected errno from jail_attach: {source}"
        );
        assert!(err.to_string().contains("jail_attach(2147483646)"), "{err}");
    }

    #[test]
    fn jid_is_gone_recognises_only_the_lookup_failures() {
        let gone = |errno: i32| {
            LlError::Attach {
                jid: 7,
                source: io::Error::from_raw_os_error(errno),
            }
            .jid_is_gone()
        };
        assert!(gone(libc::EINVAL), "as root, an unknown jid is EINVAL");
        assert!(gone(libc::ENOENT));
        assert!(
            !gone(libc::EPERM),
            "a privilege failure is a misconfiguration, not a vanished jail"
        );
        assert!(
            !LlError::Socket {
                source: io::Error::from_raw_os_error(libc::EPERM)
            }
            .jid_is_gone()
        );
        assert!(
            LlError::NoSuchJail {
                jail: "satl-t1".to_owned(),
                source: io::Error::from_raw_os_error(libc::ENOENT),
            }
            .jid_is_gone()
        );
    }

    #[test]
    fn a_jail_reference_is_either_a_jid_or_a_name() {
        // A purely numeric reference is a jid and never hits the syscall, so it
        // resolves even to a jail that does not exist — jail_getid(3) behaves
        // the same way, and jail_attach is where a bad jid is caught.
        assert_eq!(resolve_jid("52").unwrap(), 52);
        assert_eq!(resolve_jid("0").unwrap(), 0);
        // A name that matches no jail is ENOENT, and is the "jail is gone" race.
        let err = resolve_jid("satl-no-such-jail-exists").unwrap_err();
        assert!(matches!(err, LlError::NoSuchJail { .. }), "{err:?}");
        assert!(err.jid_is_gone(), "{err}");
        assert!(
            err.to_string().contains("satl-no-such-jail-exists"),
            "{err}"
        );
    }

    // ---- live, unprivileged exercise of the safe wrapper ------------------

    #[test]
    fn the_hosts_own_table_reads_back() {
        // Needs no privileges and mutates nothing: this is the same code path
        // the helper child uses after attaching, run on the host's stack.
        let entries = table().expect("the link-layer table is world-readable");
        for entry in &entries {
            assert!(
                entry.mac.is_some() || !entry.permanent(),
                "a permanent entry with no MAC makes no sense: {entry:?}"
            );
            if let Some(name) = &entry.iface {
                assert!(!name.is_empty());
            }
        }
    }

    #[test]
    fn resolve_link_refuses_an_address_on_no_local_prefix() {
        // 240/4 (reserved) is on no interface anywhere, so the RTM_GET either
        // fails outright (ESRCH, no default route) or comes back describing a
        // gateway. Both are refusals, and both must be typed.
        let mut socket = RouteSocket::open().expect("a routing socket needs no privileges");
        let err = socket
            .resolve_link(ip("240.0.0.1"))
            .expect_err("240.0.0.1 can never be on-link");
        let text = err.to_string();
        assert!(
            matches!(err, LlError::NotOnLink { .. } | LlError::Rtsock { .. }),
            "{err:?}"
        );
        assert!(text.contains("240.0.0.1"), "{text}");
    }

    #[test]
    fn resolve_link_refuses_a_loopback_address_that_does_exist() {
        // 127.0.0.1 is on lo0 in every stack, so the RTM_GET succeeds — and the
        // reply still has to be refused, because lo0 has no ARP. Measured here:
        // the loopback host route reports an AF_INET gateway, so it is the
        // AF_LINK check that catches it before the interface-type check ever
        // runs. Either refusal is correct; what must not happen is an entry.
        let mut socket = RouteSocket::open().expect("routing socket");
        let err = socket
            .resolve_link(ip("127.0.0.1"))
            .expect_err("lo0 has no ARP table to put an entry in");
        assert!(matches!(err, LlError::NotOnLink { .. }), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("127.0.0.1 is not on-link"), "{text}");
        assert!(
            text.contains("AF_LINK") || text.contains("has no ARP"),
            "{text}"
        );
    }
}
