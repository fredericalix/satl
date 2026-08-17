// SPDX-License-Identifier: BSD-2-Clause
//! [`TaskOverlay`] — the seam through which a task controller reaches the
//! node's overlay plumbing.
//!
//! The controller is the only place that touches a task's node-local
//! resources ([`crate::controller`]), and an overlay attachment is one of
//! them: an epair whose `b` end goes into the jail's VNET, a static ARP entry
//! in that jail's stack, and a `resolv.conf` pointing at this node's gateway
//! on the network. All three need the jail, so all three are the controller's
//! business — but *which* overlays a task is on, what their VNIs and subnets
//! are and where every peer endpoint lives is **cluster** state that arrives
//! on the dispatcher's assignment stream (architecture §11.2), which this
//! crate never sees.
//!
//! So the overlay programmer lives in `satld`, where both halves meet, and
//! reaches the controller through this trait. Three calls, at the three points
//! in a task's life where the overlay is visible:
//!
//! | Call | When | Why there |
//! |---|---|---|
//! | [`TaskOverlay::resolv_conf`] | `prepare`, writing `resolv.conf` | the file is content in the writable layer, so it has to exist before the container starts |
//! | [`TaskOverlay::attach`] | `start`, after `ocijail create`, before `ocijail start` | the epair's `b` end needs a jail to move into, and the container must not run before its network exists |
//! | [`TaskOverlay::detach`] | as soon as the container is terminal — `wait`'s exit arm, the health gate's exit arm, any failed `start` past the attach — and again at `remove` | the allocator frees a terminal task's addresses (SWK §9.4) and a replacement can inherit one within seconds; the epair also outlives the jail (CLAUDE.md's VNET-cleanup gotcha) |
//!
//! A node with no overlay networks has no implementation at all
//! ([`crate::ExecutorParts::overlay`] is `None`) and every call above is
//! skipped, which is what keeps the M1 single-node path free of overlay code.

use async_trait::async_trait;
use satl_core::{Id, Task};

/// Failure programming a task's overlay attachment.
///
/// Transparent over the real error so the chain the implementation built — the
/// `ifconfig` argv, the ioctl errno, the jail that vanished — reaches the task
/// status and the log unchanged. This crate has no vocabulary for those and
/// must not invent one.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct OverlayError(#[from] pub Box<dyn std::error::Error + Send + Sync>);

impl OverlayError {
    /// Wraps any error the overlay programmer produced.
    pub fn new<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(error))
    }
}

/// The node's overlay plumbing, as a task controller needs it.
///
/// Implemented in `satld` (`satld::overlay::OverlayManager`). Every method is
/// **idempotent**: the controller is re-entrant by contract (architecture
/// §8.2), so each of them may be called again on a task whose plumbing is
/// already in place.
#[async_trait]
pub trait TaskOverlay: Send + Sync + 'static {
    /// The `/etc/resolv.conf` `task`'s container should get: one `nameserver`
    /// line per overlay network it attaches to, holding **this node's** gateway
    /// address on that network, which is where the embedded responder listens.
    ///
    /// Rendered here rather than assembled by the controller because the file's
    /// shape is the responder's business (`satl_overlay::OverlayResolvConf`
    /// decides what happens to the host's `search`/`options` and to a task's
    /// `--dns-search`), and this crate must not grow a second opinion about it.
    ///
    /// `None` when the task is on no overlay network, which leaves the
    /// M1 behaviour — a copy of the host's file — in place.
    async fn resolv_conf(&self, task: &Task) -> Option<String>;

    /// Attach `jail` to every overlay network `task` is on: the VTEP, the
    /// bridge segment, the epair, and the forwarding and ARP entries that make
    /// remote endpoints reachable.
    async fn attach(&self, task: &Task, jail: &str) -> Result<(), OverlayError>;

    /// Release every overlay attachment of `task_id` on this node.
    ///
    /// Best-effort and infallible by design: it runs from the controller's
    /// cleanup path, where every step tolerates "already gone" and none may
    /// stop the others. Trouble is logged by the implementation.
    async fn detach(&self, task_id: &Id);
}
