// SPDX-License-Identifier: BSD-2-Clause
//! Where commands write.
//!
//! Streaming commands (`run`, `logs`, `exec`, `pull`) write as bytes arrive,
//! so they take a [`Streams`] pair instead of returning a string. Tests swap
//! stdio for in-memory buffers and assert on what each stream received.
//!
//! Write errors are swallowed on purpose: `satl logs -f | head` closes the
//! pipe under us and docker exits quietly rather than reporting an I/O error.

use tokio::io::{AsyncWrite, AsyncWriteExt as _};

/// A boxed async writer; `Send` so it can cross `select!` branches.
type Sink = Box<dyn AsyncWrite + Unpin + Send>;

/// The stdout/stderr pair a command writes to.
pub struct Streams {
    out: Sink,
    err: Sink,
    out_is_terminal: bool,
}

impl Streams {
    /// The process's real stdout and stderr.
    pub fn stdio() -> Self {
        use std::io::IsTerminal as _;
        Self {
            out: Box::new(tokio::io::stdout()),
            err: Box::new(tokio::io::stderr()),
            out_is_terminal: std::io::stdout().is_terminal(),
        }
    }

    /// Arbitrary sinks (tests, or a command that redirects one stream).
    pub fn new(out: Sink, err: Sink) -> Self {
        Self {
            out,
            err,
            out_is_terminal: false,
        }
    }

    /// Whether stdout is a terminal — progress rendering uses `\r` updates
    /// only when someone is watching.
    pub fn out_is_terminal(&self) -> bool {
        self.out_is_terminal
    }

    /// Write raw bytes to stdout.
    pub async fn out(&mut self, bytes: &[u8]) {
        let _ = self.out.write_all(bytes).await;
        let _ = self.out.flush().await;
    }

    /// Write raw bytes to stderr.
    pub async fn err(&mut self, bytes: &[u8]) {
        let _ = self.err.write_all(bytes).await;
        let _ = self.err.flush().await;
    }

    /// Write a line (newline appended) to stdout.
    pub async fn outln(&mut self, line: &str) {
        self.out(line.as_bytes()).await;
        self.out(b"\n").await;
    }

    /// Write a line (newline appended) to stderr.
    pub async fn errln(&mut self, line: &str) {
        self.err(line.as_bytes()).await;
        self.err(b"\n").await;
    }

    /// Write a docker-style operator warning to stderr.
    pub async fn warn(&mut self, message: &str) {
        self.errln(&format!("WARNING: {message}")).await;
    }

    /// Write an error line to stderr, in the shape docker uses for a failed
    /// element of a multi-argument command.
    pub async fn error(&mut self, message: &str) {
        self.errln(message).await;
    }
}

#[cfg(test)]
pub mod testing {
    //! In-memory streams for tests.

    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use tokio::io::AsyncWrite;

    /// A cloneable in-memory sink: hand one clone to [`super::Streams`] and
    /// keep the other to assert on what was written.
    #[derive(Debug, Clone, Default)]
    pub struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl SharedBuf {
        /// Everything written so far, as UTF-8 (lossy).
        pub fn contents(&self) -> String {
            let guard = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl AsyncWrite for SharedBuf {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut guard = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A [`super::Streams`] over two [`SharedBuf`]s, returned alongside them.
    pub fn streams() -> (super::Streams, SharedBuf, SharedBuf) {
        let out = SharedBuf::default();
        let err = SharedBuf::default();
        let streams = super::Streams::new(Box::new(out.clone()), Box::new(err.clone()));
        (streams, out, err)
    }
}
