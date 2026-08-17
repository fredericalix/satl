// SPDX-License-Identifier: BSD-2-Clause
//! Unix-socket server for the Docker REST API.

use std::future::Future;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

use axum::Router;
use tokio::net::UnixListener;

use crate::error::ApiError;

/// Serves `router` on a unix socket at `socket_path` until `shutdown`
/// resolves, then finishes in-flight requests (graceful shutdown).
///
/// A stale socket file left over from a previous run is removed first (any
/// other kind of file at that path is refused, not deleted). The bound socket
/// is chmod-ed to `0660` so daemon group members can talk to the API, per the
/// SatL security model (`docs/architecture.md` §12.5). On clean shutdown the
/// socket file is removed best-effort.
pub async fn serve_unix(
    socket_path: &Path,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ApiError> {
    remove_stale_socket(socket_path).await?;

    let listener = UnixListener::bind(socket_path).map_err(|source| ApiError::Bind {
        path: socket_path.to_owned(),
        source,
    })?;
    tokio::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
        .await
        .map_err(|source| ApiError::SetPermissions {
            path: socket_path.to_owned(),
            source,
        })?;

    tracing::info!(socket = %socket_path.display(), "docker api listening on unix socket");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|source| ApiError::Serve {
            path: socket_path.to_owned(),
            source,
        })?;

    tracing::info!(socket = %socket_path.display(), "docker api server shut down");
    // Best-effort cleanup; the next start removes a leftover socket anyway.
    let _ = tokio::fs::remove_file(socket_path).await;
    Ok(())
}

/// Removes a stale socket file at `path`; refuses to touch non-socket files.
async fn remove_stale_socket(path: &Path) -> Result<(), ApiError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.file_type().is_socket() => {
            tracing::debug!(socket = %path.display(), "removing stale unix socket");
            tokio::fs::remove_file(path)
                .await
                .map_err(|source| ApiError::RemoveStaleSocket {
                    path: path.to_owned(),
                    source,
                })
        }
        Ok(_) => Err(ApiError::NotASocket {
            path: path.to_owned(),
        }),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ApiError::InspectSocketPath {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use super::*;
    use crate::{ApiState, SystemInfo, VersionInfo, router};

    fn test_state() -> ApiState {
        ApiState::new(
            VersionInfo {
                version: "0.1.0".to_owned(),
                api_version: "1.43".to_owned(),
                min_api_version: "1.24".to_owned(),
                git_commit: "deadbeef".to_owned(),
                os: "freebsd".to_owned(),
                arch: "amd64".to_owned(),
                kernel_version: "15.1-RELEASE".to_owned(),
                build_time: "2026-08-09T00:00:00Z".to_owned(),
            },
            SystemInfo {
                id: "TEST:NODE".to_owned(),
                name: "alpha".to_owned(),
                ncpu: 8,
                mem_total: 34_359_738_368,
                operating_system: "FreeBSD".to_owned(),
                os_version: "15.1-RELEASE".to_owned(),
                server_version: "0.1.0".to_owned(),
            },
            crate::types::SwarmInfo::inactive(),
        )
    }

    fn scratch_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("satl-api-{name}-{}", std::process::id()))
    }

    async fn connect_with_retry(path: &Path) -> UnixStream {
        for _ in 0..200 {
            if let Ok(stream) = UnixStream::connect(path).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("server never started listening on {}", path.display());
    }

    #[tokio::test]
    async fn serve_unix_replaces_stale_socket_and_answers_ping() {
        let dir = scratch_dir("ping");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let socket_path = dir.join("satld.sock");

        // Leave a stale socket behind, as an unclean daemon exit would.
        drop(std::os::unix::net::UnixListener::bind(&socket_path).unwrap());
        assert!(socket_path.exists());

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let serve_path = socket_path.clone();
        let server = tokio::spawn(async move {
            serve_unix(&serve_path, router(test_state()), async move {
                let _ = stop_rx.await;
            })
            .await
        });

        let mut stream = connect_with_retry(&socket_path).await;

        let mode = tokio::fs::metadata(&socket_path)
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o660, "socket must be chmod-ed to 0660");

        stream
            .write_all(b"GET /_ping HTTP/1.1\r\nHost: satl\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();

        assert!(text.starts_with("http/1.1 200"), "response was: {text}");
        assert!(text.contains("api-version: 1.43"), "response was: {text}");
        assert!(text.contains("ostype: freebsd"), "response was: {text}");
        assert!(text.contains("server: satl/0.1.0"), "response was: {text}");
        assert!(text.ends_with("\r\nok"), "response was: {text}");

        stop_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
        assert!(
            !socket_path.exists(),
            "socket file must be removed on clean shutdown"
        );
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }

    #[tokio::test]
    async fn serve_unix_refuses_to_replace_a_non_socket_file() {
        let dir = scratch_dir("nonsock");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("not-a-socket");
        tokio::fs::write(&path, b"precious data").await.unwrap();

        let err = serve_unix(&path, router(test_state()), async {})
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("not a unix socket"), "got: {message}");
        assert!(
            message.contains(path.to_str().unwrap()),
            "error must name the path, got: {message}"
        );
        // The file must be untouched.
        assert_eq!(
            tokio::fs::read(&path).await.unwrap(),
            b"precious data".to_vec()
        );
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }
}
