//! Additional integration tests for error injection / fault engine.

use std::time::{Duration, Instant};

use gvm_mock_server::{Fault, FaultKind, GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn write_then_read(stream: &mut UnixStream, xml: &[u8]) -> std::io::Result<usize> {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    stream.read(&mut buf).await
}

#[tokio::test]
async fn err_002_disconnect_after_auth() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .inject_fault(Fault::on_command("authenticate", FaultKind::Disconnect))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    let read_result = write_then_read(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;

    assert!(
        matches!(read_result, Ok(0)) || read_result.is_err(),
        "expected EOF or read error after disconnect, got {read_result:?}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn err_003_delayed_response() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::once(FaultKind::Delay(Duration::from_millis(250))))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    let started = Instant::now();
    let resp = send_recv(&mut stream, b"<get_version/>").await;
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(200),
        "expected delayed response >= 200ms, got {elapsed:?}"
    );
    assert_eq!(resp.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn err_008_multiple_faults_compose() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::after_commands(1, FaultKind::ServerError500))
        .inject_fault(Fault::always(FaultKind::Delay(Duration::from_millis(50))))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    let started_1 = Instant::now();
    let r1 = send_recv(&mut stream, b"<get_version/>").await;
    let elapsed_1 = started_1.elapsed();
    assert!(
        elapsed_1 >= Duration::from_millis(40),
        "expected first command delay, got {elapsed_1:?}"
    );
    assert_eq!(r1.status_code(), Some(200));

    let started_2 = Instant::now();
    let r2 = send_recv(&mut stream, b"<get_targets/>").await;
    let elapsed_2 = started_2.elapsed();
    assert!(
        elapsed_2 >= Duration::from_millis(40),
        "expected second command delay, got {elapsed_2:?}"
    );
    assert_eq!(r2.status_code(), Some(500));

    server.shutdown().await;
}

#[tokio::test]
async fn err_020_fault_target_specific_command() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::on_command("get_reports", FaultKind::ServerError500))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    let tasks = send_recv(&mut stream, b"<get_tasks/>").await;
    assert_eq!(tasks.status_code(), Some(200));

    let reports = send_recv(&mut stream, b"<get_reports/>").await;
    assert_eq!(reports.status_code(), Some(500));

    let targets = send_recv(&mut stream, b"<get_targets/>").await;
    assert_eq!(targets.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn err_021_fault_on_all_commands() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::always(FaultKind::ServerError500))
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    for xml in [
        b"<get_version/>".as_slice(),
        b"<get_tasks/>",
        b"<get_targets/>",
    ] {
        let resp = send_recv(&mut stream, xml).await;
        assert_eq!(resp.status_code(), Some(500));
    }

    server.shutdown().await;
}

#[tokio::test]
async fn err_009_no_faults_control() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .unix_socket_auto()
        .build()
        .await
        .expect("start");

    let path = server.socket_path().unwrap();
    let mut stream = UnixStream::connect(path).await.expect("connect");

    for xml in [
        b"<get_version/>".as_slice(),
        b"<get_tasks/>",
        b"<get_targets/>",
        b"<get_reports/>",
        b"<help/>",
    ] {
        let resp = send_recv(&mut stream, xml).await;
        assert_eq!(resp.status_code(), Some(200));
    }

    server.shutdown().await;
}
