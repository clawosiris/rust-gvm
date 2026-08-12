// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Stateful target host-specification validation against raw GMP requests.

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::unwrap_used, missing_docs)]

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn stateful_server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    UnixStream::connect(server.socket_path().expect("Unix socket path"))
        .await
        .expect("connect to mock server")
}

async fn send_recv(stream: &mut UnixStream, xml: impl AsRef<[u8]>) -> Response {
    stream.write_all(xml.as_ref()).await.expect("write request");
    let mut buffer = vec![0_u8; 64 * 1024];
    let length = stream.read(&mut buffer).await.expect("read response");
    buffer.truncate(length);
    Response::new(buffer)
}

async fn authenticate(stream: &mut UnixStream) {
    let response = send_recv(
        stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
}

fn response_id(response: &Response) -> String {
    response.id().expect("created resource id")
}

async fn get_target_xml(stream: &mut UnixStream, target_id: &str, details: bool) -> String {
    let details = if details { " details=\"1\"" } else { "" };
    let response = send_recv(
        stream,
        format!("<get_targets target_id=\"{target_id}\"{details}/>"),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
    response.as_str().expect("UTF-8 response").to_string()
}

#[tokio::test]
async fn raw_target_create_validates_and_cleans_host_lists() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    for body in [
        "<create_target><name>No ports</name><hosts>192.0.2.1</hosts></create_target>",
        "<create_target><name>Empty ports</name><hosts>192.0.2.1</hosts><port_range/></create_target>",
        "<create_target><name>Bad ports</name><hosts>192.0.2.1</hosts><port_range>T:0</port_range></create_target>",
    ] {
        let response = send_recv(&mut stream, body).await;
        assert_eq!(response.status_code(), Some(400), "{body}");
    }

    for body in [
        "<create_target><name>Missing</name><port_range>T:1-65535</port_range></create_target>",
        "<create_target><name>Empty</name><hosts></hosts><port_range>T:1-65535</port_range></create_target>",
        "<create_target><name>Empty</name><hosts>, ,</hosts><port_range>T:1-65535</port_range></create_target>",
        "<create_target><name>Excluded</name><hosts>192.0.2.1</hosts><exclude_hosts>192.0.2.1</exclude_hosts><port_range>T:1-65535</port_range></create_target>",
        "<create_target><name>Covered</name><hosts>192.0.2.0/30</hosts><exclude_hosts>192.0.2.1-192.0.2.2</exclude_hosts><port_range>T:1-65535</port_range></create_target>",
    ] {
        let response = send_recv(&mut stream, body).await;
        assert_eq!(response.status_code(), Some(400), "{body}");
    }

    for (element, value) in [
        ("hosts", "192.0.2.1/0"),
        ("hosts", "192.0.2.1/31"),
        ("hosts", "192.0.2.1/32"),
        ("exclude_hosts", "2001:db8::/0"),
        ("exclude_hosts", "2001:db8::/129"),
    ] {
        let included = if element == "exclude_hosts" {
            "<hosts>192.0.2.1</hosts>"
        } else {
            ""
        };
        let response = send_recv(
            &mut stream,
            format!(
                "<create_target><name>Invalid</name>{included}<{element}>{value}</{element}><port_range>T:1-65535</port_range></create_target>"
            ),
        )
        .await;
        assert_eq!(response.status_code(), Some(400), "{element}={value}");
        assert_eq!(
            response.status_text().as_deref(),
            Some("Error in host specification")
        );
    }

    let response = send_recv(
        &mut stream,
        b"<create_target><name>Cleaned</name><hosts>000.001.002.003/030, ,2001:db8::1/128,2001:db8::1/128,2001:0db8:0:0:0:0:0:1/128&#10;192.0.2.1-002</hosts><exclude_hosts>192.0.2.0/1,2001:db8::/127</exclude_hosts><port_range>T:1-65535</port_range></create_target>",
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    let target_id = response_id(&response);

    for body in [
        format!(
            "<modify_target target_id=\"{target_id}\"><hosts>192.0.2.8</hosts></modify_target>"
        ),
        format!(
            "<modify_target target_id=\"{target_id}\"><exclude_hosts>192.0.2.8</exclude_hosts></modify_target>"
        ),
        format!(
            "<modify_target target_id=\"{target_id}\"><hosts></hosts><exclude_hosts></exclude_hosts></modify_target>"
        ),
        format!(
            "<modify_target target_id=\"{target_id}\"><hosts>, ,</hosts><exclude_hosts></exclude_hosts></modify_target>"
        ),
    ] {
        let response = send_recv(&mut stream, body).await;
        assert_eq!(response.status_code(), Some(400));
    }

    let xml = get_target_xml(&mut stream, &target_id, false).await;
    assert!(xml.contains("<hosts>000.001.002.003/030, 2001:db8::1/128, 2001:0db8:0:0:0:0:0:1/128, 192.0.2.1-002</hosts>"));
    assert!(xml.contains("<exclude_hosts>192.0.2.0/1, 2001:db8::/127</exclude_hosts>"));
    assert!(!xml.contains("<port_range>"));

    let xml = get_target_xml(&mut stream, &target_id, true).await;
    assert_eq!(xml.matches("<port_range>T:1-65535</port_range>").count(), 1);

    let response = send_recv(
        &mut stream,
        b"<create_target><name>Partial</name><hosts>192.0.2.0/30</hosts><exclude_hosts>192.0.2.1</exclude_hosts><port_range>T:1-65535</port_range></create_target>",
    )
    .await;
    assert_eq!(response.status_code(), Some(201));

    let response = send_recv(
        &mut stream,
        b"<create_target><name>Distinct hostname</name><hosts>Scanner.Example.</hosts><exclude_hosts>scanner.example</exclude_hosts><port_range>T:1-65535</port_range></create_target>",
    )
    .await;
    assert_eq!(response.status_code(), Some(201));

    server.shutdown().await;
}

#[tokio::test]
async fn raw_target_create_accepts_port_list_and_range_with_port_list_precedence() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    let response = send_recv(
        &mut stream,
        b"<create_port_list><name>Explicit ports</name></create_port_list>",
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    let port_list_id = response_id(&response);

    let response = send_recv(
        &mut stream,
        format!(
            "<create_target><name>Both ports</name><hosts>192.0.2.1</hosts><port_range>T:22</port_range><port_list id=\"{port_list_id}\"/></create_target>"
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    let target_id = response_id(&response);

    let response = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\" details=\"1\"/>"),
    )
    .await;
    let xml = response.as_str().expect("UTF-8 response");
    assert!(xml.contains(&format!("<port_list id=\"{port_list_id}\">")));
    assert!(!xml.contains("<port_range>"));

    let response = send_recv(
        &mut stream,
        format!(
            "<create_target><name>Invalid range</name><hosts>192.0.2.1</hosts><port_range>T:0</port_range><port_list id=\"{port_list_id}\"/></create_target>"
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));

    server.shutdown().await;
}

#[tokio::test]
async fn raw_target_modify_blocks_host_changes_while_target_is_in_use() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    let response = send_recv(
        &mut stream,
        b"<create_target><name>In use</name><hosts>192.0.2.1</hosts><exclude_hosts>192.0.2.2</exclude_hosts><port_range>T:1-65535</port_range></create_target>",
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    let target_id = response_id(&response);

    let response = send_recv(
        &mut stream,
        format!("<create_task><name>Uses target</name><target id=\"{target_id}\"/></create_task>"),
    )
    .await;
    assert_eq!(response.status_code(), Some(201));

    let response = send_recv(
        &mut stream,
        format!("<modify_target target_id=\"{target_id}\"><hosts>198.51.100.1</hosts><exclude_hosts></exclude_hosts><comment>must not apply</comment></modify_target>"),
    )
    .await;
    assert_eq!(response.status_code(), Some(409));

    let response = send_recv(
        &mut stream,
        format!("<modify_target target_id=\"{target_id}\"><comment>metadata allowed</comment></modify_target>"),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));

    let response = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>"),
    )
    .await;
    let xml = response.as_str().expect("UTF-8 response");
    assert!(xml.contains("<hosts>192.0.2.1</hosts>"));
    assert!(xml.contains("<exclude_hosts>192.0.2.2</exclude_hosts>"));
    assert!(xml.contains("<comment>metadata allowed</comment>"));
    assert!(!xml.contains("must not apply"));

    server.shutdown().await;
}

#[tokio::test]
async fn raw_target_modify_rejects_invalid_lists_without_mutating_state() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    let response = send_recv(
        &mut stream,
        b"<create_target><name>Stable</name><hosts>192.0.2.1</hosts><exclude_hosts>192.0.2.2</exclude_hosts><port_range>T:1-65535</port_range></create_target>",
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    let target_id = response_id(&response);

    for (element, value) in [
        ("hosts", "192.0.2.1/31"),
        ("exclude_hosts", "2001:db8::/129"),
    ] {
        let response = send_recv(
            &mut stream,
            format!("<modify_target target_id=\"{target_id}\"><{element}>{value}</{element}></modify_target>"),
        )
        .await;
        assert_eq!(response.status_code(), Some(400), "{element}={value}");
    }

    for (hosts, excluded) in [
        ("192.0.2.1", "192.0.2.1"),
        ("192.0.2.0/30", "192.0.2.1-192.0.2.2"),
        ("2001:db8::/126", "2001:db8::1-0002"),
    ] {
        let response = send_recv(
            &mut stream,
            format!(
                "<modify_target target_id=\"{target_id}\"><hosts>{hosts}</hosts><exclude_hosts>{excluded}</exclude_hosts></modify_target>"
            ),
        )
        .await;
        assert_eq!(response.status_code(), Some(400), "{hosts} - {excluded}");
    }

    let response = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>"),
    )
    .await;
    let xml = response.as_str().expect("UTF-8 response");
    assert!(xml.contains("<hosts>192.0.2.1</hosts>"));
    assert!(xml.contains("<exclude_hosts>192.0.2.2</exclude_hosts>"));

    let response = send_recv(
        &mut stream,
        format!("<modify_target target_id=\"{target_id}\"><hosts>000.001.002.003-004</hosts><exclude_hosts></exclude_hosts></modify_target>"),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));

    let response = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>"),
    )
    .await;
    let xml = response.as_str().expect("UTF-8 response");
    assert!(xml.contains("<hosts>000.001.002.003-004</hosts>"));
    assert!(xml.contains("<exclude_hosts></exclude_hosts>"));

    server.shutdown().await;
}

#[tokio::test]
async fn raw_target_create_supports_asset_host_filters_with_gvmd_precedence() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    for (name, comment) in [
        ("192.0.2.10", "edge"),
        ("192.0.2.11", "other"),
        ("192.0.2.12", "edge site"),
    ] {
        let response = send_recv(
            &mut stream,
            format!(
                "<create_asset><asset><type>host</type><name>{name}</name><comment>{comment}</comment></asset></create_asset>"
            ),
        )
        .await;
        assert_eq!(response.status_code(), Some(201));
    }

    let response = send_recv(
        &mut stream,
        b"<create_target><name>Filtered</name><asset_hosts filter=\"comment=edge\"/><port_range>T:1-65535</port_range></create_target>",
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    let target_id = response_id(&response);
    let response = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>"),
    )
    .await;
    let xml = response.as_str().expect("UTF-8 response");
    assert!(xml.contains("<hosts>192.0.2.10</hosts>"));
    assert!(!xml.contains("asset_hosts_filter"));

    let response = send_recv(
        &mut stream,
        b"<create_target><name>Precedence</name><hosts>198.51.100.1</hosts><asset_hosts filter=\"comment=other\"/><port_range>T:1-65535</port_range></create_target>",
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    let target_id = response_id(&response);
    let response = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>"),
    )
    .await;
    let xml = response.as_str().expect("UTF-8 response");
    assert!(xml.contains("<hosts>192.0.2.11</hosts>"));
    assert!(!xml.contains("198.51.100.1"));

    for (filter, expected) in [
        ("comment=&quot;edge site&quot;", "192.0.2.12"),
        ("comment~EDGE sort-reverse=name rows=1", "192.0.2.12"),
        ("name&gt;192.0.2.10 sort=name rows=1", "192.0.2.11"),
    ] {
        let response = send_recv(
            &mut stream,
            format!(
                "<create_target><name>Filter operators</name><asset_hosts filter=\"{filter}\"/><port_range>T:1-65535</port_range></create_target>"
            ),
        )
        .await;
        assert_eq!(response.status_code(), Some(201), "{filter}");
        let target_id = response_id(&response);
        let response = send_recv(
            &mut stream,
            format!("<get_targets target_id=\"{target_id}\"/>"),
        )
        .await;
        assert!(
            response
                .as_str()
                .expect("UTF-8 response")
                .contains(&format!("<hosts>{expected}</hosts>")),
            "{filter}"
        );
    }

    for body in [
        "<create_target><name>No Match</name><asset_hosts filter=\"comment=missing\"/><port_range>T:1-65535</port_range></create_target>",
        "<create_target><name>All Excluded</name><asset_hosts filter=\"comment=edge\"/><exclude_hosts>192.0.2.10</exclude_hosts><port_range>T:1-65535</port_range></create_target>",
        "<create_target><name>Malformed</name><asset_hosts filter=\"comment\"/><port_range>T:1-65535</port_range></create_target>",
        "<create_target><name>Unsupported</name><asset_hosts filter=\"permission=read\"/><port_range>T:1-65535</port_range></create_target>",
    ] {
        let response = send_recv(&mut stream, body).await;
        assert_eq!(response.status_code(), Some(400), "{body}");
    }

    server.shutdown().await;
}
