// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Stateful asset behavior aligned with the current public gvmd GMP surface.

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::unwrap_used, missing_docs)]

use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn connect_and_auth(server: &MockGmpServer) -> UnixStream {
    let mut stream = UnixStream::connect(server.socket_path().expect("Unix socket path"))
        .await
        .expect("connect failed");
    let auth = send_recv(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(auth.status_code(), Some(200));
    stream
}

async fn strict_server(
    seed: impl FnOnce(&gvm_mock_server::ResourceStore) + Send + 'static,
) -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .seed(seed)
        .unix_socket_auto()
        .build()
        .await
        .expect("server start failed")
}

fn response_text(response: &Response) -> &str {
    response.as_str().expect("valid UTF-8 response")
}

#[tokio::test]
async fn strict_profile_rejects_non_gvmd_asset_inputs_before_lifecycle_success() {
    let unrelated_id = Uuid::new_v4();
    let server = strict_server(move |store| {
        store.seed(Resource::with_id("task", "not an asset", unrelated_id));
    })
    .await;
    let mut stream = connect_and_auth(&server).await;

    for request in [
        br#"<create_asset asset_type="host"><name>192.0.2.10</name></create_asset>"#.as_slice(),
        b"<create_asset><asset_type>host</asset_type><value>192.0.2.10</value></create_asset>",
        b"<create_asset><asset><name>192.0.2.10</name></asset></create_asset>",
        b"<create_asset><asset><type>host</type></asset></create_asset>",
        b"<create_asset><asset><type>os</type><name>Example OS</name></asset></create_asset>",
        b"<create_asset><asset><type>host</type><name>not-an-ip</name></asset></create_asset>",
    ] {
        assert_eq!(
            send_recv(&mut stream, request).await.status_code(),
            Some(400)
        );
    }

    assert_eq!(
        send_recv(&mut stream, b"<get_assets/>").await.status_code(),
        Some(400)
    );
    assert_eq!(
        send_recv(&mut stream, b"<get_assets type=\"firmware\"/>")
            .await
            .status_code(),
        Some(404)
    );
    assert_eq!(
        send_recv(&mut stream, b"<get_assets asset_type=\"host\"/>")
            .await
            .status_code(),
        Some(400)
    );

    let unrelated_id = unrelated_id.to_string();
    assert_eq!(
        send_recv(
            &mut stream,
            format!(
                "<modify_asset asset_id=\"{unrelated_id}\"><comment>x</comment></modify_asset>"
            )
            .as_bytes(),
        )
        .await
        .status_code(),
        Some(404)
    );
    assert_eq!(
        send_recv(
            &mut stream,
            format!("<delete_asset asset_id=\"{unrelated_id}\"/>").as_bytes(),
        )
        .await
        .status_code(),
        Some(404)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn canonical_host_asset_lifecycle_is_stateful_and_permanently_deleted() {
    let server = strict_server(|_| {}).await;
    let mut stream = connect_and_auth(&server).await;

    let create = send_recv(
        &mut stream,
        b"<create_asset><asset><type>host</type><name>2001:db8::10</name><comment>edge</comment></asset></create_asset>",
    )
    .await;
    assert_eq!(create.status_code(), Some(201));
    let id = create.id().expect("created asset id").to_string();

    let alternate_spelling = send_recv(
        &mut stream,
        b"<create_asset><asset><type>host</type><name>2001:0db8:0:0:0:0:0:10</name></asset></create_asset>",
    )
    .await;
    assert_eq!(alternate_spelling.status_code(), Some(201));

    let get = send_recv(&mut stream, b"<get_assets type=\"host\"/>").await;
    assert_eq!(get.status_code(), Some(200));
    let text = response_text(&get);
    assert!(text.contains(&format!("<asset id=\"{id}\">")));
    assert!(text.contains("<owner><name>admin</name></owner>"));
    assert!(text.contains("<name>2001:db8::10</name>"));
    assert!(text.contains("<name>2001:0db8:0:0:0:0:0:10</name>"));
    assert!(text.contains("<comment>edge</comment>"));
    assert!(text.contains("<creation_time>"));
    assert!(text.contains("<modification_time>"));
    assert!(text.contains("<writable>1</writable><in_use>0</in_use>"));
    assert!(text.contains("<name>ip</name><value>2001:db8::10</value>"));
    assert!(text.contains("<type>host</type><host><severity><value>"));
    assert!(text.contains("<asset_count>2<filtered>2</filtered><page>2</page>"));
    assert!(!text.contains("<asset_type>"));

    let ignored_modify_child = send_recv(
        &mut stream,
        format!("<modify_asset asset_id=\"{id}\"><value>192.0.2.10</value></modify_asset>")
            .as_bytes(),
    )
    .await;
    assert_eq!(ignored_modify_child.status_code(), Some(200));
    let get_one = send_recv(
        &mut stream,
        format!("<get_assets asset_id=\"{id}\" type=\"host\"/>").as_bytes(),
    )
    .await;
    assert!(response_text(&get_one).contains("<comment></comment>"));

    let modify = send_recv(
        &mut stream,
        format!("<modify_asset asset_id=\"{id}\"><comment>updated</comment></modify_asset>")
            .as_bytes(),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));
    let get_one = send_recv(
        &mut stream,
        format!("<get_assets asset_id=\"{id}\" type=\"host\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_one.status_code(), Some(200));
    let text = response_text(&get_one);
    assert!(text.contains("<comment>updated</comment>"));
    assert!(text.contains("<asset_count>2<filtered>1</filtered><page>1</page>"));

    let clear_comment = send_recv(
        &mut stream,
        format!("<modify_asset asset_id=\"{id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(clear_comment.status_code(), Some(200));
    let get_one = send_recv(
        &mut stream,
        format!("<get_assets asset_id=\"{id}\" type=\"host\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_one.status_code(), Some(200));
    assert!(response_text(&get_one).contains("<comment></comment>"));

    let delete = send_recv(
        &mut stream,
        format!("<delete_asset asset_id=\"{id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete.status_code(), Some(200));
    assert_eq!(
        send_recv(
            &mut stream,
            format!("<get_assets asset_id=\"{id}\" type=\"host\"/>").as_bytes(),
        )
        .await
        .status_code(),
        Some(404)
    );
    assert_eq!(
        send_recv(&mut stream, format!("<restore id=\"{id}\"/>").as_bytes())
            .await
            .status_code(),
        Some(404)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn asset_filters_pagination_and_counts_are_applied_after_type_selection() {
    let server = strict_server(|store| {
        for (name, severity) in [
            ("192.0.2.10", "7.0"),
            ("192.0.2.20", "4.0"),
            ("192.0.2.30", "7.0"),
        ] {
            let mut host = Resource::new("asset", name);
            host.set_attr("type", "host");
            host.set_attr("severity", severity);
            store.seed(host);
        }
    })
    .await;
    let mut stream = connect_and_auth(&server).await;

    let paged = send_recv(
        &mut stream,
        b"<get_assets type=\"host\" filter=\"severity=7.0 first=2 rows=1\"/>",
    )
    .await;
    let text = response_text(&paged);
    assert!(text.contains("<name>192.0.2.30</name>"));
    assert!(!text.contains("<name>192.0.2.10</name>"));
    assert!(text.contains("<asset_count>3<filtered>2</filtered><page>1</page>"));

    let unpaged = send_recv(
        &mut stream,
        b"<get_assets type=\"host\" ignore_pagination=\"1\" filter=\"severity=7.0 rows=1\"/>",
    )
    .await;
    let text = response_text(&unpaged);
    assert!(text.contains("<name>192.0.2.10</name>"));
    assert!(text.contains("<name>192.0.2.30</name>"));
    assert!(text.contains("<asset_count>3<filtered>2</filtered><page>2</page>"));

    let no_match = send_recv(
        &mut stream,
        b"<get_assets type=\"host\" filter=\"comment=missing\"/>",
    )
    .await;
    assert!(response_text(&no_match).contains("<asset_count>3<filtered>0</filtered><page>0</page>"));

    assert_eq!(
        send_recv(
            &mut stream,
            b"<get_assets type=\"host\" filt_id=\"00000000-0000-0000-0000-000000000001\"/>",
        )
        .await
        .status_code(),
        Some(404)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn seeded_os_assets_render_the_canonical_nested_shape() {
    let os_id = Uuid::new_v4();
    let server = strict_server(move |store| {
        let mut os = Resource::with_id("asset", "cpe:/o:example:linux", os_id);
        os.comment = "seeded".to_string();
        os.set_attr("asset_type", "os");
        os.set_attr("title", "Example Linux");
        os.set_attr("installs", "0");
        os.set_attr("all_installs", "0");
        os.set_attr("latest_severity", "6.1");
        os.set_attr("highest_severity", "9.8");
        os.set_attr("average_severity", "7.95");
        store.seed(os);
    })
    .await;
    let mut stream = connect_and_auth(&server).await;

    let get = send_recv(&mut stream, b"<get_assets type=\"os\"/>").await;
    assert_eq!(get.status_code(), Some(200));
    let text = response_text(&get);
    assert!(text.contains(&format!("<asset id=\"{os_id}\">")));
    assert!(text.contains("<writable>0</writable><in_use>0</in_use>"));
    assert!(text.contains("<type>os</type><os>"));
    assert!(text.contains("<latest_severity><value>6.1</value></latest_severity>"));
    assert!(text.contains("<highest_severity><value>9.8</value></highest_severity>"));
    assert!(text.contains("<average_severity><value>7.95</value></average_severity>"));
    assert!(text.contains("<title>Example Linux</title>"));
    assert!(text.contains("<installs>0</installs><all_installs>0</all_installs><hosts>0</hosts>"));
    assert!(!text.contains("<asset_type>"));

    let modify = send_recv(
        &mut stream,
        format!("<modify_asset asset_id=\"{os_id}\"><comment>no</comment></modify_asset>")
            .as_bytes(),
    )
    .await;
    assert_eq!(modify.status_code(), Some(404));

    let delete = send_recv(
        &mut stream,
        format!("<delete_asset asset_id=\"{os_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete.status_code(), Some(200));
    let get = send_recv(&mut stream, b"<get_assets type=\"os\"/>").await;
    assert_eq!(get.status_code(), Some(200));
    assert!(response_text(&get).contains("<asset_count>0<filtered>0</filtered><page>0</page>"));

    server.shutdown().await;
}

#[tokio::test]
async fn referenced_operating_system_assets_cannot_be_deleted() {
    let os_id = Uuid::new_v4();
    let server = strict_server(move |store| {
        let mut os = Resource::with_id("asset", "cpe:/o:example:referenced", os_id);
        os.set_attr("type", "os");
        os.set_attr("installs", "1");
        store.seed(os);
    })
    .await;
    let mut stream = connect_and_auth(&server).await;

    let delete = send_recv(
        &mut stream,
        format!("<delete_asset asset_id=\"{os_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete.status_code(), Some(400));
    assert!(response_text(&delete).contains("Asset is in use"));

    server.shutdown().await;
}
