// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Broad stateful CRUD coverage for non-task resources.

#![cfg(feature = "unix-socket-tests")]
#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn auth_admin(stream: &mut UnixStream) {
    let resp = send_recv(
        stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(resp.status_code(), Some(200), "admin auth should succeed");
}

async fn create_and_get_id(
    stream: &mut UnixStream,
    create_xml: &[u8],
    create_cmd_name: &str,
) -> String {
    let resp = send_recv(stream, create_xml).await;
    assert_eq!(
        resp.status_code(),
        Some(201),
        "{create_cmd_name} should return 201"
    );

    let text = resp.as_str().expect("create response should be valid utf8");
    let marker = "id=\"";
    let start = text
        .find(marker)
        .expect("response should contain id attribute")
        + marker.len();
    let rest = &text[start..];
    let end = rest.find('"').expect("id attribute should be terminated");
    rest[..end].to_string()
}

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
    let path = server.socket_path().expect("should have socket path");
    UnixStream::connect(path).await.expect("connect failed")
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn matrix_targets_create_get_delete() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let credential_id = create_and_get_id(
        &mut stream,
        b"<create_credential><name>Matrix SSH</name><type>usk</type></create_credential>",
        "create_credential",
    )
    .await;
    let smb_credential_id = create_and_get_id(
        &mut stream,
        b"<create_credential><name>Matrix SMB</name><type>up</type></create_credential>",
        "create_credential",
    )
    .await;
    let invalid_credential_id = create_and_get_id(
        &mut stream,
        b"<create_credential><name>Matrix Password</name><type>pw</type></create_credential>",
        "create_credential",
    )
    .await;

    let target_id = create_and_get_id(
        &mut stream,
        format!(
            "<create_target><name>Matrix Target</name><hosts>127.0.0.1</hosts><port_range>T:1-65535</port_range><ssh_credential id=\"{credential_id}\"><port>2222</port></ssh_credential></create_target>"
        )
        .as_bytes(),
        "create_target",
    )
    .await;

    let get_resp = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains(&target_id));
    assert!(get_text.contains("Matrix Target"));
    assert!(get_text.contains(&format!(
        "<ssh_credential id=\"{credential_id}\"><name></name><port>2222</port></ssh_credential>"
    )));

    let modify_resp = send_recv(
        &mut stream,
        format!(
            "<modify_target target_id=\"{target_id}\"><comment>port omitted</comment></modify_target>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));
    let preserved = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>").as_bytes(),
    )
    .await;
    assert!(preserved
        .as_str()
        .expect("valid utf8")
        .contains("<port>2222</port>"));

    let reset_resp = send_recv(
        &mut stream,
        format!(
            "<modify_target target_id=\"{target_id}\"><ssh_credential id=\"{credential_id}\"><port>0</port></ssh_credential></modify_target>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(reset_resp.status_code(), Some(200));
    let reset = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>").as_bytes(),
    )
    .await;
    assert!(reset
        .as_str()
        .expect("valid utf8")
        .contains("<port>22</port>"));

    let detach_resp = send_recv(
        &mut stream,
        format!(
            "<modify_target target_id=\"{target_id}\"><ssh_credential id=\"0\"/></modify_target>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(detach_resp.status_code(), Some(200));
    let detached = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>").as_bytes(),
    )
    .await;
    assert!(detached
        .as_str()
        .expect("valid utf8")
        .contains("<ssh_credential id=\"\"><name></name><port></port></ssh_credential>"));

    let default_target_id = create_and_get_id(
        &mut stream,
        format!(
            "<create_target><name>Default SSH Port</name><hosts>127.0.0.2</hosts><port_range>T:1-65535</port_range><ssh_credential id=\"{credential_id}\"/></create_target>"
        )
        .as_bytes(),
        "create_target",
    )
    .await;
    let default_target = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{default_target_id}\"/>").as_bytes(),
    )
    .await;
    assert!(default_target
        .as_str()
        .expect("valid utf8")
        .contains("<port>22</port>"));

    let smb_port_resp = send_recv(
        &mut stream,
        format!(
            "<create_target><name>Invalid SMB Port</name><hosts>127.0.0.3</hosts><port_range>T:1-65535</port_range><smb_credential id=\"{smb_credential_id}\"><port>445</port></smb_credential></create_target>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(smb_port_resp.status_code(), Some(400));

    let create_detach_resp = send_recv(
        &mut stream,
        b"<create_target><name>Invalid Detach</name><hosts>127.0.0.4</hosts><port_range>T:1-65535</port_range><ssh_credential id=\"0\"/></create_target>",
    )
    .await;
    assert_eq!(create_detach_resp.status_code(), Some(400));

    for credential_element in ["ssh_credential", "smb_credential"] {
        let invalid_type_resp = send_recv(
            &mut stream,
            format!(
                "<create_target><name>Invalid Type {credential_element}</name><hosts>127.0.0.5</hosts><port_range>T:1-65535</port_range><{credential_element} id=\"{invalid_credential_id}\"/></create_target>"
            )
            .as_bytes(),
        )
        .await;
        assert_eq!(invalid_type_resp.status_code(), Some(400));

        let invalid_modify_type_resp = send_recv(
            &mut stream,
            format!(
                "<modify_target target_id=\"{default_target_id}\"><{credential_element} id=\"{invalid_credential_id}\"/></modify_target>"
            )
            .as_bytes(),
        )
        .await;
        assert_eq!(invalid_modify_type_resp.status_code(), Some(400));
    }

    let delete_resp = send_recv(
        &mut stream,
        format!("<delete_target target_id=\"{target_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_resp.status_code(), Some(200));

    let missing_resp = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{target_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(missing_resp.status_code(), Some(404));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_configs_create_get_list() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let config_id = create_and_get_id(
        &mut stream,
        b"<create_config><name>Matrix Config</name><comment>cfg</comment></create_config>",
        "create_config",
    )
    .await;

    let get_resp = send_recv(
        &mut stream,
        format!("<get_configs config_id=\"{config_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains(&config_id));
    assert!(get_text.contains("Matrix Config"));

    let list_resp = send_recv(&mut stream, b"<get_configs/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let list_text = list_resp.as_str().expect("valid utf8");
    assert!(list_text.contains(&config_id));
    assert!(list_text.contains("Matrix Config"));
    assert!(list_text.contains("<config_count>2") || list_text.contains("<filtered>2</filtered>"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_configs_full_lifecycle_helpers() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let config_id = create_and_get_id(
        &mut stream,
        b"<create_config><name>Matrix Config</name><comment>cfg</comment></create_config>",
        "create_config",
    )
    .await;

    let modify_resp = send_recv(
        &mut stream,
        format!(
            "<modify_config config_id=\"{config_id}\"><comment>updated</comment><usage_type>scan</usage_type></modify_config>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_configs config_id=\"{config_id}\" details=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains("<comment>updated</comment>"));
    assert!(get_text.contains("<usage_type>scan</usage_type>"));

    let sync_resp = send_recv(&mut stream, b"<sync_config/>").await;
    assert_eq!(sync_resp.status_code(), Some(200));

    let cloned_config_id = create_and_get_id(
        &mut stream,
        format!("<create_config><copy>{config_id}</copy></create_config>").as_bytes(),
        "create_config",
    )
    .await;

    let cloned_get_resp = send_recv(
        &mut stream,
        format!("<get_configs config_id=\"{cloned_config_id}\" details=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(cloned_get_resp.status_code(), Some(200));
    let cloned_get_text = cloned_get_resp.as_str().expect("valid utf8");
    assert!(cloned_get_text.contains("Matrix Config"));

    let delete_resp = send_recv(
        &mut stream,
        format!("<delete_config config_id=\"{config_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_resp.status_code(), Some(200));

    let deleted_get_resp = send_recv(
        &mut stream,
        format!("<get_configs config_id=\"{config_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(deleted_get_resp.status_code(), Some(404));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_scanners_full_lifecycle_helpers() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let scanner_id = create_and_get_id(
        &mut stream,
        b"<create_scanner><name>Matrix Scanner</name></create_scanner>",
        "create_scanner",
    )
    .await;

    let get_resp = send_recv(
        &mut stream,
        format!("<get_scanners scanner_id=\"{scanner_id}\" details=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains(&scanner_id));
    assert!(get_text.contains("Matrix Scanner"));

    let modify_resp = send_recv(
        &mut stream,
        format!(
            "<modify_scanner scanner_id=\"{scanner_id}\"><comment>updated</comment><host>127.0.0.1</host><port>9390</port></modify_scanner>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));

    let updated_get_resp = send_recv(
        &mut stream,
        format!("<get_scanners scanner_id=\"{scanner_id}\" details=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(updated_get_resp.status_code(), Some(200));
    let updated_get_text = updated_get_resp.as_str().expect("valid utf8");
    assert!(updated_get_text.contains("<comment>updated</comment>"));
    assert!(updated_get_text.contains("<host>127.0.0.1</host>"));
    assert!(updated_get_text.contains("<port>9390</port>"));

    let verify_resp = send_recv(
        &mut stream,
        format!("<verify_scanner scanner_id=\"{scanner_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(verify_resp.status_code(), Some(200));

    let cloned_scanner_id = create_and_get_id(
        &mut stream,
        format!("<create_scanner><copy>{scanner_id}</copy></create_scanner>").as_bytes(),
        "create_scanner",
    )
    .await;

    let cloned_get_resp = send_recv(
        &mut stream,
        format!("<get_scanners scanner_id=\"{cloned_scanner_id}\" details=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(cloned_get_resp.status_code(), Some(200));
    let cloned_get_text = cloned_get_resp.as_str().expect("valid utf8");
    assert!(cloned_get_text.contains("Matrix Scanner"));

    let delete_resp = send_recv(
        &mut stream,
        format!("<delete_scanner scanner_id=\"{scanner_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_scanners scanner_id=\"{scanner_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(404));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_alerts_create_list_nonempty() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let alert_id = create_and_get_id(
        &mut stream,
        b"<create_alert><name>Matrix Alert</name></create_alert>",
        "create_alert",
    )
    .await;

    let list_resp = send_recv(&mut stream, b"<get_alerts/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let list_text = list_resp.as_str().expect("valid utf8");
    assert!(list_text.contains(&alert_id));
    assert!(list_text.contains("Matrix Alert"));
    assert!(list_text.contains("<alert_count>1") || list_text.contains("<filtered>1</filtered>"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_credentials_create_get_by_id() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let credential_id = create_and_get_id(
        &mut stream,
        b"<create_credential><name>Matrix Credential</name><comment>cred</comment></create_credential>",
        "create_credential",
    )
    .await;

    let get_resp = send_recv(
        &mut stream,
        format!("<get_credentials credential_id=\"{credential_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains(&credential_id));
    assert!(get_text.contains("Matrix Credential"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_filters_create_modify_name() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let filter_id = create_and_get_id(
        &mut stream,
        b"<create_filter><name>Matrix Filter Old</name></create_filter>",
        "create_filter",
    )
    .await;

    let modify_resp = send_recv(
        &mut stream,
        format!(
            "<modify_filter filter_id=\"{filter_id}\"><name>Matrix Filter New</name></modify_filter>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_filters filter_id=\"{filter_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains(&filter_id));
    assert!(get_text.contains("Matrix Filter New"));

    let list_resp = send_recv(&mut stream, b"<get_filters/>").await;
    assert_eq!(list_resp.status_code(), Some(200));
    let list_text = list_resp.as_str().expect("valid utf8");
    assert!(list_text.contains("Matrix Filter New"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_schedules_create_delete_to_trash_and_restore() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let schedule_id = create_and_get_id(
        &mut stream,
        b"<create_schedule><name>Matrix Schedule</name><icalendar>BEGIN:VCALENDAR&#10;VERSION:2.0&#10;BEGIN:VEVENT&#10;DTSTART:20300101T000000Z&#10;RRULE:FREQ=DAILY&#10;END:VEVENT&#10;END:VCALENDAR</icalendar><timezone>UTC</timezone></create_schedule>",
        "create_schedule",
    )
    .await;

    let delete_resp = send_recv(
        &mut stream,
        format!("<delete_schedule schedule_id=\"{schedule_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_resp.status_code(), Some(200));

    let trashed_resp = send_recv(&mut stream, b"<get_schedules trash=\"1\"/>").await;
    assert_eq!(trashed_resp.status_code(), Some(200));
    let trashed_text = trashed_resp.as_str().expect("valid utf8");
    assert!(trashed_text.contains(&schedule_id));

    let restore_resp = send_recv(
        &mut stream,
        format!("<restore id=\"{schedule_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(restore_resp.status_code(), Some(200));

    let get_resp = send_recv(
        &mut stream,
        format!("<get_schedules schedule_id=\"{schedule_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains(&schedule_id));
    assert!(get_text.contains("Matrix Schedule"));

    server.shutdown().await;
}

#[tokio::test]
async fn schedules_default_timezone_and_require_calendar_on_modify() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let schedule_id = create_and_get_id(
        &mut stream,
        b"<create_schedule><name>Default Zone</name><icalendar>BEGIN:VEVENT&#10;DTSTART:20300101T000000&#10;END:VEVENT</icalendar></create_schedule>",
        "create_schedule",
    )
    .await;

    let get_resp = send_recv(
        &mut stream,
        format!("<get_schedules schedule_id=\"{schedule_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(get_resp.status_code(), Some(200));
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains("<timezone>UTC</timezone>"));
    assert!(get_text.contains("<first_run>2030-01-01T00:00:00Z</first_run>"));
    assert!(get_text.contains("<next_run>2030-01-01T00:00:00Z</next_run>"));

    let modify_resp = send_recv(
        &mut stream,
        format!(
            "<modify_schedule schedule_id=\"{schedule_id}\"><comment>missing calendar</comment></modify_schedule>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(400));

    let modify_resp = send_recv(
        &mut stream,
        format!(
            "<modify_schedule schedule_id=\"{schedule_id}\"><icalendar>BEGIN:VEVENT&#10;DTSTART:20310101T010000&#10;END:VEVENT</icalendar></modify_schedule>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify_resp.status_code(), Some(200));
    let get_resp = send_recv(
        &mut stream,
        format!("<get_schedules schedule_id=\"{schedule_id}\"/>").as_bytes(),
    )
    .await;
    let get_text = get_resp.as_str().expect("valid utf8");
    assert!(get_text.contains("<timezone>UTC</timezone>"));
    assert!(get_text.contains("<first_run>2031-01-01T01:00:00Z</first_run>"));
    assert!(get_text.contains("<next_run>2031-01-01T01:00:00Z</next_run>"));

    server.shutdown().await;
}

#[tokio::test]
async fn matrix_tags_create_and_empty_trashcan() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let tag_id = create_and_get_id(
        &mut stream,
        b"<create_tag><name>Matrix Tag</name></create_tag>",
        "create_tag",
    )
    .await;

    let delete_resp = send_recv(
        &mut stream,
        format!("<delete_tag tag_id=\"{tag_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_resp.status_code(), Some(200));

    let trashed_before = send_recv(&mut stream, b"<get_tags trash=\"1\"/>").await;
    assert_eq!(trashed_before.status_code(), Some(200));
    let trashed_before_text = trashed_before.as_str().expect("valid utf8");
    assert!(trashed_before_text.contains(&tag_id));

    let empty_resp = send_recv(&mut stream, b"<empty_trashcan/>").await;
    assert_eq!(empty_resp.status_code(), Some(200));

    let trashed_after = send_recv(&mut stream, b"<get_tags trash=\"1\"/>").await;
    assert_eq!(trashed_after.status_code(), Some(200));
    let trashed_after_text = trashed_after.as_str().expect("valid utf8");
    assert!(
        trashed_after_text.contains("<tag_count>0")
            || trashed_after_text.contains("<filtered>0</filtered>")
            || !trashed_after_text.contains(&tag_id)
    );

    println!("STATEFUL_MATRIX_DONE");

    server.shutdown().await;
}
