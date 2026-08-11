// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Deterministic task/resource graph integrity coverage for Stateful mode.

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::unwrap_used, missing_docs)]

use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

const DEFAULT_CONFIG_ID: &str = "daba56c8-73ec-11df-a475-002264764cea";
const DEFAULT_SCANNER_ID: &str = "08b69003-5fc2-4037-a479-93b440211c73";

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buffer = vec![0_u8; 64 * 1024];
    let size = stream.read(&mut buffer).await.expect("read failed");
    buffer.truncate(size);
    Response::new(buffer)
}

async fn server() -> Option<MockGmpServer> {
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

async fn server_with_schedule() -> Option<(MockGmpServer, String)> {
    let schedule = Resource::new("schedule", "Import-Ignored Schedule");
    let schedule_id = schedule.id.to_string();
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .seed(move |store| store.seed(schedule))
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some((server, schedule_id)),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }
}

async fn connect_and_auth(server: &MockGmpServer) -> UnixStream {
    let mut stream = UnixStream::connect(server.socket_path().expect("socket path"))
        .await
        .expect("connect failed");
    let response = send_recv(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
    stream
}

fn id(response: &Response) -> String {
    response.id().expect("response id")
}

fn report_id(response: &Response) -> String {
    let text = response.as_str().expect("UTF-8 response");
    let start = text.find("<report_id>").expect("report_id start") + "<report_id>".len();
    let end = text[start..].find("</report_id>").expect("report_id end") + start;
    text[start..end].to_string()
}

async fn create_target(stream: &mut UnixStream, name: &str) -> String {
    let response = send_recv(
        stream,
        format!("<create_target><name>{name}</name><hosts>127.0.0.1</hosts></create_target>")
            .as_bytes(),
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    id(&response)
}

async fn create_task(stream: &mut UnixStream, name: &str, target_id: &str) -> String {
    let response = send_recv(
        stream,
        format!("<create_task><name>{name}</name><target id=\"{target_id}\"/></create_task>")
            .as_bytes(),
    )
    .await;
    assert_eq!(response.status_code(), Some(201));
    id(&response)
}

async fn assert_import_schedule_state(stream: &mut UnixStream, task_id: &str, periods: u32) {
    let response = send_recv(
        stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
    let text = response.as_str().expect("UTF-8 response");
    assert!(!text.contains("<schedule id="), "{text}");
    assert!(
        text.contains(&format!("<schedule_periods>{periods}</schedule_periods>")),
        "{text}"
    );
}

#[tokio::test]
async fn import_task_creation_ignores_schedule_fields_without_validating_them() {
    let Some((server, schedule_id)) = server_with_schedule().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let commands = [
        format!(
            "<create_task><name>Valid Ignored Schedule</name><target id=\"0\"/><schedule id=\"{schedule_id}\"/><schedule_periods>3</schedule_periods></create_task>"
        ),
        "<create_task><name>Missing Ignored Schedule</name><target id=\"0\"/><schedule/><schedule_periods/></create_task>".to_string(),
        "<create_task><name>Malformed Ignored Schedule</name><target id=\"0\"/><schedule id=\"not-a-uuid\"/><schedule_periods>not-a-number</schedule_periods></create_task>".to_string(),
    ];

    for command in commands {
        let response = send_recv(&mut stream, command.as_bytes()).await;
        assert_eq!(response.status_code(), Some(201), "{command}");
        assert_import_schedule_state(&mut stream, &id(&response), 0).await;
    }

    server.shutdown().await;
}

#[tokio::test]
async fn import_task_modify_rejects_schedule_ids_but_allows_periods_only() {
    let Some((server, schedule_id)) = server_with_schedule().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;
    let create = send_recv(
        &mut stream,
        b"<create_task><name>Mutable Import</name><target id=\"0\"/></create_task>",
    )
    .await;
    assert_eq!(create.status_code(), Some(201));
    let task_id = id(&create);

    let set = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{task_id}\"><schedule id=\"{schedule_id}\"/><schedule_periods>4</schedule_periods></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(set.status_code(), Some(400));
    assert_import_schedule_state(&mut stream, &task_id, 0).await;

    let periods_only = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{task_id}\"><schedule_periods>7</schedule_periods></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(periods_only.status_code(), Some(200));
    assert_import_schedule_state(&mut stream, &task_id, 7).await;

    let clear = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{task_id}\"><schedule id=\"0\"/><schedule_periods>3</schedule_periods></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(clear.status_code(), Some(400));
    assert_import_schedule_state(&mut stream, &task_id, 7).await;

    server.shutdown().await;
}

#[tokio::test]
async fn task_creation_rejects_missing_malformed_and_wrong_type_references() {
    let Some(server) = server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;

    let missing_target = send_recv(
        &mut stream,
        b"<create_task><name>No Target</name></create_task>",
    )
    .await;
    assert_eq!(missing_target.status_code(), Some(400));

    let malformed_target = send_recv(
        &mut stream,
        b"<create_task><name>Bad Target</name><target id=\"not-a-uuid\"/></create_task>",
    )
    .await;
    assert_eq!(malformed_target.status_code(), Some(400));

    let absent_target = send_recv(
        &mut stream,
        b"<create_task><name>Absent Target</name><target id=\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"/></create_task>",
    )
    .await;
    assert_eq!(absent_target.status_code(), Some(404));

    let wrong_type = send_recv(
        &mut stream,
        format!(
            "<create_task><name>Wrong Target Type</name><target id=\"{DEFAULT_CONFIG_ID}\"/></create_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(wrong_type.status_code(), Some(404));

    let tasks = send_recv(&mut stream, b"<get_tasks/>").await;
    assert!(tasks
        .as_str()
        .expect("UTF-8 response")
        .contains("<task_count>0"));

    let target_id = create_target(&mut stream, "Valid Target").await;
    let task_id = create_task(&mut stream, "Valid Task", &target_id).await;

    for command in [
        format!("<modify_task task_id=\"{task_id}\"><target/></modify_task>"),
        format!("<modify_task task_id=\"{task_id}\"><config/></modify_task>"),
        format!("<modify_task task_id=\"{task_id}\"><scanner/></modify_task>"),
        format!("<modify_task task_id=\"{task_id}\"><scanner id=\"not-a-uuid\"/></modify_task>"),
    ] {
        let response = send_recv(&mut stream, command.as_bytes()).await;
        assert_eq!(response.status_code(), Some(400), "{command}");
    }

    for command in [
        "<create_report><task/></create_report>",
        "<create_report><task id=\"not-a-uuid\"/></create_report>",
    ] {
        let response = send_recv(&mut stream, command.as_bytes()).await;
        assert_eq!(response.status_code(), Some(400), "{command}");
    }

    let wrong_typed_get = send_recv(
        &mut stream,
        format!("<get_targets target_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(wrong_typed_get.status_code(), Some(404));

    server.shutdown().await;
}

#[tokio::test]
async fn corrupt_seeded_task_graph_is_rejected_instead_of_cloned() {
    let mut corrupt_task = Resource::new("task", "Corrupt Seed");
    corrupt_task.set_attr("status", "New");
    let corrupt_task_id = corrupt_task.id;
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .seed(move |store| store.seed(corrupt_task))
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("server start failed: {error}"),
    };
    let mut stream = connect_and_auth(&server).await;

    let response = send_recv(
        &mut stream,
        format!("<create_task><copy>{corrupt_task_id}</copy><name>Copy</name></create_task>")
            .as_bytes(),
    )
    .await;
    assert_eq!(response.status_code(), Some(409));
    assert!(response
        .as_str()
        .expect("UTF-8 response")
        .contains("Task graph is inconsistent: target"));

    let absent_id = Uuid::new_v4();
    let absent_clone = send_recv(
        &mut stream,
        format!("<create_task><copy>{absent_id}</copy></create_task>").as_bytes(),
    )
    .await;
    assert_eq!(absent_clone.status_code(), Some(404));

    server.shutdown().await;
}

#[tokio::test]
async fn referenced_resources_cannot_be_removed_or_addressed_as_another_type() {
    let Some(server) = server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;
    let target_id = create_target(&mut stream, "Linked Target").await;
    let task_id = create_task(&mut stream, "Linked Task", &target_id).await;

    for command in [
        format!("<delete_target target_id=\"{target_id}\" ultimate=\"0\"/>"),
        format!("<delete_config config_id=\"{DEFAULT_CONFIG_ID}\" ultimate=\"0\"/>"),
        format!("<delete_scanner scanner_id=\"{DEFAULT_SCANNER_ID}\" ultimate=\"0\"/>"),
    ] {
        let response = send_recv(&mut stream, command.as_bytes()).await;
        assert_eq!(response.status_code(), Some(409), "{command}");
    }

    let wrong_typed_delete = send_recv(
        &mut stream,
        format!("<delete_target target_id=\"{task_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(wrong_typed_delete.status_code(), Some(404));

    let delete_task = send_recv(
        &mut stream,
        format!("<delete_task task_id=\"{task_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_task.status_code(), Some(200));
    let trash_target = send_recv(
        &mut stream,
        format!("<delete_target target_id=\"{target_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;
    assert_eq!(trash_target.status_code(), Some(200));

    let restore_task = send_recv(
        &mut stream,
        format!("<restore id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(restore_task.status_code(), Some(404));
    let ultimate_target = send_recv(
        &mut stream,
        format!("<delete_target target_id=\"{target_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(ultimate_target.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn task_reference_updates_are_validated_and_only_allowed_while_new() {
    let Some(server) = server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;
    let first_target_id = create_target(&mut stream, "First Target").await;
    let second_target_id = create_target(&mut stream, "Second Target").await;
    let task_id = create_task(&mut stream, "Mutable Task", &first_target_id).await;

    let wrong_type = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{task_id}\"><target id=\"{DEFAULT_CONFIG_ID}\"/></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(wrong_type.status_code(), Some(404));

    let update = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{task_id}\"><target id=\"{second_target_id}\"/></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(update.status_code(), Some(200));
    let task = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert!(task.as_str().expect("UTF-8 response").contains(&format!(
        "<target id=\"{second_target_id}\"><name></name></target>"
    )));

    let old_target_delete = send_recv(
        &mut stream,
        format!("<delete_target target_id=\"{first_target_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(old_target_delete.status_code(), Some(200));

    let start = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start.status_code(), Some(202));
    let running_update = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{task_id}\"><target id=\"{second_target_id}\"/></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(running_update.status_code(), Some(409));

    server.shutdown().await;
}

#[tokio::test]
async fn stop_and_resume_preserve_one_report_and_update_both_statuses() {
    let Some(server) = server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;
    let target_id = create_target(&mut stream, "Lifecycle Target").await;
    let task_id = create_task(&mut stream, "Lifecycle Task", &target_id).await;

    let start = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let started_report_id = report_id(&start);
    let active_delete = send_recv(
        &mut stream,
        format!("<delete_report report_id=\"{started_report_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(active_delete.status_code(), Some(409));

    let stop = send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(stop.status_code(), Some(200));
    let stopped_report = send_recv(
        &mut stream,
        format!("<get_reports report_id=\"{started_report_id}\"/>").as_bytes(),
    )
    .await;
    assert!(stopped_report
        .as_str()
        .expect("UTF-8 response")
        .contains("<status>Stopped</status>"));

    let resume = send_recv(
        &mut stream,
        format!("<resume_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(report_id(&resume), started_report_id);
    let reports = send_recv(&mut stream, b"<get_reports/>").await;
    assert!(reports
        .as_str()
        .expect("UTF-8 response")
        .contains("<report_count>1"));

    send_recv(
        &mut stream,
        format!("<stop_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let delete_stopped_report = send_recv(
        &mut stream,
        format!("<delete_report report_id=\"{started_report_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_stopped_report.status_code(), Some(200));
    let task = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    let task_text = task.as_str().expect("UTF-8 response");
    assert!(task_text.contains("<status>New</status>"));
    assert!(!task_text.contains("<report_id>"));
    let resume_without_report = send_recv(
        &mut stream,
        format!("<resume_task task_id=\"{task_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(resume_without_report.status_code(), Some(409));

    server.shutdown().await;
}

#[tokio::test]
async fn imported_reports_require_an_existing_task_and_task_deletion_cascades() {
    let Some(server) = server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;
    let target_id = create_target(&mut stream, "Import Target").await;
    let task_id = create_task(&mut stream, "Import Task", &target_id).await;

    let wrong_type = send_recv(
        &mut stream,
        format!("<create_report><task id=\"{target_id}\"/></create_report>").as_bytes(),
    )
    .await;
    assert_eq!(wrong_type.status_code(), Some(404));

    let linked_report = send_recv(
        &mut stream,
        format!("<create_report><task id=\"{task_id}\"/></create_report>").as_bytes(),
    )
    .await;
    assert_eq!(linked_report.status_code(), Some(201));
    let linked_report_id = id(&linked_report);

    let delete_task = send_recv(
        &mut stream,
        format!("<delete_task task_id=\"{task_id}\" ultimate=\"1\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete_task.status_code(), Some(200));
    let report = send_recv(
        &mut stream,
        format!("<get_reports report_id=\"{linked_report_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(report.status_code(), Some(404));

    server.shutdown().await;
}
