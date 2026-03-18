// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Manual E2E harness for a real Greenbone Community container stack.

#![allow(clippy::print_stdout, clippy::too_many_lines)]

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use gvm_client::{parse_version_text, GmpClient, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::port_lists::{get_port_lists, GetPortListsOpts};
use gvm_gmp::commands::report_formats::{get_report_formats, GetReportFormatsOpts};
use gvm_gmp::commands::reports::get_report;
use gvm_gmp::commands::scan_configs::{get_scan_configs, GetScanConfigsOpts};
use gvm_gmp::commands::scanners::{get_scanners, GetScannersOpts};
use gvm_gmp::commands::targets::{create_target, delete_target, get_target, CreateTargetOpts};
use gvm_gmp::commands::tasks::{
    create_task, delete_task, get_task, start_task, stop_task, CreateTaskOpts,
};
use gvm_gmp::types::{EntityId, GmpVersion};
use gvm_protocol::Response;
use quick_xml::events::Event;
use quick_xml::Reader;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio::time::sleep;

const SMOKE_TARGET_NAME: &str = "e2e-test-target";
const SCAN_TARGET_NAME: &str = "e2e-scan-target";
const SCAN_TASK_NAME: &str = "e2e-scan-task";

fn main() -> ExitCode {
    match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => match runtime.block_on(async_main()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                log_line(&format!("E2E failure: {error}"));
                log_line(
                    "Capture container logs with: docker compose logs gvmd ospd-openvas openvasd > e2e-failure.log",
                );
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            log_line(&format!("failed to build Tokio runtime: {error}"));
            ExitCode::FAILURE
        }
    }
}

async fn async_main() -> Result<(), AppError> {
    let mode = Mode::from_args(env::args().skip(1))?;
    let config = EnvConfig::from_env()?;

    match mode {
        Mode::WaitReady => {
            wait_ready(&config).await?;
            log_line("gvmd is responsive");
        }
        Mode::Smoke => {
            let mut tracker = CleanupTracker::new(config.clone());
            run_smoke_suite(&config, &mut tracker).await?;
            tracker.cleanup_now().await?;
            log_line("E2E smoke suite passed");
        }
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct EnvConfig {
    username: String,
    password: String,
    socket_path: String,
    run_scan: bool,
}

impl EnvConfig {
    fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            username: env::var("GVM_ADMIN_USER").unwrap_or_else(|_| "admin".to_string()),
            password: env::var("GVM_ADMIN_PASS").unwrap_or_else(|_| "admin".to_string()),
            socket_path: env::var("GVM_SOCKET_PATH")
                .unwrap_or_else(|_| "/run/gvmd/gvmd.sock".to_string()),
            run_scan: matches!(
                env::var("E2E_RUN_SCAN")
                    .unwrap_or_else(|_| "0".to_string())
                    .as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES"
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Smoke,
    WaitReady,
}

impl Mode {
    fn from_args(args: impl Iterator<Item = String>) -> Result<Self, AppError> {
        let values: Vec<String> = args.collect();
        if values.is_empty() {
            return Ok(Self::Smoke);
        }

        if values.len() == 2 && values[0] == "--mode" {
            return match values[1].as_str() {
                "smoke" => Ok(Self::Smoke),
                "wait-ready" => Ok(Self::WaitReady),
                other => Err(AppError::Usage(format!(
                    "unsupported mode `{other}`; expected `smoke` or `wait-ready`"
                ))),
            };
        }

        Err(AppError::Usage(
            "usage: cargo run --example e2e_gvm_community -- --mode <smoke|wait-ready>".to_string(),
        ))
    }
}

#[derive(Debug)]
struct CleanupTracker {
    config: EnvConfig,
    target_ids: Vec<String>,
    task_ids: Vec<String>,
    armed: bool,
}

impl CleanupTracker {
    fn new(config: EnvConfig) -> Self {
        Self {
            config,
            target_ids: Vec::new(),
            task_ids: Vec::new(),
            armed: true,
        }
    }

    fn track_target(&mut self, id: &EntityId) {
        self.target_ids.push(id.to_string());
    }

    fn track_task(&mut self, id: &EntityId) {
        self.task_ids.push(id.to_string());
    }

    async fn cleanup_now(&mut self) -> Result<(), AppError> {
        self.cleanup_inner().await?;
        self.armed = false;
        Ok(())
    }

    async fn cleanup_inner(&mut self) -> Result<(), AppError> {
        if self.task_ids.is_empty() && self.target_ids.is_empty() {
            return Ok(());
        }

        let mut client = connect_client(&self.config).await?;

        while let Some(task_id) = self.task_ids.pop() {
            let entity_id = parse_entity_id(&task_id)?;
            let response = client.send(delete_task(&entity_id, true)).await?;
            log_cleanup_result("delete_task", &task_id, response.status_code());
        }

        while let Some(target_id) = self.target_ids.pop() {
            let entity_id = parse_entity_id(&target_id)?;
            let response = client.send(delete_target(&entity_id, true)).await?;
            log_cleanup_result("delete_target", &target_id, response.status_code());
        }

        client.disconnect().await?;
        Ok(())
    }
}

impl Drop for CleanupTracker {
    fn drop(&mut self) {
        if !self.armed || (self.task_ids.is_empty() && self.target_ids.is_empty()) {
            return;
        }

        let config = self.config.clone();
        let task_ids = self.task_ids.clone();
        let target_ids = self.target_ids.clone();

        match Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => {
                let result = runtime.block_on(async move {
                    let mut tracker = CleanupTracker {
                        config,
                        task_ids,
                        target_ids,
                        armed: false,
                    };
                    tracker.cleanup_inner().await
                });

                if let Err(error) = result {
                    log_line(&format!("cleanup after failure was incomplete: {error}"));
                }
            }
            Err(error) => {
                log_line(&format!("failed to build cleanup runtime: {error}"));
            }
        }
    }
}

#[derive(Debug, Error)]
enum AppError {
    #[error("{0}")]
    Assertion(String),
    #[error("{0}")]
    Usage(String),
    #[error("invalid entity id `{0}`")]
    InvalidEntityId(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Protocol(#[from] gvm_protocol::error::ProtocolError),
    #[error(transparent)]
    Xml(#[from] quick_xml::Error),
    #[error(transparent)]
    Client(#[from] GvmError),
}

async fn wait_ready(config: &EnvConfig) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;
    let response = client
        .send(gvm_gmp::commands::version::get_version())
        .await?;
    assert_status(&response, 200, "get_version")?;
    client.disconnect().await?;
    Ok(())
}

async fn run_smoke_suite(config: &EnvConfig, tracker: &mut CleanupTracker) -> Result<(), AppError> {
    let mut client = connect_client(config).await?;

    let version_response = client
        .send(gvm_gmp::commands::version::get_version())
        .await?;
    assert_status(&version_response, 200, "get_version")?;
    let version_text = version_response
        .child_text("version")
        .ok_or_else(|| AppError::Assertion("get_version response missing <version>".to_string()))?;
    let version = parse_version_text(&version_text)?;
    ensure(
        version >= GmpVersion(22, 4),
        &format!("expected GMP version >= 22.4, got {version}"),
    )?;
    log_pass("01", &format!("version negotiation ({version})"));

    let auth_response = client
        .call(authenticate(&config.username, &config.password))
        .await?;
    assert_status(&auth_response, 200, "authenticate")?;
    log_pass("02", "authentication");

    let configs_response = client
        .call(get_scan_configs(GetScanConfigsOpts::default()))
        .await?;
    assert_status(&configs_response, 200, "get_scan_configs")?;
    let config_count = count_elements(&configs_response, "config")?;
    ensure(config_count >= 1, "expected at least one scan config")?;
    log_pass("03", &format!("list scan configs ({config_count})"));

    let scanners_response = client
        .call(get_scanners(GetScannersOpts::default()))
        .await?;
    assert_status(&scanners_response, 200, "get_scanners")?;
    let scanner_count = count_elements(&scanners_response, "scanner")?;
    ensure(scanner_count >= 1, "expected at least one scanner")?;
    log_pass("04", &format!("list scanners ({scanner_count})"));

    let report_formats_response = client
        .call(get_report_formats(GetReportFormatsOpts::default()))
        .await?;
    assert_status(&report_formats_response, 200, "get_report_formats")?;
    log_pass(
        "05",
        &format!(
            "list report formats ({})",
            count_elements(&report_formats_response, "report_format")?
        ),
    );

    let port_lists_response = client
        .call(get_port_lists(GetPortListsOpts::default()))
        .await?;
    assert_status(&port_lists_response, 200, "get_port_lists")?;
    let port_list_count = count_elements(&port_lists_response, "port_list")?;
    ensure(port_list_count >= 1, "expected at least one port list")?;
    log_pass("06", &format!("list port lists ({port_list_count})"));

    let target_response = client
        .call(create_target(
            SMOKE_TARGET_NAME,
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                ..CreateTargetOpts::default()
            },
        ))
        .await?;
    assert_status(&target_response, 201, "create_target")?;
    let target_id = response_id(&target_response, "create_target")?;
    tracker.track_target(&target_id);
    log_pass("07", &format!("create target ({target_id})"));

    let get_target_response = client.call(get_target(&target_id)).await?;
    assert_status(&get_target_response, 200, "get_target")?;
    ensure(
        response_contains(&get_target_response, SMOKE_TARGET_NAME)?,
        "expected created target name in get_target response",
    )?;
    log_pass("08", "get target by UUID");

    let delete_target_response = client.call(delete_target(&target_id, true)).await?;
    assert_status(&delete_target_response, 200, "delete_target")?;
    tracker
        .target_ids
        .retain(|value| value != target_id.as_str());
    log_pass("09", "delete target");

    let verify_delete_response = client.send(get_target(&target_id)).await?;
    assert_status(&verify_delete_response, 404, "verify target deletion")?;
    log_pass("10", "verify deletion");

    if config.run_scan {
        run_scan_suite(&mut client, tracker).await?;
    }

    client.disconnect().await?;
    Ok(())
}

async fn run_scan_suite(
    client: &mut GmpClient<UnixSocketConnection>,
    tracker: &mut CleanupTracker,
) -> Result<(), AppError> {
    log_line("Running extended scan flow because E2E_RUN_SCAN=1");

    let scan_target = client
        .call(create_target(
            SCAN_TARGET_NAME,
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                ..CreateTargetOpts::default()
            },
        ))
        .await?;
    assert_status(&scan_target, 201, "create scan target")?;
    let target_id = response_id(&scan_target, "create scan target")?;
    tracker.track_target(&target_id);

    let config_id = first_element_id(
        &client
            .call(get_scan_configs(GetScanConfigsOpts::default()))
            .await?,
        "config",
    )?;
    let scanner_id = first_element_id(
        &client
            .call(get_scanners(GetScannersOpts::default()))
            .await?,
        "scanner",
    )?;

    let create_task_response = client
        .call(create_task(
            SCAN_TASK_NAME,
            &config_id,
            &target_id,
            &scanner_id,
            CreateTaskOpts::default(),
        ))
        .await?;
    assert_status(&create_task_response, 201, "create_task")?;
    let task_id = response_id(&create_task_response, "create_task")?;
    tracker.track_task(&task_id);

    let start_response = client.call(start_task(&task_id)).await?;
    assert_status(&start_response, 202, "start_task")?;
    let report_id = child_entity_id(&start_response, "report_id")?;

    let task_status = poll_task_status(client, &task_id, Duration::from_secs(30)).await?;
    if matches!(
        task_status.as_str(),
        "Running" | "Requested" | "Stop Requested"
    ) {
        let stop_response = client.call(stop_task(&task_id)).await?;
        assert_status(&stop_response, 200, "stop_task")?;
    } else {
        log_line(&format!(
            "scan task reached terminal status `{task_status}` before stop_task"
        ));
    }

    let report_response = client.call(get_report(&report_id)).await?;
    assert_status(&report_response, 200, "get_report")?;
    ensure(
        response_contains(&report_response, "<report ")?
            || response_contains(&report_response, "<results>")?
            || response_contains(&report_response, "<result>")?,
        "expected report payload in get_report response",
    )?;

    let delete_task_response = client.call(delete_task(&task_id, true)).await?;
    assert_status(&delete_task_response, 200, "delete_task")?;
    tracker.task_ids.retain(|value| value != task_id.as_str());

    let delete_target_response = client.call(delete_target(&target_id, true)).await?;
    assert_status(&delete_target_response, 200, "delete_target")?;
    tracker
        .target_ids
        .retain(|value| value != target_id.as_str());

    log_pass("11", "extended scan flow");
    Ok(())
}

async fn poll_task_status(
    client: &mut GmpClient<UnixSocketConnection>,
    task_id: &EntityId,
    timeout: Duration,
) -> Result<String, AppError> {
    let started = tokio::time::Instant::now();
    let mut last_status = String::from("unknown");

    while started.elapsed() <= timeout {
        let response = client.call(get_task(task_id)).await?;
        assert_status(&response, 200, "get_task")?;
        if let Some(status) = response.child_text("status") {
            last_status = status;
            if last_status != "New" {
                return Ok(last_status);
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    Err(AppError::Assertion(format!(
        "task {task_id} did not progress within {} seconds; last status: {last_status}",
        timeout.as_secs()
    )))
}

async fn connect_client(config: &EnvConfig) -> Result<GmpClient<UnixSocketConnection>, AppError> {
    let connection = UnixSocketConnection::with_path(&config.socket_path);
    Ok(GmpClient::connect(connection).await?)
}

fn assert_status(response: &Response, expected: u16, label: &str) -> Result<(), AppError> {
    let actual = response.status_code().unwrap_or_default();
    ensure(
        actual == expected,
        &format!(
            "{label} returned status {actual}, expected {expected}. Response: {}",
            response_summary(response)?
        ),
    )
}

fn response_id(response: &Response, label: &str) -> Result<EntityId, AppError> {
    let id = response.id().ok_or_else(|| {
        AppError::Assertion(format!("{label} response missing resource id attribute"))
    })?;
    parse_entity_id(&id)
}

fn child_entity_id(response: &Response, child_name: &str) -> Result<EntityId, AppError> {
    let id = response
        .child_text(child_name)
        .ok_or_else(|| AppError::Assertion(format!("response missing <{child_name}> element")))?;
    parse_entity_id(&id)
}

fn parse_entity_id(value: &str) -> Result<EntityId, AppError> {
    EntityId::from_str(value).map_err(|_| AppError::InvalidEntityId(value.to_string()))
}

fn count_elements(response: &Response, element_name: &str) -> Result<usize, AppError> {
    let xml = response.as_str()?;
    let mut reader = Reader::from_str(xml);
    let mut count = 0_usize;

    loop {
        match reader.read_event()? {
            Event::Start(ref event) | Event::Empty(ref event)
                if event.name().as_ref() == element_name.as_bytes() =>
            {
                count += 1;
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(count)
}

fn first_element_id(response: &Response, element_name: &str) -> Result<EntityId, AppError> {
    let xml = response.as_str()?;
    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event()? {
            Event::Start(ref event) | Event::Empty(ref event)
                if event.name().as_ref() == element_name.as_bytes() =>
            {
                for attribute in event.attributes().flatten() {
                    if attribute.key.as_ref() == b"id" {
                        let value = attribute
                            .decode_and_unescape_value(reader.decoder())?
                            .into_owned();
                        return parse_entity_id(&value);
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Err(AppError::Assertion(format!(
        "response did not contain <{element_name} id=\"...\">"
    )))
}

fn response_contains(response: &Response, needle: &str) -> Result<bool, AppError> {
    Ok(response.as_str()?.contains(needle))
}

fn response_summary(response: &Response) -> Result<String, AppError> {
    let xml = response.as_str()?;
    Ok(xml.chars().take(240).collect())
}

fn ensure(condition: bool, message: &str) -> Result<(), AppError> {
    if condition {
        Ok(())
    } else {
        Err(AppError::Assertion(message.to_string()))
    }
}

fn log_pass(step: &str, label: &str) {
    log_line(&format!("[pass] {step} {label}"));
}

fn log_cleanup_result(action: &str, id: &str, status: Option<u16>) {
    let rendered_status = status
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    log_line(&format!("[cleanup] {action} {id} -> {rendered_status}"));
}

fn log_line(message: &str) {
    let _ = writeln!(io::stdout(), "{message}");
}
