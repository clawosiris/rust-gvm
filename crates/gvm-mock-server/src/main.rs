// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! gvm-mock-server standalone binary.

#![allow(clippy::print_stderr, clippy::print_stdout)]

use clap::Parser;
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use std::io::Write as _;
#[cfg(feature = "tls")]
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "gvm-mock-server", about = "Programmable mock GMP server")]
struct Args {
    /// Server mode: echo, fixture, or stateful
    #[arg(long, default_value = "echo")]
    mode: String,

    /// GMP version to advertise
    #[arg(long, default_value = "22.7")]
    version: String,

    /// Unix socket path
    #[arg(long)]
    socket: Option<String>,

    /// TCP address (e.g., 127.0.0.1:9390)
    #[arg(long)]
    tcp: Option<String>,

    /// Maximum size of one XML request in bytes
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_request_bytes: usize,

    /// TLS address using a generated self-signed certificate (e.g., 127.0.0.1:9390)
    #[cfg(feature = "tls")]
    #[arg(long)]
    tls: Option<String>,

    /// PEM CA file whose client certificates must be presented during TLS handshakes
    #[cfg(feature = "tls")]
    #[arg(long, requires = "tls")]
    tls_client_ca: Option<PathBuf>,

    /// Write the generated public TLS server certificate to this PEM file
    #[cfg(feature = "tls")]
    #[arg(long, requires = "tls")]
    tls_cert_out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let mode = match args.mode.as_str() {
        "echo" => ServerMode::Echo,
        "fixture" => ServerMode::Fixture,
        "stateful" => ServerMode::Stateful,
        other => {
            eprintln!("Unknown mode: {other}. Use 'echo', 'fixture', or 'stateful'.");
            std::process::exit(1);
        }
    };

    let version = match args.version.as_str() {
        "22.4" => GmpVersion::V22_4,
        "22.5" => GmpVersion::V22_5,
        "22.6" => GmpVersion::V22_6,
        "22.7" => GmpVersion::V22_7,
        "22.8" => GmpVersion::V22_8,
        other => {
            eprintln!("Unknown version: {other}. Use 22.4, 22.5, 22.6, 22.7, or 22.8.");
            std::process::exit(1);
        }
    };

    let mut builder = MockGmpServer::builder()
        .mode(mode)
        .version(version)
        .with_max_request_bytes(Some(args.max_request_bytes));

    let transport_count = usize::from(args.socket.is_some()) + usize::from(args.tcp.is_some());
    #[cfg(feature = "tls")]
    let transport_count = transport_count + usize::from(args.tls.is_some());
    if transport_count != 1 {
        #[cfg(feature = "tls")]
        eprintln!("Specify exactly one of --socket, --tcp, or --tls");
        #[cfg(not(feature = "tls"))]
        eprintln!("Specify exactly one of --socket or --tcp");
        std::process::exit(1);
    }

    if let Some(socket) = args.socket {
        builder = builder.unix_socket(socket);
    } else if let Some(tcp) = args.tcp {
        builder = builder.tcp(tcp);
    }

    #[cfg(feature = "tls")]
    if let Some(tls) = args.tls {
        builder = builder.tls(tls);
        if let Some(client_ca) = args.tls_client_ca {
            builder = builder.require_client_cert(client_ca);
        }
    }

    let server = builder.build().await?;

    if let Some(path) = server.socket_path() {
        println!("Listening on Unix socket: {}", path.display());
    }
    if let Some(addr) = server.tcp_addr() {
        println!("Listening on TCP: {addr}");
    }
    #[cfg(feature = "tls")]
    announce_tls(&server, args.tls_cert_out.as_deref())?;
    std::io::stdout().flush()?;

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    println!("Shutting down...");
    server.shutdown().await;

    Ok(())
}

#[cfg(feature = "tls")]
fn announce_tls(
    server: &MockGmpServer,
    certificate_path: Option<&std::path::Path>,
) -> std::io::Result<()> {
    let Some(addr) = server.tls_addr() else {
        return Ok(());
    };
    if let Some(path) = certificate_path {
        let certificate = server
            .tls_certificate_pem()
            .expect("TLS listener has a certificate");
        std::fs::write(path, certificate)?;
    }
    println!("Listening on TLS: {addr}");
    if let Some(path) = certificate_path {
        println!("TLS certificate: {}", path.display());
    }
    Ok(())
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn tls_announcement_exports_certificate_and_ignores_other_transports() {
        let directory = TempDir::new().expect("temporary directory");
        let certificate_path = directory.path().join("server.pem");
        let tls_server = MockGmpServer::builder()
            .tls("127.0.0.1:0")
            .build()
            .await
            .expect("TLS server");
        announce_tls(&tls_server, Some(&certificate_path)).expect("announce TLS");
        assert!(std::fs::read_to_string(certificate_path)
            .expect("exported certificate")
            .contains("BEGIN CERTIFICATE"));
        announce_tls(&tls_server, None).expect("announce TLS without certificate export");
        tls_server.shutdown().await;

        let tcp_server = MockGmpServer::builder()
            .tcp("127.0.0.1:0")
            .build()
            .await
            .expect("TCP server");
        announce_tls(&tcp_server, None).expect("ignore non-TLS server");
        tcp_server.shutdown().await;
    }
}
