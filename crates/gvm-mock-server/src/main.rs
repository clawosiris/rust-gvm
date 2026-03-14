//! gvm-mock-server standalone binary.

use clap::Parser;
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};

#[derive(Parser)]
#[command(name = "gvm-mock-server", about = "Programmable mock GMP server")]
struct Args {
    /// Server mode: echo or fixture
    #[arg(long, default_value = "echo")]
    mode: String,

    /// GMP version to advertise
    #[arg(long, default_value = "22.5")]
    version: String,

    /// Unix socket path
    #[arg(long)]
    socket: Option<String>,

    /// TCP address (e.g., 127.0.0.1:9390)
    #[arg(long)]
    tcp: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let mode = match args.mode.as_str() {
        "echo" => ServerMode::Echo,
        "fixture" => ServerMode::Fixture,
        other => {
            eprintln!("Unknown mode: {other}. Use 'echo' or 'fixture'.");
            std::process::exit(1);
        }
    };

    let version = match args.version.as_str() {
        "22.4" => GmpVersion::V22_4,
        "22.5" => GmpVersion::V22_5,
        "22.6" => GmpVersion::V22_6,
        "22.7" => GmpVersion::V22_7,
        other => {
            eprintln!("Unknown version: {other}. Use 22.4, 22.5, 22.6, or 22.7.");
            std::process::exit(1);
        }
    };

    let mut builder = MockGmpServer::builder().mode(mode).version(version);

    if let Some(socket) = args.socket {
        builder = builder.unix_socket(socket);
    } else if let Some(tcp) = args.tcp {
        builder = builder.tcp(tcp);
    } else {
        eprintln!("Specify --socket or --tcp");
        std::process::exit(1);
    }

    let server = builder.build().await?;

    if let Some(path) = server.socket_path() {
        println!("Listening on Unix socket: {}", path.display());
    }
    if let Some(addr) = server.tcp_addr() {
        println!("Listening on TCP: {addr}");
    }

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    println!("Shutting down...");
    server.shutdown().await;

    Ok(())
}
