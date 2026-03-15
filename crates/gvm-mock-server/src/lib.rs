// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Programmable mock GMP server for testing.
//!
//! Provides a configurable mock implementation of the GMP server protocol
//! in three modes:
//! - **Echo**: Returns well-formed generic responses for any command
//! - **Fixture**: Returns pre-built XML responses from a fixture library
//! - **Stateful**: Maintains an in-memory resource store with CRUD operations
//! - **Scenario**: Plays back a scripted command sequence with strict or lenient matching
//!
//! # Example
//! ```no_run
//! use gvm_mock_server::{MockGmpServer, ServerMode, GmpVersion};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let server = MockGmpServer::builder()
//!     .mode(ServerMode::Echo)
//!     .version(GmpVersion::V22_5)
//!     .unix_socket_auto()
//!     .build()
//!     .await?;
//!
//! let socket_path = server.socket_path().unwrap();
//! // ... connect clients and test ...
//! server.shutdown().await;
//! # Ok(())
//! # }
//! ```

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unwrap_used,
    clippy::unused_self,
    clippy::useless_format
)]

pub mod builder;
pub mod command_parser;
pub mod fault;
pub mod fixtures;
pub mod handler;
pub mod history;
pub mod listener;
pub mod response_gen;
pub mod scenario;
pub mod server;
pub mod store;
pub(crate) mod util;
pub mod version;

pub use builder::MockGmpServerBuilder;
pub use fault::{Fault, FaultEngine, FaultKind};
pub use history::CommandRecord;
pub use scenario::{ScenarioEngine, ScenarioMode, ScenarioOutcome, ScenarioStep};
pub use server::MockGmpServer;
pub use store::{Resource, ResourceStore};
pub use version::GmpVersion;

/// Server operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerMode {
    /// Returns well-formed generic responses for any recognized command.
    Echo,
    /// Returns pre-built XML responses from a fixture library.
    Fixture,
    /// Maintains an in-memory resource store with CRUD operations.
    Stateful,
    /// Plays back scripted responses from a scenario sequence.
    Scenario,
}
