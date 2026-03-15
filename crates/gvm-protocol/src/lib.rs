//! Sans-I/O protocol core for the Greenbone Management Protocol (GMP).
//!
//! This crate implements the GMP XML framing state machine, decoupled from I/O.
//! It provides [`XmlCommand`] for building GMP XML commands and [`Response`] for
//! parsing GMP XML responses.

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unwrap_used
)]

pub mod error;
pub mod request;
pub mod response;
pub mod xml_command;
pub mod xml_reader;

pub use error::ProtocolError;
pub use request::Request;
pub use response::Response;
pub use xml_command::XmlCommand;
pub use xml_reader::XmlReader;
