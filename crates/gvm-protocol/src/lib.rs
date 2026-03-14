//! Sans-I/O protocol core for the Greenbone Management Protocol (GMP).
//!
//! This crate implements the GMP XML framing state machine, decoupled from I/O.
//! It provides [`Connection`] for managing protocol state and [`XmlCommand`] for
//! building GMP XML commands.
