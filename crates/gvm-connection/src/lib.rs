//! Transport layer for GVM connections.
//!
//! Provides async connection implementations for communicating with gvmd:
//! - Unix domain sockets (default)
//! - TLS over TCP (feature: `tls`)
//! - SSH tunnels (feature: `ssh`)
