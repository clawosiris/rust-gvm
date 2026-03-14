//! High-level async GMP client with version negotiation.
//!
//! Combines [`gvm_connection`], [`gvm_protocol`], and [`gvm_gmp`] into a
//! single client that connects, negotiates the GMP version, and provides
//! typed access to all GMP commands.
