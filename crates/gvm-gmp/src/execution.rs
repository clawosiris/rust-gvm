// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Statically associated GMP request and response contracts.

use gvm_protocol::{Request, Response};

use crate::{responses::ParseError, GmpVersion};

/// A semantic GMP request whose response type is known at compile time.
///
/// Encoding remains the responsibility of [`Request`], so typed execution and
/// the raw/custom request escape hatch share the same XML command machinery.
///
/// A request cannot be associated with an unrelated response type:
///
/// ```compile_fail
/// use gvm_gmp::commands::version::GetVersionRequest;
/// use gvm_gmp::responses::AuthenticateResponse;
/// use gvm_gmp::GmpRequest;
///
/// fn require_authentication<R: GmpRequest<Response = AuthenticateResponse>>(_: R) {}
/// require_authentication(GetVersionRequest::new());
/// ```
pub trait GmpRequest: Request {
    /// The only typed response produced by this request.
    type Response: GmpResponse;
}

/// A typed GMP response that can decode the protocol response envelope.
pub trait GmpResponse: Sized {
    /// Decode a typed value from a raw GMP response.
    ///
    /// The negotiated `version` is available to response models whose wire
    /// shape varies by GMP version. Models that are version-independent may
    /// ignore it.
    ///
    /// # Errors
    /// Returns the response model's existing parse or server-status error.
    fn decode(response: &Response, version: GmpVersion) -> Result<Self, ParseError>;
}
