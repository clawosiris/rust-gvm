// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Statically associated GMP request and response contracts.

use gvm_protocol::{Request, Response};

use crate::{responses::ParseError, GmpVersion};

/// A semantic GMP request whose response type is known at compile time.
///
/// Encoding remains the responsibility of [`Request`], so typed execution and
/// the raw/custom request escape hatch share the same XML command machinery.
/// Implementations may delegate to a public builder or provide an explicit
/// codec for irregular/custom XML. [`Request::semantic_command_name`] remains
/// authoritative when the wire root and capability name differ.
///
/// A downstream custom codec uses the same public contracts:
///
/// ```
/// use gvm_gmp::responses::ParseError;
/// use gvm_gmp::{GmpRequest, GmpResponse, GmpVersion};
/// use gvm_protocol::{Request, Response};
///
/// struct CustomRequest;
///
/// impl Request for CustomRequest {
///     fn to_bytes(&self) -> Vec<u8> {
///         b"<custom_command/>".to_vec()
///     }
/// }
///
/// #[derive(Debug, PartialEq, Eq)]
/// struct CustomResponse(u16);
///
/// impl GmpResponse for CustomResponse {
///     fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
///         let status = response
///             .status_code()
///             .ok_or_else(|| ParseError::MissingElement("status".into()))?;
///         let message = response
///             .status_text()
///             .ok_or_else(|| ParseError::MissingElement("status_text".into()))?;
///         if !(200..300).contains(&status) {
///             return Err(ParseError::ServerError { status, message });
///         }
///         Ok(Self(status))
///     }
/// }
///
/// impl GmpRequest for CustomRequest {
///     type Response = CustomResponse;
/// }
///
/// fn require_custom_response<R: GmpRequest<Response = CustomResponse>>(_: R) {}
/// require_custom_response(CustomRequest);
/// let raw = Response::new(
///     br#"<custom_command_response status="200" status_text="OK"/>"#.to_vec(),
/// );
/// assert_eq!(CustomResponse::decode(&raw, GmpVersion(22, 8))?, CustomResponse(200));
/// # Ok::<(), ParseError>(())
/// ```
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
///
/// Implementations must preserve the typed response contract: non-2xx GMP
/// statuses are returned as [`ParseError::ServerError`], and structural parse
/// errors retain enough field context to identify the malformed value. This is
/// the extension point for irregular or application-owned response codecs.
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
