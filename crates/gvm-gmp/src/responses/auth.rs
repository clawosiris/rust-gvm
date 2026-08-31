// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Authentication response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticateResponse {
    pub status: u16,
    pub status_text: String,
}

impl AuthenticateResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let _ = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
        })
    }
}

impl GmpResponse for AuthenticateResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_authenticate_response() {
        let response = Response::from(
            r#"<authenticate_response status="200" status_text="OK"><role>Admin</role></authenticate_response>"#,
        );

        let parsed = AuthenticateResponse::from_response(&response).expect("authenticate parses");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.status_text, "OK");
    }

    #[test]
    fn parses_self_closing_authenticate_response() {
        let response = Response::from(r#"<authenticate_response status="200" status_text="OK"/>"#);

        let parsed = AuthenticateResponse::from_response(&response).expect("authenticate parses");

        assert_eq!(parsed.status, 200);
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<authenticate_response status="401" status_text="Denied"/>"#);

        let error = AuthenticateResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 401,
                message
            } if message == "Denied"
        ));
    }
}
