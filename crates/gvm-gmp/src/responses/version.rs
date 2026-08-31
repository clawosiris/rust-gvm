// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Version response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetVersionResponse {
    pub status: u16,
    pub status_text: String,
    pub version: String,
}

impl GetVersionResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
            version: root.required_child_text("version")?,
        })
    }
}

impl GmpResponse for GetVersionResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_version_response() {
        let response = Response::from(
            r#"<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>"#,
        );

        let parsed = GetVersionResponse::from_response(&response).expect("version parses");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.status_text, "OK");
        assert_eq!(parsed.version, "22.7");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_version_response status="500" status_text="Backend down"/>"#);

        let error = GetVersionResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 500,
                message
            } if message == "Backend down"
        ));
    }

    #[test]
    fn rejects_missing_version() {
        let response = Response::from(r#"<get_version_response status="200" status_text="OK"/>"#);

        let error = GetVersionResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(error, ParseError::MissingElement(ref field) if field == "version"));
    }
}
