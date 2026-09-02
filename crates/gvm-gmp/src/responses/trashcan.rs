// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Trashcan response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EmptyTrashcanResponse {
    pub status: u16,
    pub status_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RestoreResponse {
    pub status: u16,
    pub status_text: String,
}

impl EmptyTrashcanResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let _ = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
        })
    }
}

impl GmpResponse for EmptyTrashcanResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl RestoreResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let _ = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
        })
    }
}

impl GmpResponse for RestoreResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_empty_trashcan_response() {
        let response =
            Response::from(r#"<empty_trashcan_response status="200" status_text="OK"/>"#);

        let parsed = EmptyTrashcanResponse::from_response(&response).expect("parse");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.status_text, "OK");
    }

    #[test]
    fn parses_restore_response() {
        let response = Response::from(r#"<restore_response status="200" status_text="OK"/>"#);

        let parsed = RestoreResponse::from_response(&response).expect("parse");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.status_text, "OK");
    }

    #[test]
    fn rejects_restore_not_found() {
        let response =
            Response::from(r#"<restore_response status="404" status_text="Resource not found"/>"#);

        let error = RestoreResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 404,
                message
            } if message == "Resource not found"
        ));
    }
}
