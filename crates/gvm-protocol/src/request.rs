// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! GMP request trait.

/// A GMP request that can be serialized to XML bytes.
pub trait Request: Send {
    /// Serialize this request to GMP XML bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Return a semantic command name when a helper shares a wire command name
    /// with older GMP behavior.
    fn semantic_command_name(&self) -> Option<&'static str> {
        None
    }
}

/// Blanket implementation: anything that is a `Request` can be converted to bytes.
impl Request for Vec<u8> {
    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }
}

impl Request for &[u8] {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec_u8_request() {
        let data = b"<get_version/>".to_vec();
        assert_eq!(data.to_bytes(), b"<get_version/>");
    }

    #[test]
    fn test_slice_request() {
        let data: &[u8] = b"<get_tasks/>";
        assert_eq!(data.to_bytes(), b"<get_tasks/>");
    }
}
