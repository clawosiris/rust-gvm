//! GMP request trait.

/// A GMP request that can be serialized to XML bytes.
pub trait Request: Send {
    /// Serialize this request to GMP XML bytes.
    fn to_bytes(&self) -> Vec<u8>;
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
