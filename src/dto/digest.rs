pub struct Digest {
    algorithm: String,
    hex: String,
}

pub enum DigestError {
    InvalidDigestString(String),
}

impl Digest {
    /// Check if a string is a digest
    pub fn is_digest(s: &str) -> bool {
        if let Some(idx) = s.find(":") {
            let (algo, hex) = s.split_at(idx);

            return !algo.is_empty() && !hex.is_empty();
        }

        false
    }

    pub fn from_string(s: &str) -> Result<Self, DigestError> {
        if let Some(idx) = s.find(":") {
            let (algo, hex) = s.split_at(idx);

            return Ok(Self {
                algorithm: algo.to_string(),
                hex: hex.to_string(),
            })
        }

        Err(DigestError::InvalidDigestString(String::from(s)))
    }
}