#[allow(dead_code)]

pub struct Digest {
    algorithm: String,
    hex: String,
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
}