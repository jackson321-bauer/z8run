//! Deterministic name mangling for the generated part of an export.
//!
//! Only the generated glue (config file names, generated identifiers) is
//! renamed. Code from `z8run-core` is included unchanged, as required.

use sha2::{Digest, Sha256};

/// Name generator for one export.
pub struct Names {
    readable: bool,
}

impl Names {
    pub fn new(readable: bool) -> Self {
        Self { readable }
    }

    fn digest(seed: &str, len: usize) -> String {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let hex = format!("{:x}", hasher.finalize());
        hex[..len].to_string()
    }

    fn slug(seed: &str) -> String {
        let mut s: String = seed
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if s.is_empty() || s.starts_with(|c: char| c.is_ascii_digit()) {
            s.insert(0, 'n');
        }
        s
    }

    /// Rust identifier for a generated item.
    pub fn ident(&self, seed: &str) -> String {
        if self.readable {
            format!("z8_{}", Self::slug(seed))
        } else {
            format!("z8_{}", Self::digest(seed, 10))
        }
    }

    /// File base name for per-node config files.
    pub fn file_base(&self, seed: &str) -> String {
        if self.readable {
            Self::slug(seed)
        } else {
            Self::digest(seed, 16)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mangled_names_are_stable_and_distinct() {
        let n = Names::new(false);
        assert_eq!(n.ident("a"), n.ident("a"));
        assert_ne!(n.ident("a"), n.ident("b"));
        assert!(n.file_base("a").len() == 16);
    }

    #[test]
    fn readable_names_are_slugs() {
        let n = Names::new(true);
        assert_eq!(n.ident("a-b"), "z8_a_b");
    }
}
