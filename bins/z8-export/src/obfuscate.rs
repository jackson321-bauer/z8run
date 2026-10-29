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

/// Mangled names for the generated runner's functions.
pub struct FnNames {
    pub resolve_env: String,
    pub compile_one: String,
    pub new_engine: String,
    pub parse_body: String,
    pub read_body: String,
    pub run: String,
    pub handle: String,
    pub parse_query: String,
    pub run_one: String,
}

impl FnNames {
    pub fn new(names: &Names) -> Self {
        Self {
            resolve_env: names.ident("resolve_env"),
            compile_one: names.ident("compile_one"),
            new_engine: names.ident("new_engine"),
            parse_body: names.ident("parse_body"),
            read_body: names.ident("read_body"),
            run: names.ident("run"),
            handle: names.ident("handle"),
            parse_query: names.ident("parse_query"),
            run_one: names.ident("run_one"),
        }
    }

    /// Applies all function-name placeholders to a generated source string.
    pub fn apply(&self, source: &str) -> String {
        source
            .replace("__FN_RESOLVE__", &self.resolve_env)
            .replace("__FN_COMPILE__", &self.compile_one)
            .replace("__FN_ENGINE__", &self.new_engine)
            .replace("__FN_PARSE_BODY__", &self.parse_body)
            .replace("__FN_READ_BODY__", &self.read_body)
            .replace("__FN_RUN__", &self.run)
            .replace("__FN_HANDLE__", &self.handle)
            .replace("__FN_PARSE_QUERY__", &self.parse_query)
            .replace("__FN_RUN_ONE__", &self.run_one)
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
