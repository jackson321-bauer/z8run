//! Fehlertypen des Proxy-Kerns. Keine I/O-, Netz- oder FS-Abhaengigkeit.

use serde::Serialize;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ProxyError {
    #[error("nicht authentifiziert")]
    Unauthorized,
    #[error("Token abgelaufen oder unbekannt")]
    TokenExpired,
    #[error("db_id nicht im Session-Scope")]
    NotInScope,
    #[error("ungueltige Anfrage: {0}")]
    BadRequest(String),
    #[error("nicht gefunden: {0}")]
    NotFound(String),
    #[error("DB-Kanal: {0}")]
    Db(String),
    #[error("WASM-App: {0}")]
    Wasm(String),
    #[error("Bundle: {0}")]
    Bundle(String),
    #[error("Stream: {0}")]
    Stream(String),
    #[error("intern: {0}")]
    Internal(String),
}

impl ProxyError {
    /// Stabiler Code fuer Antworten und Logs (nie Klartext-Geheimnisse).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::NotInScope => "NOT_IN_SCOPE",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Db(_) => "DB_ERROR",
            Self::Wasm(_) => "APP_ERROR",
            Self::Bundle(_) => "BUNDLE_ERROR",
            Self::Stream(_) => "STREAM_ERROR",
            Self::Internal(_) => "INTERNAL",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Self::Unauthorized | Self::TokenExpired => 401,
            Self::NotInScope => 403,
            Self::BadRequest(_) => 400,
            Self::NotFound(_) => 404,
            Self::Stream(_) => 409,
            Self::Db(_) | Self::Wasm(_) | Self::Bundle(_) | Self::Internal(_) => 500,
        }
    }
}

/// Oeffentliche Fehlerantwort ohne interne Details.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub error: String,
}

impl ErrorBody {
    pub fn from_error(e: &ProxyError) -> Self {
        Self {
            code: e.code().to_string(),
            error: e.to_string(),
        }
    }
}
