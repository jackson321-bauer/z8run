//! App-Auswahl + Bundle-Validierung aus der Secretbox (S1).
//!
//! Die Secretbox deklariert je Engine: Name, `standard_app`-Marker und den
//! Bucket/Prefix des Bundles. Beim Login gilt:
//!   - Standard-App ist PFLICHT (fehlt sie, ist die Welt kaputt -> 400).
//!   - Das Login-Feld `apps` darf NUR deklarierte Engines nennen; alles
//!     andere ist ein Gate-Fehler (400), wie beim Egress-Gate.
//!   - Fehlt `apps` oder ist es leer, wird NUR die Standard-App geladen.

use proxy_kern::ProxyError;
use serde_json::Value;

pub const MAX_WASM: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineDecl {
    pub name: String,
    pub standard_app: bool,
    pub bucket: String,
    pub prefix: String,
}

impl EngineDecl {
    pub fn is_loadable(&self) -> bool {
        !self.bucket.is_empty() && !self.prefix.is_empty()
    }
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Parst die Engine-Deklaration aus der Secretbox. Altlisten aus reinen
/// Strings bleiben gueltig, sind aber nicht ladbar (kein Bucket/Prefix).
pub fn parse_engines(value: &Value) -> Result<Vec<EngineDecl>, ProxyError> {
    let Some(list) = value.as_array() else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return Err(ProxyError::BadRequest("engines muss Liste sein".into()));
    };
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        match item {
            Value::String(name) => out.push(EngineDecl {
                name: name.clone(),
                standard_app: false,
                bucket: String::new(),
                prefix: String::new(),
            }),
            Value::Object(_) => {
                let name = text(item, "name");
                if name.is_empty() {
                    return Err(ProxyError::BadRequest(
                        "Engine-Deklaration ohne name".into(),
                    ));
                }
                out.push(EngineDecl {
                    name,
                    standard_app: item
                        .get("standard_app")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    bucket: text(item, "bucket"),
                    prefix: text(item, "prefix"),
                });
            }
            _ => {
                return Err(ProxyError::BadRequest(
                    "Engine-Deklaration muss String oder Objekt sein".into(),
                ))
            }
        }
    }
    Ok(out)
}

/// Waehlt die zu ladenden Engines: Standard-App immer, optionale Apps nur
/// wenn deklariert. Liefert eine leere Liste, wenn die Welt keine ladbaren
/// Deklarationen traegt (Alt-Welt ohne Bucket/Prefix).
pub fn selection(
    engines: &[EngineDecl],
    apps: Option<&Value>,
) -> Result<Vec<EngineDecl>, ProxyError> {
    let loadable: Vec<&EngineDecl> = engines.iter().filter(|e| e.is_loadable()).collect();
    if loadable.is_empty() {
        return Ok(Vec::new());
    }
    let standard: Vec<&EngineDecl> = loadable.iter().copied().filter(|e| e.standard_app).collect();
    if standard.is_empty() {
        return Err(ProxyError::BadRequest(
            "Standard-App fehlt in der Secretbox (Welt gilt als kaputt)".into(),
        ));
    }
    let mut chosen: Vec<EngineDecl> = standard.into_iter().cloned().collect();
    let requested = match apps {
        None | Some(Value::Null) => &[][..],
        Some(v) => v
            .as_array()
            .ok_or_else(|| ProxyError::BadRequest("apps muss Liste sein".into()))?
            .as_slice(),
    };
    for item in requested {
        let name = item
            .as_str()
            .ok_or_else(|| ProxyError::BadRequest("apps-Eintrag muss String sein".into()))?;
        let decl = loadable
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| ProxyError::BadRequest(format!("App {name} nicht deklariert")))?;
        if !chosen.iter().any(|c| c.name == decl.name) {
            chosen.push((*decl).clone());
        }
    }
    Ok(chosen)
}

/// Manifest-Pruefung vor dem Register (fail-closed).
pub fn validate_bundle(
    engine: &str,
    manifest: &Value,
    wasm: &[u8],
) -> Result<(String, String), ProxyError> {
    if wasm.is_empty() {
        return Err(ProxyError::Bundle("App-WASM leer".into()));
    }
    if wasm.len() > MAX_WASM {
        return Err(ProxyError::Bundle(format!(
            "App-WASM zu gross: {} > {}",
            wasm.len(),
            MAX_WASM
        )));
    }
    let name = text(manifest, "name");
    let version = text(manifest, "version");
    let app = text(manifest, "app");
    if name.is_empty() || version.is_empty() || app.is_empty() {
        return Err(ProxyError::Bundle("manifest: name/version/app fehlt".into()));
    }
    if name != engine {
        return Err(ProxyError::Bundle(format!(
            "manifest.name {name} != deklarierte App {engine}"
        )));
    }
    Ok((name, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dek() -> Vec<EngineDecl> {
        parse_engines(&json!([
            {"name": "hm-flow-kern", "standard_app": true, "bucket": "b", "prefix": "apps/hm/"},
            {"name": "sync", "standard_app": false, "bucket": "b", "prefix": "apps/sync/"}
        ]))
        .unwrap()
    }

    #[test]
    fn default_ist_nur_standard() {
        let sel = selection(&dek(), None).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].name, "hm-flow-kern");
    }

    #[test]
    fn auswahl_erweitert_und_behaelt_standard() {
        let sel = selection(&dek(), Some(&json!(["sync"]))).unwrap();
        let names: Vec<&str> = sel.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["hm-flow-kern", "sync"]);
    }

    #[test]
    fn undeklariert_ist_400() {
        let e = selection(&dek(), Some(&json!(["fremd"]))).unwrap_err();
        assert_eq!(e.status(), 400);
    }

    #[test]
    fn standard_fehlt_ist_400() {
        let d = parse_engines(&json!([
            {"name": "sync", "standard_app": false, "bucket": "b", "prefix": "apps/sync/"}
        ]))
        .unwrap();
        assert_eq!(selection(&d, None).unwrap_err().status(), 400);
    }

    #[test]
    fn altliste_ohne_bucket_laedt_nichts() {
        let d = parse_engines(&json!(["demo", "fts5"])).unwrap();
        assert!(selection(&d, Some(&json!(["demo"]))).unwrap().is_empty());
    }

    #[test]
    fn manifest_name_muss_passen() {
        let wasm = vec![0u8; 8];
        assert!(validate_bundle(
            "hm-flow-kern",
            &json!({"name": "hm-flow-kern", "version": "1", "app": "a.wasm"}),
            &wasm
        )
        .is_ok());
        assert!(validate_bundle(
            "sync",
            &json!({"name": "hm-flow-kern", "version": "1", "app": "a.wasm"}),
            &wasm
        )
        .is_err());
        assert!(validate_bundle(
            "x",
            &json!({"name": "x", "version": "1", "app": "a.wasm"}),
            &[]
        )
        .is_err());
    }
}
