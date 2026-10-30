//! LineFS-/Ordner-Aktionen des One-Shot-MCP-CLI (z8_db).
//! Ein Aufruf kann EINE Aktion oder eine `ops`-Liste (open/write/close in
//! einem Prozess) ausfuehren; Antworten enthalten nie den Masterkey.

use serde_json::{json, Value};
use z8run_core::dbnode::linefs_rows::{LinefsAktion, LinefsRequest};
use z8run_core::dbnode::DbNode;

fn tag(op: &str) -> Option<&'static str> {
    Some(match op {
        "linefs_anlegen" | "LinefsAnlegen" => "LinefsAnlegen",
        "linefs_open" | "linefs_oeffnen" | "LinefsOeffnen" => "LinefsOeffnen",
        "linefs_read" | "linefs_lesen" | "LinefsLesen" => "LinefsLesen",
        "linefs_write" | "linefs_zeile_setzen" | "LinefsZeileSetzen" => "LinefsZeileSetzen",
        "linefs_insert" | "linefs_einfuegen" | "LinefsEinfuegen" => "LinefsEinfuegen",
        "linefs_delete" | "linefs_zeile_loeschen" | "LinefsZeileLoeschen" => "LinefsZeileLoeschen",
        "linefs_search" | "linefs_suchen" | "LinefsSuchen" => "LinefsSuchen",
        "linefs_replace" | "linefs_ersetzen" | "LinefsErsetzen" => "LinefsErsetzen",
        "linefs_save" | "linefs_speichern" | "LinefsSpeichern" => "LinefsSpeichern",
        "linefs_close" | "linefs_schliessen" | "LinefsSchliessen" => "LinefsSchliessen",
        "linefs_render" | "linefs_rendere" | "LinefsRendere" => "LinefsRendere",
        "linefs_pages" | "linefs_seiten" | "LinefsSeiten" => "LinefsSeiten",
        "linefs_history" | "linefs_historie" | "LinefsHistorie" => "LinefsHistorie",
        "linefs_point_in_time" | "linefs_stand_zu_zeitpunkt" | "LinefsStandZuZeitpunkt" => "LinefsStandZuZeitpunkt",
        "linefs_rename" | "linefs_umbenennen" | "LinefsUmbenennen" => "LinefsUmbenennen",
        "linefs_verify" | "linefs_kette_pruefen" | "LinefsKettePruefen" => "LinefsKettePruefen",
        "linefs_render_process" | "linefs_render_fuer_prozess" | "LinefsRenderFuerProzess" => "LinefsRenderFuerProzess",
        "linefs_process_end" | "linefs_prozess_ende" | "LinefsProzessEnde" => "LinefsProzessEnde",
        "linefs_blob_put" | "linefs_binaer_hochladen" | "LinefsBinaerHochladen" => "LinefsBinaerHochladen",
        "linefs_blob_show" | "linefs_binaer_zeigen" | "LinefsBinaerZeigen" => "LinefsBinaerZeigen",
        "linefs_blob_get" | "linefs_binaer_holen" | "LinefsBinaerHolen" => "LinefsBinaerHolen",
        "to_binary" | "linefs_uebergang_zu_binaer" | "LinefsUebergangZuBinaer" => "LinefsUebergangZuBinaer",
        "to_text" | "linefs_uebergang_zu_text" | "LinefsUebergangZuText" => "LinefsUebergangZuText",
        "ordner_anlegen" | "OrdnerAnlegen" => "OrdnerAnlegen",
        "ordner_verschieben" | "OrdnerVerschieben" => "OrdnerVerschieben",
        "ordner_umbenennen" | "OrdnerUmbenennen" => "OrdnerUmbenennen",
        "ordner_listen" | "OrdnerListen" => "OrdnerListen",
        "ordner_pfad_aufloesen" | "OrdnerPfadAufloesen" => "OrdnerPfadAufloesen",
        _ => return None,
    })
}

fn aktion(v: &Value) -> Result<LinefsAktion, (String, String)> {
    let op = v["op"].as_str().or_else(|| v["action"].as_str()).unwrap_or("");
    let Some(t) = tag(op) else {
        return Err(("ACTION".into(), format!("unbekannte LineFS-Aktion: {op}")));
    };
    let mut obj = v.as_object().cloned().unwrap_or_default();
    obj.insert("op".into(), Value::String(t.into()));
    serde_json::from_value(Value::Object(obj))
        .map_err(|e| ("ACTION".into(), format!("{t}: {e}")))
}

pub async fn run(
    node: &DbNode, db: &str, session: &str, v: &Value,
) -> Result<Value, (String, String)> {
    let ops: Vec<LinefsAktion> = match v.get("ops").and_then(|x| x.as_array()) {
        Some(list) => list.iter().map(aktion).collect::<Result<_, _>>()?,
        None => vec![aktion(v)?],
    };
    node.reserve(db, session).map_err(|e| (e.code, e.message))?;
    let mut out = Vec::new();
    for a in ops {
        match node.linefs(LinefsRequest {
            db_id: db.to_string(), session_id: session.to_string(), aktion: a,
        }).await {
            Ok(x) => out.push(x),
            Err(e) => {
                let _ = node.release(db, session);
                return Err((e.code, e.message));
            }
        }
    }
    let _ = node.release(db, session);
    Ok(if out.len() == 1 {
        json!({"status": 200, "ergebnis": out.remove(0)})
    } else {
        json!({"status": 200, "ergebnisse": out})
    })
}
