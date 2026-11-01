//! Konflikt-Regel (O7/O8): S3-WALs sind die Wahrheit. Ist der lokale
//! OPFS-Stand aelter, werden die neueren S3-WALs replayed; die UI bekommt
//! ein Meldungs-Ereignis. Gleicher Stand + andere Kette = harter Konflikt.

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Resolution {
    /// Kein Konflikt: lokal ist aktuell.
    LocalCurrent,
    /// Aelterer lokaler Stand: S3-WALs ab `from_wal` replayen + UI-Meldung.
    ReplayRemote { from_wal: u64, message: String },
    /// Gleiche WAL-Nummer, andere Hash-Kette: manuelle Entscheidung noetig.
    ChainMismatch { message: String },
}

pub fn resolve(
    local_wal: u64,
    local_hash: &str,
    remote_wal: u64,
    remote_hash: &str,
) -> Resolution {
    if remote_wal > local_wal {
        return Resolution::ReplayRemote {
            from_wal: local_wal + 1,
            message: format!(
                "Lokaler Stand (WAL {local_wal}) ist aelter als S3 (WAL {remote_wal}); \
                 S3-WALs werden replayed."
            ),
        };
    }
    if remote_wal == local_wal && local_hash != remote_hash {
        return Resolution::ChainMismatch {
            message: format!(
                "WAL {local_wal} hat unterschiedliche Hash-Ketten (lokal/remote); \
                 manuelle Entscheidung noetig."
            ),
        };
    }
    Resolution::LocalCurrent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aelterer_lokaler_stand_replayed() {
        let r = resolve(7, "aa", 9, "bb");
        match r {
            Resolution::ReplayRemote { from_wal, message } => {
                assert_eq!(from_wal, 8);
                assert!(message.contains("WAL 9"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn gleicher_stand_andere_kette_ist_konflikt() {
        assert!(matches!(
            resolve(9, "aa", 9, "bb"),
            Resolution::ChainMismatch { .. }
        ));
        assert_eq!(resolve(9, "aa", 9, "aa"), Resolution::LocalCurrent);
    }
}
