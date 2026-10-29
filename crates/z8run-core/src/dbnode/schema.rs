//! Schema-Anzeige für Canvas/Proxy: Tabellen, Spalten, Zeilen, WAL-Stand,
//! Reservierung. Dieselben Felder liefert später das Sub-Canvas.

use crate::dbnode::handle::{open_readonly, DbHandle};
use crate::dbnode::types::{ColumnSchema, DbResult, SchemaInfo, TableSchema};

impl DbHandle {
    pub fn schema(&self) -> DbResult<SchemaInfo> {
        let conn = open_readonly(&self.db_path, &self.key)?;
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master \
             WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_z8_%' \
             ORDER BY name",
        )?;
        let names: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        drop(stmt);

        let (wal_stand, reserved_by) = {
            let s = self.stats.lock().unwrap();
            let r = self.reservation.lock().unwrap();
            (s.last_wal, r.by.clone())
        };
        let mut tables = Vec::with_capacity(names.len());
        for name in names {
            let mut cols = Vec::new();
            let quoted = name.replace('"', "\"\"");
            let mut cstmt =
                conn.prepare(&format!("PRAGMA table_info(\"{quoted}\")"))?;
            let mut rows = cstmt.query([])?;
            while let Some(row) = rows.next()? {
                cols.push(ColumnSchema {
                    name: row.get::<_, String>(1)?,
                    typ: row.get::<_, String>(2).unwrap_or_default(),
                });
            }
            drop(rows);
            drop(cstmt);
            let count: i64 = conn
                .query_row(&format!("SELECT count(*) FROM \"{quoted}\""), [], |r| r.get(0))
                .unwrap_or(0);
            tables.push(TableSchema {
                name,
                columns: cols,
                rows: count as u64,
                wal_stand,
                reserved_by: reserved_by.clone(),
            });
        }
        Ok(SchemaInfo {
            db_id: self.id.clone(),
            tables,
        })
    }
}
