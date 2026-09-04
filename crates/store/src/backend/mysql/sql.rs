/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Subspace;

pub(crate) struct SubspaceSql {
    pub(crate) get_value: Box<str>,
    pub(crate) get_value_for_update: Box<str>,
    pub(crate) key_exists: Box<str>,
    pub(crate) insert_value: Box<str>,
    pub(crate) update_value: Box<str>,
    pub(crate) upsert_value: Box<str>,
    pub(crate) insert_presence: Box<str>,
    pub(crate) delete_key: Box<str>,
    pub(crate) increment: Box<str>,
    pub(crate) decrement: Box<str>,
    pub(crate) increment_returning: Box<str>,
    pub(crate) delete_range: Box<str>,
    pub(crate) range_boundary: Box<str>,
    pub(crate) purge_zero: Box<str>,
    pub(crate) purge_zero_range: Box<str>,
    pub(crate) purge_zero_from: Box<str>,
    pub(crate) purge_boundary: Box<str>,
    iterate: [Box<str>; 8],
}

pub(crate) struct SqlStatements {
    statements: Box<[SubspaceSql]>,
}

impl SubspaceSql {
    fn new(subspace: Subspace) -> Self {
        let table = subspace.name();
        let range = |order: &str, limit: &str, columns: &str| {
            format!(
                "SELECT {columns} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k {order}{limit}"
            )
            .into_boxed_str()
        };

        Self {
            get_value: format!("SELECT v FROM {table} WHERE k = ?").into_boxed_str(),
            get_value_for_update: format!("SELECT v FROM {table} WHERE k = ? FOR UPDATE")
                .into_boxed_str(),
            key_exists: format!("SELECT 1 FROM {table} WHERE k = ?").into_boxed_str(),
            insert_value: format!("INSERT INTO {table} (k, v) VALUES (?, ?)").into_boxed_str(),
            update_value: format!("UPDATE {table} SET v = ? WHERE k = ?").into_boxed_str(),
            upsert_value: format!(
                "INSERT INTO {table} (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)"
            )
            .into_boxed_str(),
            insert_presence: format!(
                "INSERT INTO {table} (k) VALUES (?) ON DUPLICATE KEY UPDATE k = k"
            )
            .into_boxed_str(),
            delete_key: format!("DELETE FROM {table} WHERE k = ?").into_boxed_str(),
            increment: format!(
                "INSERT INTO {table} (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = v + VALUES(v)"
            )
            .into_boxed_str(),
            decrement: format!("UPDATE {table} SET v = v + ? WHERE k = ?").into_boxed_str(),
            increment_returning: format!(
                "INSERT INTO {table} (k, v) VALUES (?, LAST_INSERT_ID(?)) ON DUPLICATE KEY UPDATE v = LAST_INSERT_ID(v + ?)"
            )
            .into_boxed_str(),
            delete_range: format!("DELETE FROM {table} WHERE k >= ? AND k < ?").into_boxed_str(),
            range_boundary: format!(
                "SELECT k FROM {table} WHERE k >= ? AND k < ? ORDER BY k ASC LIMIT ?, 1"
            )
            .into_boxed_str(),
            purge_zero: format!("DELETE FROM {table} WHERE v = 0").into_boxed_str(),
            purge_zero_range: format!("DELETE FROM {table} WHERE v = 0 AND k >= ? AND k < ?")
                .into_boxed_str(),
            purge_zero_from: format!("DELETE FROM {table} WHERE v = 0 AND k >= ?").into_boxed_str(),
            purge_boundary: format!(
                "SELECT k FROM {table} WHERE k >= ? ORDER BY k ASC LIMIT ?, 1"
            )
            .into_boxed_str(),
            iterate: [
                range("ASC", "", "k"),
                range("ASC", "", "k, v"),
                range("DESC", "", "k"),
                range("DESC", "", "k, v"),
                range("ASC", " LIMIT 1", "k"),
                range("ASC", " LIMIT 1", "k, v"),
                range("DESC", " LIMIT 1", "k"),
                range("DESC", " LIMIT 1", "k, v"),
            ],
        }
    }

    #[inline(always)]
    pub(crate) fn iterate(&self, first: bool, ascending: bool, values: bool) -> &str {
        &self.iterate[((first as usize) << 2) | ((!ascending as usize) << 1) | (values as usize)]
    }
}

impl SqlStatements {
    pub(crate) fn new() -> Self {
        Self {
            statements: Subspace::ALL
                .iter()
                .copied()
                .map(SubspaceSql::new)
                .collect(),
        }
    }

    #[inline(always)]
    pub(crate) fn get(&self, subspace: Subspace) -> &SubspaceSql {
        &self.statements[subspace.index()]
    }
}
