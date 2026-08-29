/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Subspace;

const SLOTS: usize = u8::MAX as usize + 1;

pub(crate) struct SubspaceSql {
    pub(crate) get_value: Box<str>,
    pub(crate) key_exists: Box<str>,
    pub(crate) upsert_value: Box<str>,
    pub(crate) insert_presence: Box<str>,
    pub(crate) delete_key: Box<str>,
    pub(crate) increment: Box<str>,
    pub(crate) decrement: Box<str>,
    pub(crate) increment_returning: Box<str>,
    pub(crate) delete_range: Box<str>,
    pub(crate) purge_zero: Box<str>,
    iterate: [Box<str>; 8],
}

pub(crate) struct SqlStatements {
    statements: Vec<SubspaceSql>,
    slots: [u8; SLOTS],
}

impl SubspaceSql {
    fn new(subspace: Subspace) -> Self {
        let table = subspace.name();
        let range = |order: &str, limit: &str, columns: &str| {
            format!("SELECT {columns} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k {order}{limit}")
                .into_boxed_str()
        };

        Self {
            get_value: format!("SELECT v FROM {table} WHERE k = ?").into_boxed_str(),
            key_exists: format!("SELECT 1 FROM {table} WHERE k = ?").into_boxed_str(),
            upsert_value: format!(
                "INSERT INTO {table} (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v"
            )
            .into_boxed_str(),
            insert_presence: format!("INSERT OR IGNORE INTO {table} (k) VALUES (?)")
                .into_boxed_str(),
            delete_key: format!("DELETE FROM {table} WHERE k = ?").into_boxed_str(),
            increment: format!(
                "INSERT INTO {table} (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = v + excluded.v"
            )
            .into_boxed_str(),
            decrement: format!("UPDATE {table} SET v = v + ? WHERE k = ?").into_boxed_str(),
            increment_returning: format!(
                "INSERT INTO {table} (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = v + excluded.v RETURNING v"
            )
            .into_boxed_str(),
            delete_range: format!("DELETE FROM {table} WHERE k >= ? AND k < ?").into_boxed_str(),
            purge_zero: format!("DELETE FROM {table} WHERE v = 0").into_boxed_str(),
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
        &self.iterate
            [((first as usize) << 2) | ((!ascending as usize) << 1) | (values as usize)]
    }
}

impl SqlStatements {
    pub(crate) fn new() -> Self {
        let mut slots = [0u8; SLOTS];
        let mut statements = Vec::with_capacity(Subspace::ALL.len());

        for (index, subspace) in Subspace::ALL.iter().copied().enumerate() {
            slots[subspace.byte() as usize] = index as u8;
            statements.push(SubspaceSql::new(subspace));
        }

        Self { statements, slots }
    }

    #[inline(always)]
    pub(crate) fn get(&self, subspace: Subspace) -> &SubspaceSql {
        &self.statements[self.slots[subspace.byte() as usize] as usize]
    }
}
