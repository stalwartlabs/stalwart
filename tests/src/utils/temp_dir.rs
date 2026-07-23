/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub struct TempDir {
    pub path: std::path::PathBuf,
    pub delete: bool,
}

impl TempDir {
    pub fn new(name: &str, delete_if_exists: bool) -> Self {
        let mut path = std::env::temp_dir();
        path.push(name);
        if delete_if_exists && path.exists() {
            std::fs::remove_dir_all(&path).unwrap();
        }
        std::fs::create_dir_all(&path).unwrap();
        Self {
            path,
            delete: delete_if_exists,
        }
    }

    pub fn delete(&self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if self.delete {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
