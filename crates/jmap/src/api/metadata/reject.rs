/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{error::set::SetError, method::set::SetResponse, object::JmapObject};
use std::mem;

pub fn reject_uncommitted<T: JmapObject>(
    response: &mut SetResponse<T>,
    creates: impl IntoIterator<Item = String>,
    description: &'static str,
) {
    let error = || SetError::forbidden().with_description(description);
    for create_id in creates {
        response.not_created.append(create_id, error());
    }
    for (id, _) in mem::take(&mut response.updated) {
        response.not_updated.append(id, error());
    }
    for id in mem::take(&mut response.destroyed) {
        response.not_destroyed.append(id, error());
    }
}
