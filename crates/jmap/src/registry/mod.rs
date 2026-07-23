/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use registry::schema::prelude::ObjectType;

pub mod get;
pub mod mapping;
pub mod query;
pub mod set;

pub trait EnterpriseRegistry {
    fn assert_enterprise_object(&self, object_type: ObjectType) -> trc::Result<()>;
}

impl EnterpriseRegistry for Server {
    fn assert_enterprise_object(&self, object_type: ObjectType) -> trc::Result<()> {
        if !matches!(
            object_type,
            ObjectType::MaskedEmail
                | ObjectType::ArchivedItem
                | ObjectType::Metric
                | ObjectType::Trace
        ) {
            return Ok(());
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if self.is_enterprise_edition() {
            return Ok(());
        }
        // SPDX-SnippetEnd

        Err(trc::JmapEvent::Forbidden.into_err().details(concat!(
            "This feature is only available in the Enterprise edition. ",
            "Obtain your trial license at https://license.stalw.art/trial."
        )))
    }
}
