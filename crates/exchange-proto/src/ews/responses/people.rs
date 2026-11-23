/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMessage;
use crate::{
    common::{Braces, Guid, HexCase},
    ews::{
        persona::PersonaEntry,
        types::value::{M, T, XBinary},
    },
    xml::XmlWriter,
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FindPeopleBody<'x> {
    pub people: Vec<PersonaEntry<'x>>,
    pub total_number_of_people_in_view: Option<i32>,
    pub first_matching_row_index: Option<i32>,
    pub first_loaded_row_index: Option<i32>,
    pub transaction_id: Option<Guid>,
}

impl ResponseMessage for FindPeopleBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "People");
        for persona in &self.people {
            persona.write(w, "Persona");
        }
        w.end(M, "People");
        for (name, value) in [
            (
                "TotalNumberOfPeopleInView",
                self.total_number_of_people_in_view,
            ),
            ("FirstMatchingRowIndex", self.first_matching_row_index),
            ("FirstLoadedRowIndex", self.first_loaded_row_index),
        ] {
            if let Some(value) = value {
                w.leaf_i64(M, name, i64::from(value));
            }
        }
        if let Some(id) = &self.transaction_id {
            w.start(M, "TransactionId").close_start();
            id.write_text(w.buffer(), HexCase::Lower, Braces::None);
            w.end(M, "TransactionId");
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetPersonaBody<'x> {
    pub persona: PersonaEntry<'x>,
}

impl ResponseMessage for GetPersonaBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "Persona");
        self.persona.write_children(w);
        w.end(M, "Persona");
    }

    fn write_required(w: &mut XmlWriter<'_>) {
        w.start(M, "Persona");
        w.start(T, "PersonaId").attr("Id", "");
        w.end(T, "PersonaId");
        w.end(M, "Persona");
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserPhotoBody<'x> {
    pub has_changed: bool,
    pub picture_data: Option<XBinary<'x>>,
}

impl ResponseMessage for GetUserPhotoBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.leaf_bool(M, "HasChanged", self.has_changed);
        if let Some(data) = &self.picture_data {
            w.start(M, "PictureData");
            w.close_start();
            data.write_content(w);
            w.end(M, "PictureData");
        }
    }

    fn write_required(w: &mut XmlWriter<'_>) {
        w.leaf_bool(M, "HasChanged", false);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AddEntityFeedbackBody {
    pub error_count: i32,
}

impl ResponseMessage for AddEntityFeedbackBody {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.leaf_i64(M, "ErrorCount", i64::from(self.error_count));
        w.start(M, "ErrorDetails");
        w.end(M, "ErrorDetails");
    }
}
