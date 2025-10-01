/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use types::ChangeId;
use utils::codec::{
    base32_custom::{Base32Reader, Base32Writer},
    leb128::{Leb128Iterator, Leb128Writer},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JMAPIntermediateState {
    pub from_id: ChangeId,
    pub to_id: ChangeId,
    pub items_sent: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum State {
    #[default]
    Initial,
    Exact(ChangeId),
    Intermediate(JMAPIntermediateState),
}

impl From<ChangeId> for State {
    fn from(change_id: ChangeId) -> Self {
        State::Exact(change_id)
    }
}

impl From<Option<ChangeId>> for State {
    fn from(change_id: Option<ChangeId>) -> Self {
        match change_id {
            Some(change_id) => State::Exact(change_id),
            None => State::Initial,
        }
    }
}

impl State {
    pub fn parse(value: &str) -> Option<Self> {
        let mut it = value.as_bytes().iter();

        match it.next()? {
            b'n' => Some(State::Initial),
            b's' => {
                let mut reader = Base32Reader::from_iter(it);
                reader.next_leb128::<ChangeId>().map(State::Exact)
            }
            b'r' => {
                let mut it = Base32Reader::from_iter(it);

                if let (Some(from_id), Some(to_id), Some(items_sent)) = (
                    it.next_leb128::<ChangeId>(),
                    it.next_leb128::<ChangeId>(),
                    it.next_leb128::<usize>(),
                ) {
                    if items_sent > 0 {
                        Some(State::Intermediate(JMAPIntermediateState {
                            from_id,
                            to_id: from_id.saturating_add(to_id),
                            items_sent,
                        }))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn new_initial() -> Self {
        State::Initial
    }

    pub fn new_exact(id: ChangeId) -> Self {
        State::Exact(id)
    }

    pub fn new_intermediate(from_id: ChangeId, to_id: ChangeId, items_sent: usize) -> Self {
        State::Intermediate(JMAPIntermediateState {
            from_id,
            to_id,
            items_sent,
        })
    }

    pub fn get_change_id(&self) -> ChangeId {
        match self {
            State::Exact(id) => *id,
            State::Intermediate(intermediate) => intermediate.to_id,
            State::Initial => ChangeId::MAX,
        }
    }
}

impl serde::Serialize for State {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for State {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        State::parse(<&str>::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("invalid JMAP State"))
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writer = Base32Writer::with_capacity(10);

        match self {
            State::Initial => {
                writer.push_char('n');
            }
            State::Exact(id) => {
                writer.push_char('s');
                writer.write_leb128(*id).unwrap();
            }
            State::Intermediate(intermediate) => {
                writer.push_char('r');
                writer.write_leb128(intermediate.from_id).unwrap();
                writer
                    .write_leb128(intermediate.to_id - intermediate.from_id)
                    .unwrap();
                writer.write_leb128(intermediate.items_sent).unwrap();
            }
        }

        f.write_str(&writer.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    use types::ChangeId;

    #[test]
    fn test_state_id() {
        for id in [
            State::new_initial(),
            State::new_exact(0),
            State::new_exact(12345678),
            State::new_exact(ChangeId::MAX),
            State::new_intermediate(0, 0, 1),
            State::new_intermediate(1024, 2048, 100),
            State::new_intermediate(12345678, 87654321, 1),
            State::new_intermediate(0, 0, 12345678),
            State::new_intermediate(0, 87654321, 12345678),
            State::new_intermediate(12345678, 87654321, 1),
            State::new_intermediate(12345678, 87654321, 12345678),
            State::new_intermediate(ChangeId::MAX, ChangeId::MAX, ChangeId::MAX as usize),
        ] {
            assert_eq!(State::parse(&id.to_string()).unwrap(), id);
        }
    }
}
