/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::base32::STALWART;
use std::{
    fmt::{self, Write},
    io::Cursor,
};
use types::ChangeId;
use utils::codec::leb128::{Leb128Iterator, Leb128Writer};

const MAX_SERIALIZED_LEN: usize = 30;

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
                let mut reader = STALWART.decoder_from_iter(it);
                reader
                    .next_leb128::<ChangeId>()
                    .map(|change_id| (change_id != 0).then_some(change_id).into())
            }
            b'r' => {
                let mut it = STALWART.decoder_from_iter(it);

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
        serializer.collect_str(self)
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

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Cursor::new([0u8; MAX_SERIALIZED_LEN]);

        let prefix = match self {
            State::Initial => 'n',
            State::Exact(id) => {
                bytes.write_leb128(*id).map_err(|_| fmt::Error)?;
                's'
            }
            State::Intermediate(intermediate) => {
                bytes
                    .write_leb128(intermediate.from_id)
                    .map_err(|_| fmt::Error)?;
                bytes
                    .write_leb128(intermediate.to_id - intermediate.from_id)
                    .map_err(|_| fmt::Error)?;
                bytes
                    .write_leb128(intermediate.items_sent)
                    .map_err(|_| fmt::Error)?;
                'r'
            }
        };

        f.write_char(prefix)?;
        let len = bytes.position() as usize;
        write!(
            f,
            "{}",
            STALWART.display(bytes.get_ref().get(..len).unwrap_or_default())
        )
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
            State::new_exact(1),
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

    #[test]
    fn test_state_text() {
        for (state, text) in [
            (State::new_initial(), "n"),
            (State::new_exact(1), "sae"),
            (State::new_exact(12345678), "sz9bpcbi"),
            (State::new_intermediate(1024, 2048, 100), "rqaeiacde"),
        ] {
            assert_eq!(state.to_string(), text);
            assert_eq!(State::parse(text), Some(state));
        }
    }

    #[test]
    fn test_state_zero_change_id_is_initial() {
        assert_eq!(
            State::parse(&State::new_exact(0).to_string()).unwrap(),
            State::Initial
        );
        assert_eq!(State::from(None), State::Initial);
    }
}
