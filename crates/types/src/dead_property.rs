/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "test_mode", serde(tag = "type", content = "data"))]
#[rkyv(derive(Debug))]
pub enum DeadPropertyTag {
    ElementStart(DeadElementTag),
    ElementEnd,
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
#[rkyv(derive(Debug))]
pub struct DeadElementTag {
    pub name: String,
    pub attrs: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "test_mode", serde(transparent))]
#[rkyv(derive(Debug))]
#[repr(transparent)]
pub struct DeadProperty(pub Vec<DeadPropertyTag>);

impl From<&ArchivedDeadProperty> for DeadProperty {
    fn from(value: &ArchivedDeadProperty) -> Self {
        DeadProperty(value.0.iter().map(|tag| tag.into()).collect::<Vec<_>>())
    }
}

impl From<&ArchivedDeadPropertyTag> for DeadPropertyTag {
    fn from(tag: &ArchivedDeadPropertyTag) -> Self {
        match tag {
            ArchivedDeadPropertyTag::ElementStart(tag) => DeadPropertyTag::ElementStart(tag.into()),
            ArchivedDeadPropertyTag::ElementEnd => DeadPropertyTag::ElementEnd,
            ArchivedDeadPropertyTag::Text(tag) => DeadPropertyTag::Text(tag.to_string()),
        }
    }
}

impl From<&ArchivedDeadElementTag> for DeadElementTag {
    fn from(tag: &ArchivedDeadElementTag) -> Self {
        DeadElementTag {
            name: tag.name.to_string(),
            attrs: tag.attrs.as_ref().map(|s| s.to_string()),
        }
    }
}

impl ArchivedDeadProperty {
    pub fn find_tag(&self, needle: &str) -> Option<DeadProperty> {
        let mut depth: u32 = 0;
        let mut tags = Vec::new();
        let mut found_tag = false;

        for tag in self.0.iter() {
            match tag {
                ArchivedDeadPropertyTag::ElementStart(start) => {
                    if depth == 0 && start.name == needle {
                        found_tag = true;
                    } else if found_tag {
                        tags.push(tag.into());
                    }

                    depth += 1;
                }
                ArchivedDeadPropertyTag::ElementEnd => {
                    if found_tag {
                        if depth == 1 {
                            break;
                        } else {
                            tags.push(tag.into());
                        }
                    }
                    depth = depth.saturating_sub(1);
                }
                ArchivedDeadPropertyTag::Text(_) => {
                    if found_tag {
                        tags.push(tag.into());
                    }
                }
            }
        }

        if found_tag {
            Some(DeadProperty(tags))
        } else {
            None
        }
    }
}

impl DeadProperty {
    pub fn remove_element(&mut self, element: &DeadElementTag) {
        let mut depth = 0;
        let mut remove = false;
        self.0.retain(|item| match item {
            DeadPropertyTag::ElementStart(tag) => {
                if depth == 0 && !remove && tag.name == element.name {
                    remove = true;
                }
                depth += 1;

                !remove
            }
            DeadPropertyTag::ElementEnd => {
                depth -= 1;
                if remove && depth == 0 {
                    remove = false;
                    false
                } else {
                    !remove
                }
            }
            _ => !remove,
        });
    }

    pub fn add_element(&mut self, element: DeadElementTag, values: Vec<DeadPropertyTag>) {
        self.0.push(DeadPropertyTag::ElementStart(element));
        self.0.extend(values);
        self.0.push(DeadPropertyTag::ElementEnd);
    }

    pub fn size(&self) -> usize {
        let mut size = 0;
        for item in &self.0 {
            match item {
                DeadPropertyTag::ElementStart(tag) => {
                    size += tag.size();
                }
                DeadPropertyTag::ElementEnd => {
                    size += 1;
                }
                DeadPropertyTag::Text(text) => {
                    size += text.len();
                }
            }
        }
        size
    }
}

impl ArchivedDeadProperty {
    pub fn size(&self) -> usize {
        let mut size = 0;
        for item in self.0.iter() {
            match item {
                ArchivedDeadPropertyTag::ElementStart(tag) => {
                    size += tag.size();
                }
                ArchivedDeadPropertyTag::ElementEnd => {
                    size += 1;
                }
                ArchivedDeadPropertyTag::Text(text) => {
                    size += text.len();
                }
            }
        }
        size
    }
}

impl DeadElementTag {
    pub fn new(name: String, attrs: Option<String>) -> Self {
        DeadElementTag { name, attrs }
    }

    pub fn size(&self) -> usize {
        self.name.len() + self.attrs.as_ref().map_or(0, |attrs| attrs.len())
    }
}

impl ArchivedDeadElementTag {
    pub fn size(&self) -> usize {
        self.name.len() + self.attrs.as_ref().map_or(0, |attrs| attrs.len())
    }
}

impl Default for DeadProperty {
    fn default() -> Self {
        DeadProperty(Vec::with_capacity(4))
    }
}
