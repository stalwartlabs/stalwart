/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Document,
    table::{Slot, Table},
};
use crate::pdf::{
    object::{Dict, ObjRef},
    repair::{Kind, Scan},
    xref::{Builder, Entries, Entry, NO_SLOT, read_stream_section},
};
use std::{borrow::Cow, cmp::Reverse};

const CANDIDATES_PER_OBJECT: usize = 2;

pub(crate) struct Recovered<'a> {
    pub(super) table: Table<'a>,
    pub(super) trailers: Vec<Dict<'a>>,
    pub(super) catalogs: Vec<ObjRef>,
    pub(super) page_trees: Vec<ObjRef>,
    pub(super) pages: Vec<ObjRef>,
}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    num: u32,
    position: u32,
    entry: Entry,
}

#[derive(Debug, Clone, Copy)]
struct Located {
    id: ObjRef,
    position: u32,
    order: u32,
    kind: Kind,
    entry: Entry,
}

struct Container {
    num: u32,
    position: u32,
    slot: u32,
}

impl<'a> Document<'a> {
    pub(super) fn repair(&self) -> bool {
        if self.repaired.get().is_some() || self.repairing.get() {
            return false;
        }
        self.repairing.set(true);
        let recovered = self.recover();
        self.repairing.set(false);
        self.repaired.set(recovered).is_ok()
    }

    fn recover(&self) -> Recovered<'a> {
        let data = self.source.data;
        let scan = Scan::run(&self.source);
        let dense_cap = Builder::dense_cap(data.len(), self.max_objects);
        let limit = dense_cap.saturating_mul(CANDIDATES_PER_OBJECT);
        let mut candidates: Vec<Candidate> = scan
            .objects
            .iter()
            .take(limit)
            .map(|found| Candidate {
                num: found.id.num,
                position: found.offset,
                entry: Entry::Offset {
                    offset: found.offset,
                    generation: found.id.generation,
                    slot: NO_SLOT,
                },
            })
            .collect();
        let mut trailers: Vec<(u32, Dict<'a>)> = scan
            .trailers
            .iter()
            .filter_map(|trailer| Some((trailer.offset, trailer.dict(data)?)))
            .collect();
        let mut harvested_candidates = Vec::new();
        let mut harvested = Entries::default();
        for found in scan.objects.iter().filter(|found| found.kind == Kind::XRef) {
            if self.source.scan_exhausted() {
                break;
            }
            let mut builder = Builder::sparse(&mut harvested, limit);
            let dict = read_stream_section(&self.source, found.offset as usize, &mut builder, 0);
            builder.finish();
            let Some(dict) = dict else {
                continue;
            };
            trailers.push((found.offset, dict));
            let room = limit.saturating_sub(harvested_candidates.len());
            harvested_candidates.extend(
                harvested
                    .iter()
                    .filter(|(_, entry)| matches!(entry, Entry::Compressed { .. }))
                    .take(room)
                    .map(|(num, entry)| Candidate {
                        num,
                        position: found.offset,
                        entry,
                    }),
            );
        }
        trailers.sort_by_key(|&(offset, _)| Reverse(offset));
        let trailers: Vec<Dict<'a>> = trailers.into_iter().map(|(_, dict)| dict).collect();

        let mut direct = winners(&mut candidates, dense_cap);
        if self.crypt.get().is_none() {
            let lookup = Table::new(Cow::Borrowed(&direct), Vec::new(), 0, 0);
            let _ = self.setup_crypt(&lookup, &trailers);
        }
        let mut located: Vec<Located> = scan
            .objects
            .iter()
            .filter(|found| !matches!(found.kind, Kind::Plain | Kind::XRef))
            .map(|found| Located {
                id: found.id,
                position: found.offset,
                order: 0,
                kind: found.kind,
                entry: Entry::Offset {
                    offset: found.offset,
                    generation: found.id.generation,
                    slot: NO_SLOT,
                },
            })
            .filter(|found| direct.get(found.id.num) == found.entry)
            .collect();
        let containers: Vec<Container> = located
            .iter()
            .filter(|found| found.kind == Kind::ObjStm)
            .zip(0u32..)
            .map(|(found, slot)| Container {
                num: found.id.num,
                position: found.position,
                slot,
            })
            .collect();
        let mut container_numbers: Vec<u32> =
            containers.iter().map(|container| container.num).collect();
        container_numbers.sort_unstable();
        let room = limit.saturating_sub(candidates.len());
        candidates.extend(
            harvested_candidates
                .into_iter()
                .filter(|candidate| match candidate.entry {
                    Entry::Compressed { stream, .. } => {
                        container_numbers.binary_search(&stream).is_ok()
                    }
                    _ => false,
                })
                .take(room),
        );
        candidates.sort_by_key(|candidate| (candidate.num, candidate.position));
        for container in &containers {
            if let Some(Entry::Offset { slot, .. }) = direct.get_mut(container.num) {
                *slot = container.slot;
            }
            if let Ok(index) = candidates
                .binary_search_by_key(&(container.num, container.position), |candidate| {
                    (candidate.num, candidate.position)
                })
                && let Some(Candidate {
                    entry: Entry::Offset { slot, .. },
                    ..
                }) = candidates.get_mut(index)
            {
                *slot = container.slot;
            }
        }
        let table = Table::new(Cow::Owned(direct), Slot::many(containers.len()), 0, 0);
        for container in &containers {
            let Some(cell) = table.slot(container.slot) else {
                continue;
            };
            let loaded = self.load_objstm(&table, container.position, container.num);
            let Some(objstm) = cell.cell.get_or_init(|| loaded) else {
                continue;
            };
            for (member, index) in objstm.members() {
                if self.source.scan_exhausted() {
                    break;
                }
                let entry = Entry::Compressed {
                    stream: container.num,
                    index,
                };
                if candidates.len() < limit {
                    candidates.push(Candidate {
                        num: member,
                        position: container.position,
                        entry,
                    });
                }
                let kind = objstm
                    .object(index, member)
                    .filter(|&(_, consumed)| self.source.charge_scan(consumed))
                    .and_then(|(object, _)| object.as_dict())
                    .map_or(Kind::Plain, Kind::of);
                if matches!(kind, Kind::Catalog | Kind::PageTree | Kind::Page)
                    && let Some(id) = ObjRef::new(i64::from(member), 0)
                {
                    located.push(Located {
                        id,
                        position: container.position,
                        order: index.saturating_add(1),
                        kind,
                        entry,
                    });
                }
            }
        }
        let entries = winners(&mut candidates, dense_cap);
        located.retain(|found| entries.get(found.id.num) == found.entry);
        located.sort_by_key(|found| (found.position, found.order));
        let by_kind = |kind: Kind| -> Vec<ObjRef> {
            located
                .iter()
                .filter(|found| found.kind == kind)
                .map(|found| found.id)
                .collect()
        };
        let mut catalogs = by_kind(Kind::Catalog);
        catalogs.reverse();
        let mut page_trees = by_kind(Kind::PageTree);
        page_trees.reverse();
        let pages = by_kind(Kind::Page);
        let Table { slots, .. } = table;
        Recovered {
            table: Table::new(Cow::Owned(entries), slots, 0, 0),
            trailers,
            catalogs,
            page_trees,
            pages,
        }
    }
}

fn winners(candidates: &mut [Candidate], dense_cap: usize) -> Entries {
    candidates.sort_by_key(|candidate| (candidate.num, candidate.position));
    let mut entries = Entries::default();
    for group in candidates.chunk_by(|left, right| left.num == right.num) {
        if let Some(last) = group.last() {
            entries.put_sorted(last.num, last.entry, dense_cap);
        }
    }
    entries
}
