/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    html::HtmlText,
    output::{Output, Separator},
    package::{Arena, Package, Span},
    xml::{Handler, Tag},
};
use memchr::memrchr;

pub(crate) const CONTAINER: &[u8] = b"META-INF/container.xml";

#[derive(Debug, Clone, Copy)]
struct Item {
    id: Span,
    href: Span,
}

#[derive(Default)]
pub(crate) struct Scratch {
    arena: Arena,
    manifest: Vec<Item>,
    spine: Vec<Span>,
    chapter: HtmlText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Element {
    Rootfile,
    Item,
    ItemRef,
}

impl Element {
    fn parse(local: &[u8]) -> Option<Element> {
        hashify::map!(local, Element,
            b"rootfile" => Element::Rootfile,
            b"item" => Element::Item,
            b"itemref" => Element::ItemRef,
        )
        .copied()
    }
}

fn is_html_media_type(media_type: &[u8]) -> bool {
    hashify::set_ignore_case!(
        media_type.trim_ascii(),
        b"application/xhtml+xml",
        b"text/html",
        b"application/html",
        b"text/x-oeb1-document",
    )
}

fn has_html_extension(name: &[u8]) -> bool {
    memrchr(b'.', name)
        .and_then(|dot| name.get(dot + 1..))
        .is_some_and(|extension| {
            hashify::set_ignore_case!(extension, b"xhtml", b"html", b"htm", b"xht")
        })
}

struct ContainerHandler<'x> {
    arena: &'x mut Arena,
    rootfile: Option<Span>,
}

impl Handler for ContainerHandler<'_> {
    fn start(&mut self, tag: &Tag<'_>, _out: &mut Output<'_>) {
        if self.rootfile.is_some() || Element::parse(tag.local()) != Some(Element::Rootfile) {
            return;
        }
        let mut path = None;
        let mut is_package = true;
        for (name, value) in tag.attributes() {
            hashify::fnc_map!(name,
                b"full-path" => { path = Some(value); },
                b"media-type" => {
                    is_package = hashify::set_ignore_case!(value, b"application/oebps-package+xml");
                },
                _ => {}
            );
        }
        if is_package {
            self.rootfile = path.and_then(|path| self.arena.push_decoded(path));
        }
    }

    fn end(&mut self, _name: &[u8], _out: &mut Output<'_>) {}

    fn text(&mut self, _text: &[u8], _out: &mut Output<'_>) {}
}

struct PackageHandler<'x> {
    arena: &'x mut Arena,
    manifest: &'x mut Vec<Item>,
    spine: &'x mut Vec<Span>,
    source: Span,
    limit: usize,
}

impl Handler for PackageHandler<'_> {
    fn start(&mut self, tag: &Tag<'_>, _out: &mut Output<'_>) {
        match Element::parse(tag.local()) {
            Some(Element::Item) if self.manifest.len() < self.limit => {
                let (mut id, mut href, mut html) = (None, None, None);
                for (name, value) in tag.attributes() {
                    hashify::fnc_map!(name,
                        b"id" => { id = Some(value); },
                        b"href" => { href = Some(value); },
                        b"media-type" => { html = Some(is_html_media_type(value)); },
                        _ => {}
                    );
                }
                let (Some(id), Some(href)) = (id, href) else {
                    return;
                };
                if !html.unwrap_or_else(|| has_html_extension(href)) {
                    return;
                }
                let mark = self.arena.mark();
                match (
                    self.arena.push_decoded(id),
                    self.arena.push_resolved(self.source, href),
                ) {
                    (Some(id), Some(href)) => self.manifest.push(Item { id, href }),
                    _ => self.arena.rewind(mark),
                }
            }
            Some(Element::ItemRef) if self.spine.len() < self.limit => {
                if let Some(id) = tag
                    .attributes()
                    .find_map(|(name, value)| hashify::set!(name, b"idref").then_some(value))
                    .and_then(|id| self.arena.push_decoded(id))
                {
                    self.spine.push(id);
                }
            }
            _ => {}
        }
    }

    fn end(&mut self, _name: &[u8], _out: &mut Output<'_>) {}

    fn text(&mut self, _text: &[u8], _out: &mut Output<'_>) {}
}

pub(crate) fn extract(package: &mut Package<'_, '_>, scratch: &mut Scratch, out: &mut Output<'_>) {
    let Scratch {
        arena,
        manifest,
        spine,
        chapter,
    } = scratch;
    arena.clear();
    manifest.clear();
    spine.clear();
    let limit = package.budget.parts;

    let mut container = ContainerHandler {
        arena,
        rootfile: None,
    };
    package.scan(CONTAINER, &mut container, out);
    if let Some(rootfile) = container.rootfile {
        let mut handler = PackageHandler {
            arena,
            manifest,
            spine,
            source: rootfile,
            limit,
        };
        if let Some(member) = package.archive.find(handler.arena.get(rootfile))
            && let Some(data) = package.archive.read(&member, package.claimed)
        {
            package
                .buffers
                .scan(data, &mut package.budget, &mut handler, out);
        }
    }

    manifest.sort_unstable_by(|left, right| arena.get(left.id).cmp(arena.get(right.id)));
    let mut chapters = 0usize;
    for &idref in spine.iter() {
        if package.stopped(out) {
            return;
        }
        let id = arena.get(idref);
        let index = manifest.partition_point(|item| arena.get(item.id) < id);
        let Some(item) = manifest.get(index).filter(|item| arena.get(item.id) == id) else {
            continue;
        };
        chapter.reset();
        if package.scan(arena.get(item.href), chapter, out) {
            chapters += 1;
            out.separator(Separator::Newline);
        }
    }
    if chapters > 0 {
        return;
    }
    let archive = package.archive;
    for member in archive
        .members()
        .filter(|member| member.is_readable() && has_html_extension(member.name))
    {
        if package.stopped(out) {
            return;
        }
        chapter.reset();
        if package.scan_member(&member, chapter, out) {
            out.separator(Separator::Newline);
        }
    }
}
