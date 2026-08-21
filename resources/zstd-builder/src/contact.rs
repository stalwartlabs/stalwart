use std::path::Path;

use calcard::{
    Entry, Parser,
    vcard::{VCard, VCardParameterName, VCardParameterValue, VCardProperty, VCardValue},
};
use common::DavName;
use groupware::contact::ContactCard;

use crate::corpus::{Corpus, Rng, Stats, archive, collect_files, scrub};

const SCRUB_SEED: u64 = 0x5eed_5c2b;

const KEEP: &[&str] = &[
    "http", "https", "mailto", "tel", "data", "urn", "uuid", "www", "com", "net", "org", "true",
    "false", "base64", "image", "png", "jpeg", "gif", "text", "plain", "vcard", "vcf", "charset",
    "utf", "8",
];

pub fn build(dir: &Path, keep_text: bool, stats: &mut Stats) -> std::io::Result<Corpus> {
    let files = collect_files(dir, &["vcf"])?;
    let mut corpus = Corpus::new();
    let mut seed = 0u64;

    for path in files.iter() {
        let Ok(raw) = std::fs::read_to_string(path) else {
            stats.skipped += 1;
            continue;
        };

        let mut parser = Parser::new(&raw).strict();
        let mut found = 0;
        loop {
            match parser.entry() {
                Entry::VCard(real) if !real.entries.is_empty() => {
                    seed += 1;
                    let size = real.to_string().len();
                    if keep_text {
                        corpus.push_both(archive(&contact(&mut Rng::new(seed), real, size)));
                    } else {
                        let mut scrubbed = real.clone();
                        scrub_vcard(&mut Rng::new(seed ^ SCRUB_SEED), &mut scrubbed);
                        corpus.push(
                            archive(&contact(&mut Rng::new(seed), scrubbed, size)),
                            archive(&contact(&mut Rng::new(seed), real, size)),
                        );
                    }
                    stats.read += 1;
                    found += 1;
                }
                Entry::Eof => break,
                _ => {}
            }
        }

        if found == 0 {
            stats.skipped += 1;
        }
    }

    Ok(corpus)
}

fn contact(rng: &mut Rng, card: VCard, size: usize) -> ContactCard {
    let name = card
        .uid()
        .map(|uid| uid.to_string())
        .unwrap_or_else(|| rng.token(36));
    let created = 1_750_000_000 + rng.below(86400 * 365) as i64;

    ContactCard {
        names: vec![DavName {
            name: format!("{name}.vcf"),
            parent_id: rng.below(3) as u32,
        }],
        display_name: None,
        card,
        dead_properties: Default::default(),
        created,
        modified: created + rng.below(86400 * 30) as i64,
        size: size as u32,
    }
}

fn scrub_vcard(rng: &mut Rng, card: &mut VCard) {
    for entry in card.entries.iter_mut() {
        if let Some(group) = entry.group.as_mut() {
            *group = scrub(rng, group, KEEP);
        }

        if !keep_property(&entry.name) {
            for value in entry.values.iter_mut() {
                match value {
                    VCardValue::Text(text) => *text = scrub(rng, text, KEEP),
                    VCardValue::Component(parts) => {
                        for part in parts.iter_mut() {
                            *part = scrub(rng, part, KEEP);
                        }
                    }
                    VCardValue::Binary(data) => {
                        let len = data.data.len();
                        data.data = rng.bytes(len);
                    }
                    _ => {}
                }
            }
        }

        for param in entry.params.iter_mut() {
            if matches!(
                param.name,
                VCardParameterName::Language
                    | VCardParameterName::Value
                    | VCardParameterName::Type
                    | VCardParameterName::Mediatype
                    | VCardParameterName::Calscale
                    | VCardParameterName::Tz
                    | VCardParameterName::Pref
            ) {
                continue;
            }
            if let VCardParameterValue::Text(text) = &mut param.value {
                *text = scrub(rng, text, KEEP);
            }
        }
    }
}

fn keep_property(property: &VCardProperty) -> bool {
    matches!(
        property,
        VCardProperty::Version
            | VCardProperty::Prodid
            | VCardProperty::Kind
            | VCardProperty::Categories
            | VCardProperty::Tz
            | VCardProperty::Lang
            | VCardProperty::Language
    )
}
