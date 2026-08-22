use email::sieve::{SieveScript, VacationResponse};
use jmap_proto::types::date::UTCDate;
use mail_builder::MessageBuilder;
use mail_parser::decoders::html::html_to_text;
use sieve::Compiler;
use std::borrow::Cow;
use types::blob_hash::BlobHash;

use crate::corpus::{Corpus, Rng, Stats, archive};

const SAMPLES: usize = 16;

const SUBJECTS: [&str; 6] = [
    "Out of the office",
    "Away from my desk",
    "On vacation",
    "Currently unavailable",
    "Auto: Out of office reply",
    "I am on holiday until the end of the month",
];

const BODIES: [&str; 5] = [
    "I am currently out of the office and will reply to your message when I return.",
    "Thank you for your email. I am away until further notice and will get back to you as soon as possible.",
    "I am on vacation with limited access to email. For urgent matters please contact my colleagues.",
    "Hello,\r\n\r\nI am away from the office and will respond to your message upon my return.\r\n\r\nBest regards",
    "I am away.",
];

pub fn build(compiler: &Compiler, corpus: &mut Corpus, stats: &mut Stats) {
    for index in 0..SAMPLES {
        let mut rng = Rng::new(0x5ac0 + index as u64);
        let mut object = SieveScript {
            name: "vacation".into(),
            blob_hash: BlobHash::default(),
            size: 0,
            vacation_response: Some(auto_reply(&mut rng)),
            script: Vec::new(),
        };

        let source = build_script(&object);
        let script = match compiler.compile(&source) {
            Ok(script) => script,
            Err(err) => {
                eprintln!("skipped vacation response: {err}");
                stats.skipped += 1;
                continue;
            }
        };
        let Ok(script) = script.to_bytes() else {
            stats.skipped += 1;
            continue;
        };

        object.blob_hash = BlobHash::generate(&source);
        object.size = source.len() as u32;
        object.script = script;

        corpus.push_both(archive(&object));
        stats.read += 1;
    }
}

fn auto_reply(rng: &mut Rng) -> VacationResponse {
    let from_date = rng
        .chance(75)
        .then(|| 1_750_000_000 + rng.below(86400 * 365) as u64);
    let text_body = rng.pick(&BODIES).to_string();

    VacationResponse {
        from_date,
        to_date: from_date.map(|from_date| from_date + rng.range(86400, 86400 * 21) as u64),
        subject: rng.chance(80).then(|| rng.pick(&SUBJECTS).to_string()),
        html_body: rng.chance(40).then(|| {
            format!(
                "<html><head></head><body><div dir=\"ltr\"><p>{}</p></div></body></html>",
                text_body.replace("\r\n", "<br>")
            )
        }),
        text_body: rng.chance(85).then_some(text_body),
    }
}

// Kept byte identical to Server::build_script in crates/jmap/src/vacation/set.rs
fn build_script(obj: &SieveScript) -> Vec<u8> {
    let mut script = Vec::with_capacity(1024);
    script.extend_from_slice(b"require [\"vacation\", \"relational\", \"date\"];\r\n\r\n");
    let mut num_blocks = 0;

    if let Some(value) = obj.vacation_response.as_ref().and_then(|v| v.from_date) {
        script.extend_from_slice(b"if currentdate :value \"ge\" \"iso8601\" \"");
        script.extend_from_slice(UTCDate::from(value).to_string().as_bytes());
        script.extend_from_slice(b"\" {\r\n");
        num_blocks += 1;
    }

    if let Some(value) = obj.vacation_response.as_ref().and_then(|v| v.to_date) {
        script.extend_from_slice(b"if currentdate :value \"le\" \"iso8601\" \"");
        script.extend_from_slice(UTCDate::from(value).to_string().as_bytes());
        script.extend_from_slice(b"\" {\r\n");
        num_blocks += 1;
    }

    script.extend_from_slice(b"vacation :mime ");
    if let Some(value) = obj
        .vacation_response
        .as_ref()
        .and_then(|v| v.subject.as_ref())
    {
        script.extend_from_slice(b":subject \"");
        for &ch in value.as_bytes().iter() {
            match ch {
                b'\\' | b'\"' => {
                    script.push(b'\\');
                }
                b'\r' | b'\n' => {
                    continue;
                }
                _ => (),
            }
            script.push(ch);
        }
        script.extend_from_slice(b"\" ");
    }

    let mut text_body = if let Some(value) = obj
        .vacation_response
        .as_ref()
        .and_then(|v| v.text_body.as_ref())
    {
        Cow::from(value.as_str()).into()
    } else {
        None
    };
    let html_body = if let Some(value) = obj
        .vacation_response
        .as_ref()
        .and_then(|v| v.html_body.as_ref())
    {
        Cow::from(value.as_str()).into()
    } else {
        None
    };
    match (&html_body, &text_body) {
        (Some(html_body), None) => {
            text_body = Cow::from(html_to_text(html_body.as_ref())).into();
        }
        (None, None) => {
            text_body = Cow::from("I am away.").into();
        }
        _ => (),
    }

    let mut builder = MessageBuilder::new();
    let mut body_len = 0;
    if let Some(html_body) = html_body {
        body_len = html_body.len();
        builder = builder.html_body(html_body);
    }
    if let Some(text_body) = text_body {
        body_len += text_body.len();
        builder = builder.text_body(text_body);
    }
    let mut message_body = Vec::with_capacity(body_len + 128);
    builder.write_body(&mut message_body).ok();

    script.push(b'\"');
    for ch in message_body {
        if b"\\\"".contains(&ch) {
            script.push(b'\\');
        }
        script.push(ch);
    }
    script.extend_from_slice(b"\";\r\n");

    for _ in 0..num_blocks {
        script.extend_from_slice(b"}\r\n");
    }

    script
}
