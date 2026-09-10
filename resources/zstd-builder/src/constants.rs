use crate::corpus::Rng;

const MAX_KEPT_LEN: usize = 64;

const SUBJECTS: [&str; 8] = [
    "Re: Quarterly report",
    "Meeting notes",
    "Your invoice is ready",
    "Weekly newsletter",
    "Fwd: Travel itinerary",
    "Payment confirmation",
    "Re: Support ticket #4821",
    "Reminder: subscription renewal",
];

const SENTENCES: [&str; 6] = [
    "Please let me know if you have any questions.",
    "Thanks for getting back to me so quickly.",
    "This message was automatically generated, please do not reply.",
    "You are receiving this message because you subscribed to our newsletter.",
    "Your message could not be delivered to one or more recipients.",
    "I no longer read this mailbox, please write to the address below.",
];

const MAILBOXES: [&str; 8] = [
    "INBOX",
    "Archive",
    "Newsletters",
    "Receipts",
    "Lists/announce",
    "Projects/Internal",
    "INBOX/Automated",
    "Junk Mail",
];

pub fn sanitize(source: &[u8], rng: &mut Rng) -> Option<Vec<u8>> {
    let source = std::str::from_utf8(source).ok()?;
    let mut out = String::with_capacity(source.len());
    let mut replaced = false;
    let mut rest = source;

    while let Some(token) = next_token(rest) {
        out.push_str(&rest[..token.start]);
        match token.kind {
            Token::Comment => out.push_str(&rest[token.start..token.end]),
            Token::Quoted(literal) => {
                if is_realistic(&literal) {
                    out.push_str(&rest[token.start..token.end]);
                } else {
                    out.push('"');
                    for ch in replacement(rng).chars() {
                        if ch == '"' || ch == '\\' {
                            out.push('\\');
                        }
                        out.push(ch);
                    }
                    out.push('"');
                    replaced = true;
                }
            }
            Token::MultiLine(body) => {
                if is_realistic(&body) {
                    out.push_str(&rest[token.start..token.end]);
                } else {
                    out.push_str("text:\r\n");
                    out.push_str(&replacement(rng));
                    out.push_str("\r\n.\r\n");
                    replaced = true;
                }
            }
        }
        rest = &rest[token.end..];
    }

    if replaced {
        out.push_str(rest);
        Some(out.into_bytes())
    } else {
        None
    }
}

enum Token {
    Comment,
    Quoted(String),
    MultiLine(String),
}

struct Located {
    kind: Token,
    start: usize,
    end: usize,
}

fn next_token(source: &str) -> Option<Located> {
    let bytes = source.as_bytes();
    let mut at = 0;

    while at < bytes.len() {
        let start = at;
        match bytes[at] {
            b'#' => {
                let end = source[at..]
                    .find('\n')
                    .map_or(source.len(), |offset| at + offset);
                return Located::at(Token::Comment, start, end).into();
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                let end = source[at + 2..]
                    .find("*/")
                    .map_or(source.len(), |offset| at + 2 + offset + 2);
                return Located::at(Token::Comment, start, end).into();
            }
            b'"' => {
                let (literal, end) = read_quoted(source, at);
                return Located::at(Token::Quoted(literal), start, end).into();
            }
            _ => {
                if let Some((body, end)) = read_multiline(source, at) {
                    return Located::at(Token::MultiLine(body), start, end).into();
                }
                at += 1;
            }
        }
    }

    None
}

fn read_quoted(source: &str, at: usize) -> (String, usize) {
    let bytes = source.as_bytes();
    let mut literal = String::new();
    let mut cursor = at + 1;

    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' if cursor + 1 < bytes.len() => {
                literal.push_str(&source[cursor + 1..cursor + 2]);
                cursor += 2;
            }
            b'"' => return (literal, cursor + 1),
            _ => {
                let width = source[cursor..].chars().next().map_or(1, char::len_utf8);
                literal.push_str(&source[cursor..cursor + width]);
                cursor += width;
            }
        }
    }

    (literal, source.len())
}

fn read_multiline(source: &str, at: usize) -> Option<(String, usize)> {
    const MARKER: &str = "text:";

    if !source[at..]
        .get(..MARKER.len())?
        .eq_ignore_ascii_case(MARKER)
        || source[..at]
            .chars()
            .next_back()
            .is_some_and(|ch| ch.is_alphanumeric() || ch == '_')
    {
        return None;
    }

    let opening = at + MARKER.len() + source[at + MARKER.len()..].find('\n')?;
    let mut body = String::new();
    let mut cursor = opening + 1;

    for line in source[cursor..].split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        cursor += line.len();
        if content == "." {
            return Some((body, cursor));
        }
        body.push_str(content.strip_prefix("..").unwrap_or(content));
        body.push_str("\r\n");
    }

    None
}

impl Located {
    fn at(kind: Token, start: usize, end: usize) -> Self {
        Located { kind, start, end }
    }
}

fn is_realistic(constant: &str) -> bool {
    if constant.len() > MAX_KEPT_LEN
        || !constant.is_ascii()
        || constant.contains(['\r', '\n'])
        || constant.chars().any(|ch| ch.is_ascii_control())
    {
        return false;
    }

    let mut chars = constant.chars();
    let Some(first) = chars.next() else {
        return true;
    };

    !chars.all(|ch| ch == first) || constant.len() < 3
}

fn replacement(rng: &mut Rng) -> String {
    match rng.below(4) {
        0 => rng.pick(&MAILBOXES).to_string(),
        1 => rng.pick(&SUBJECTS).to_string(),
        2 => rng.address(),
        _ => rng.pick(&SENTENCES).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sanitized(source: &str) -> Option<String> {
        sanitize(source.as_bytes(), &mut Rng::new(1))
            .map(|output| String::from_utf8(output).expect("utf-8 output"))
    }

    #[test]
    fn keeps_realistic_scripts_untouched() {
        assert_eq!(
            sanitized("require [\"fileinto\"];\r\nfileinto \"INBOX/Lists\";\r\n"),
            None
        );
    }

    #[test]
    fn replaces_junk_literals() {
        let output = sanitized("fileinto \"aaaaaaaaaaaaaaaa\";\r\n").expect("replaced");
        assert!(output.starts_with("fileinto \""), "{output}");
        assert!(output.ends_with("\";\r\n"), "{output}");
        assert!(!output.contains("aaaa"), "{output}");
    }

    #[test]
    fn ignores_quotes_inside_comments() {
        assert_eq!(sanitized("# \"aaaaaaaaaaaa\"\r\nstop;\r\n"), None);
        assert_eq!(sanitized("/* \"aaaaaaaaaaaa\" */\r\nstop;\r\n"), None);
    }

    #[test]
    fn keeps_escaped_quotes_in_place() {
        assert_eq!(sanitized("set \"a\" \"say \\\"hello\\\"\";\r\n"), None);
    }

    #[test]
    fn replaces_junk_multiline_blocks() {
        let output = sanitized(
            "notify text:\r\nxxxxxxxxxxxxxxxxxxxx\r\nxxxxxxxxxxxxxxxxxxxx\r\n.\r\nstop;\r\n",
        )
        .expect("replaced");
        assert!(output.starts_with("notify text:\r\n"), "{output}");
        assert!(output.ends_with(".\r\nstop;\r\n"), "{output}");
        assert!(!output.contains("xxxx"), "{output}");
    }
}
