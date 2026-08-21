const TESTSUITE_CAPABILITY: &str = "\"vnd.stalwart.testsuite\"";

pub fn to_sieve(source: &str) -> String {
    let lines: Vec<&str> = source.split('\n').collect();
    let mut out = Vec::with_capacity(lines.len());
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim_start();

        if line.contains(TESTSUITE_CAPABILITY) {
            if let Some(kept) = strip_capability(line) {
                out.push(kept);
            }
            index += 1;
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("test_fail") {
            if starts_argument(rest) {
                let indent = &line[..line.len() - trimmed.len()];
                out.push(format!("{indent}stop;"));
                index = skip_statement(&lines, index);
                continue;
            }
        }

        if trimmed.starts_with("test_") {
            index = skip_statement(&lines, index);
            continue;
        }

        if let Some(rewritten) = open_test_block(line) {
            out.push(rewritten);
            index += 1;
            continue;
        }

        out.push(replace_predicates(line));
        index += 1;
    }

    out.join("\n")
}

fn strip_capability(line: &str) -> Option<String> {
    let cleaned = line.replace(TESTSUITE_CAPABILITY, "");
    let cleaned = cleaned.replace(",,", ",");
    let cleaned = cleaned.replace("[,", "[").replace(",]", "]");
    let has_argument = cleaned
        .split('"')
        .nth(1)
        .is_some_and(|argument| !argument.is_empty());
    has_argument.then_some(cleaned)
}

fn starts_argument(rest: &str) -> bool {
    rest.is_empty()
        || rest
            .chars()
            .next()
            .is_some_and(|ch| ch.is_whitespace() || ch == '"' || ch == ';')
}

fn skip_statement(lines: &[&str], mut index: usize) -> usize {
    if lines[index].contains("text:") {
        index += 1;
        while index < lines.len() && lines[index].trim() != "." {
            index += 1;
        }
        index += 1;
        if index < lines.len() && matches!(lines[index].trim(), ";" | "") {
            index += 1;
        }
        return index;
    }

    while index < lines.len() && !lines[index].trim_end().ends_with(';') {
        index += 1;
    }
    index + 1
}

fn open_test_block(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    let rest = trimmed.strip_prefix("test")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let rest = rest.trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let end = string_end(rest, 0)?;
    let tail = rest[end..].trim_start();
    tail.starts_with('{')
        .then(|| format!("{indent}if true {tail}"))
}

fn string_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

fn replace_predicates(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'"' => match string_end(line, index) {
                Some(end) => {
                    out.push_str(&line[index..end]);
                    index = end;
                }
                None => {
                    out.push_str(&line[index..]);
                    break;
                }
            },
            _ if line[index..].starts_with("test_") && is_boundary(bytes, index) => {
                let end = predicate_end(line, index);
                out.push_str("true");
                index = end;
            }
            _ => {
                let ch = line[index..].chars().next().unwrap();
                out.push(ch);
                index += ch.len_utf8();
            }
        }
    }

    out
}

fn is_boundary(bytes: &[u8], index: usize) -> bool {
    index == 0 || !(bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_')
}

fn predicate_end(line: &str, start: usize) -> usize {
    let bytes = line.as_bytes();
    let mut index = start;
    while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
        index += 1;
    }

    loop {
        let mut next = index;
        while next < bytes.len() && (bytes[next] == b' ' || bytes[next] == b'\t') {
            next += 1;
        }
        if next == index || next >= bytes.len() {
            return index;
        }
        match bytes[next] {
            b':' => {
                next += 1;
                while next < bytes.len() && bytes[next].is_ascii_alphanumeric() {
                    next += 1;
                }
            }
            b'"' => match string_end(line, next) {
                Some(end) => next = end,
                None => return index,
            },
            b'0'..=b'9' => {
                while next < bytes.len() && bytes[next].is_ascii_digit() {
                    next += 1;
                }
            }
            _ => return index,
        }
        index = next;
    }
}
