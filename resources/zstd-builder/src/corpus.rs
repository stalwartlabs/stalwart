use std::path::{Path, PathBuf};

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9e3779b97f4a7c15) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.next_u64() % 100 < percent
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    pub fn range(&mut self, from: usize, to: usize) -> usize {
        from + self.below(to.saturating_sub(from) + 1)
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }

    pub fn token(&mut self, len: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        (0..len.max(1))
            .map(|_| ALPHABET[self.below(ALPHABET.len())] as char)
            .collect()
    }

    pub fn domain(&mut self) -> String {
        const TLDS: [&str; 6] = ["com", "net", "org", "io", "de", "co.uk"];
        let len = self.range(4, 11);
        let label = self.token(len);
        let tld = *self.pick(&TLDS);
        format!("{label}.{tld}")
    }

    pub fn address(&mut self) -> String {
        let len = self.range(3, 9);
        let local = self.token(len);
        let domain = self.domain();
        format!("{local}@{domain}")
    }
}

pub fn scrub(rng: &mut Rng, text: &str, keep: &[&str]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();

    let flush = |run: &mut String, out: &mut String, rng: &mut Rng| {
        if run.is_empty() {
            return;
        }
        if keep.iter().any(|token| token.eq_ignore_ascii_case(run)) {
            out.push_str(run);
        } else {
            for ch in run.chars() {
                out.push(replace_char(rng, ch));
            }
        }
        run.clear();
    };

    for ch in text.chars() {
        if ch.is_alphanumeric() {
            run.push(ch);
        } else {
            flush(&mut run, &mut out, rng);
            out.push(ch);
        }
    }
    flush(&mut run, &mut out, rng);
    out
}

pub fn normalize_crlf(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 32);
    let mut previous = 0u8;
    for &byte in input {
        if byte == b'\n' && previous != b'\r' {
            out.push(b'\r');
        }
        out.push(byte);
        previous = byte;
    }
    out
}

fn replace_char(rng: &mut Rng, ch: char) -> char {
    match ch.len_utf8() {
        1 if ch.is_ascii_digit() => (b'0' + (rng.next_u64() % 10) as u8) as char,
        1 if ch.is_ascii_uppercase() => (b'A' + (rng.next_u64() % 26) as u8) as char,
        1 if ch.is_ascii_lowercase() => (b'a' + (rng.next_u64() % 26) as u8) as char,
        1 => ch,
        2 => pick_char(rng, 0x00c0, 0x02af),
        3 => pick_char(rng, 0x4e00, 0x9fff),
        _ => pick_char(rng, 0x1_f300, 0x1_f5ff),
    }
}

fn pick_char(rng: &mut Rng, from: u32, to: u32) -> char {
    let span = to - from + 1;
    char::from_u32(from + (rng.next_u64() % span as u64) as u32).unwrap_or('?')
}

pub fn collect_files(dir: &Path, extensions: &[&str]) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                if !matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some("target") | Some(".git") | Some("node_modules")
                ) {
                    stack.push(path);
                }
            } else if file_type.is_file()
                && (extensions.is_empty()
                    || path
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| {
                            extensions.iter().any(|want| want.eq_ignore_ascii_case(ext))
                        }))
            {
                files.push(path);
            }
        }
    }

    files.sort();
    Ok(files)
}

pub fn archive<T>(value: &T) -> Vec<u8>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                Vec<u8>,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(value, Vec::new())
        .expect("serialize archive")
}

#[derive(Default)]
pub struct Corpus {
    pub scrubbed: Vec<Vec<u8>>,
    pub real: Vec<Vec<u8>>,
    pub train_only: Vec<Vec<u8>>,
}

impl Corpus {
    pub fn new() -> Self {
        Corpus::default()
    }

    pub fn push(&mut self, scrubbed: Vec<u8>, real: Vec<u8>) {
        self.scrubbed.push(scrubbed);
        self.real.push(real);
    }

    pub fn push_both(&mut self, sample: Vec<u8>) {
        self.scrubbed.push(sample.clone());
        self.real.push(sample);
    }

    pub fn push_train_only(&mut self, sample: Vec<u8>) {
        self.train_only.push(sample);
    }

    pub fn len(&self) -> usize {
        self.real.len()
    }

    pub fn is_empty(&self) -> bool {
        self.real.is_empty()
    }
}

pub struct Stats {
    pub read: usize,
    pub skipped: usize,
}

impl Stats {
    pub fn report(&self, kind: &str) {
        println!(
            "{kind:<10}: {} samples, {} inputs skipped as unparseable",
            self.read, self.skipped
        );
    }
}
