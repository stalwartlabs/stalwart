use serde_json::Value;
use sieve::Sieve;

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

pub fn sanitize(script: &Sieve, rng: &mut Rng) -> Option<Sieve> {
    let mut value = serde_json::to_value(script).ok()?;
    let mut replaced = false;

    for constant in value.get_mut("constants")?.as_array_mut()? {
        let text = constant.as_str()?;
        if is_realistic(text) {
            continue;
        }
        *constant = Value::String(replacement(rng));
        replaced = true;
    }

    if !replaced {
        return Some(script.clone());
    }

    let sanitized: Sieve = serde_json::from_value(value).ok()?;
    (sanitized.constant_count() == script.constant_count()
        && sanitized.instruction_count() == script.instruction_count())
    .then_some(sanitized)
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
