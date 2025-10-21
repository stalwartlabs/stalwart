/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use calcard::{
    common::{IanaString, PartialDateTime},
    icalendar::{ICalendar, ICalendarProperty, ICalendarValue},
};
use groupware::scheduling::{
    ItipMessage, ItipSummary,
    event_cancel::itip_cancel,
    event_create::itip_create,
    event_update::itip_update,
    inbound::{MergeResult, itip_import_message, itip_merge_changes, itip_process_message},
    snapshot::itip_snapshot,
};
use std::{collections::hash_map::Entry, path::PathBuf};

struct Test {
    test_name: String,
    command: Command,
    line_num: usize,
    parameters: Vec<String>,
    payload: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Put,
    Get,
    Delete(bool),
    Expect,
    Send,
    Reset,
    Itip,
}

pub fn test() {
    for entry in std::fs::read_dir(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("itip"),
    )
    .unwrap()
    {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "txt") {
            continue;
        }
        let file_name = path.file_name().unwrap().to_str().unwrap();
        let rules = std::fs::read_to_string(&path).unwrap();
        let mut last_comment = "";
        let mut last_command = "";
        let mut last_line_num = 0;
        let mut payload = String::new();
        let mut commands = Vec::new();

        for (line_num, line) in rules.lines().enumerate() {
            if line.starts_with('#') {
                last_comment = line.trim_start_matches('#').trim();
            } else if let Some(command) = line.strip_prefix("> ") {
                last_command = command.trim();
                last_line_num = line_num;
            } else if !line.is_empty() {
                payload.push_str(line);
                payload.push('\n');
            } else {
                if last_command.is_empty() && payload.is_empty() {
                    continue;
                }
                let mut command_and_args = last_command.split_whitespace();
                let command = match command_and_args
                    .next()
                    .expect("Command should not be empty")
                {
                    "put" => Command::Put,
                    "get" => Command::Get,
                    "expect" => Command::Expect,
                    "send" => Command::Send,
                    "delete" => Command::Delete(false),
                    "delete-force-send" => Command::Delete(true),
                    "reset" => Command::Reset,
                    "itip" => Command::Itip,
                    _ => panic!("Unknown command: {}", last_command),
                };

                commands.push(Test {
                    command,
                    test_name: last_comment.to_string(),
                    line_num: last_line_num,
                    parameters: command_and_args.map(String::from).collect(),
                    payload: payload.trim().to_string(),
                });

                last_command = "";
                last_line_num = 0;
                payload.clear();
            }
        }

        if commands.is_empty() {
            panic!("No commands found in file: {}", file_name);
        } else if !last_command.is_empty() {
            panic!(
                "File ended with command '{}' at line {} without payload",
                last_command, last_line_num
            );
        }

        println!("====== Running test: {} ======", file_name);

        let mut store: AHashMap<String, AHashMap<String, ICalendar>> = AHashMap::new();
        let mut dtstamp_map: AHashMap<PartialDateTime, usize> = AHashMap::new();
        let mut last_itip = None;

        for command in &commands {
            if command.command != Command::Put {
                println!("{} (line {})", command.test_name, command.line_num);
            }
            match command.command {
                Command::Put => {
                    let account = command
                        .parameters
                        .first()
                        .expect("Account parameter is required");
                    let name = command
                        .parameters
                        .get(1)
                        .expect("Name parameter is required");
                    let mut ical = ICalendar::parse(&command.payload)
                        .expect("Failed to parse iCalendar payload");
                    match store
                        .entry(account.to_string())
                        .or_default()
                        .entry(name.to_string())
                    {
                        Entry::Occupied(mut entry) => {
                            last_itip = Some(itip_update(
                                &mut ical,
                                entry.get_mut(),
                                &[account.to_string()],
                            ));
                            entry.insert(ical);
                        }
                        Entry::Vacant(entry) => {
                            last_itip = Some(itip_create(&mut ical, &[account.to_string()]));
                            entry.insert(ical);
                        }
                    }
                }
                Command::Get => {
                    let account = command
                        .parameters
                        .first()
                        .expect("Account parameter is required")
                        .as_str();
                    let name = command
                        .parameters
                        .get(1)
                        .expect("Name parameter is required")
                        .as_str();
                    let ical = ICalendar::parse(&command.payload)
                        .expect("Failed to parse iCalendar payload")
                        .to_string()
                        .replace("\r\n", "\n");
                    store
                        .get(account)
                        .and_then(|account_store| account_store.get(name))
                        .map(|stored_ical| {
                            let stored_ical = normalize_ical(stored_ical.clone(), &mut dtstamp_map);
                            if stored_ical != ical {
                                panic!(
                                    "ICalendar mismatch for {}: expected {}, got {}",
                                    command.test_name, ical, stored_ical
                                );
                            }
                        })
                        .unwrap_or_else(|| {
                            panic!(
                                "ICalendar not found for account: {}, name: {}",
                                account, name
                            );
                        });
                }
                Command::Delete(force_send) => {
                    let account = command
                        .parameters
                        .first()
                        .expect("Account parameter is required")
                        .as_str();
                    let name = command
                        .parameters
                        .get(1)
                        .expect("Name parameter is required")
                        .as_str();
                    let store = store.get_mut(account).expect("Account not found in store");

                    if let Some(ical) = store.remove(name) {
                        last_itip = Some(
                            itip_cancel(&ical, &[account.to_string()], force_send)
                                .map(|message| vec![message]),
                        );
                    } else {
                        panic!(
                            "ICalendar not found for account: {}, name: {}",
                            account, name
                        );
                    }
                }
                Command::Expect => {
                    let last_itip_str = match last_itip
                        .as_ref()
                        .expect("No last iTIP message to compare against")
                    {
                        Ok(m) => {
                            let mut result = String::new();
                            for (i, m) in m.iter().enumerate() {
                                if i > 0 {
                                    result.push_str("================================\n");
                                }
                                result.push_str(&m.to_string(&mut dtstamp_map));
                            }
                            result
                        }
                        Err(e) => format!("{e:?}"),
                    };

                    assert_eq!(
                        command.payload.trim(),
                        last_itip_str.trim(),
                        "iTIP message mismatch for {} at line {}\nEXPECTED {}\n\nRECEIVED {}",
                        command.test_name,
                        command.line_num,
                        command.payload,
                        last_itip_str
                    );
                }
                Command::Send => {
                    let mut results = String::new();
                    match last_itip {
                        Some(Ok(messages)) => {
                            for message in messages {
                                for rcpt in &message.to {
                                    let result = match itip_snapshot(
                                        &message.message,
                                        &[rcpt.to_string()],
                                        false,
                                    ) {
                                        Ok(itip_snapshots) => {
                                            match store
                                                .entry(rcpt.to_string())
                                                .or_default()
                                                .entry(itip_snapshots.uid.to_string())
                                            {
                                                Entry::Occupied(mut entry) => {
                                                    let ical = entry.get_mut();
                                                    let snapshots = itip_snapshot(
                                                        ical,
                                                        &[rcpt.to_string()],
                                                        false,
                                                    )
                                                    .expect("Failed to create iTIP snapshot");

                                                    match itip_process_message(
                                                        ical,
                                                        snapshots,
                                                        &message.message,
                                                        itip_snapshots,
                                                        message.from.clone(),
                                                    ) {
                                                        Ok(result) => match result {
                                                            MergeResult::Actions(changes) => {
                                                                itip_merge_changes(ical, changes);
                                                                Ok(None)
                                                            }
                                                            MergeResult::Message(message) => {
                                                                Ok(Some(message))
                                                            }
                                                            MergeResult::None => Ok(None),
                                                        },
                                                        Err(err) => Err(err),
                                                    }
                                                }
                                                Entry::Vacant(entry) => {
                                                    let mut message = message.message.clone();
                                                    itip_import_message(&mut message)
                                                        .expect("Failed to import iTIP message");
                                                    entry.insert(message);
                                                    Ok(None)
                                                }
                                            }
                                        }
                                        Err(err) => Err(err),
                                    };

                                    match result {
                                        Ok(Some(itip_message)) => {
                                            results.push_str(
                                                &itip_message.to_string(&mut dtstamp_map),
                                            );
                                        }
                                        Ok(None) => {}
                                        Err(e) => {
                                            results.push_str(&format!("{e:?}"));
                                        }
                                    }
                                }
                            }

                            assert_eq!(
                                results.trim(),
                                command.payload.trim(),
                                "iTIP send result mismatch for {} at line {}: expected {}, got {}",
                                command.test_name,
                                command.line_num,
                                command.payload,
                                results
                            );
                        }
                        Some(Err(e)) => {
                            panic!(
                                "Failed to create iTIP message for {} at line {}: {:?}",
                                command.test_name, command.line_num, e
                            );
                        }
                        None => {
                            panic!(
                                "No iTIP message to send for {} at line {}",
                                command.test_name, command.line_num
                            );
                        }
                    }
                    last_itip = None;
                }
                Command::Itip => {
                    let mut commands = command.parameters.iter();
                    last_itip = Some(Ok(vec![ItipMessage {
                        from_organizer: false,
                        from: commands
                            .next()
                            .expect("From parameter is required")
                            .to_string(),
                        to: commands.map(|s| s.to_string()).collect::<Vec<_>>(),
                        summary: ItipSummary::Invite(vec![]),
                        message: ICalendar::parse(&command.payload)
                            .expect("Failed to parse iCalendar payload"),
                    }]))
                }
                Command::Reset => {
                    store.clear();
                    dtstamp_map.clear();
                    last_itip = None;
                }
            }
        }
    }
}

trait ItipMessageExt {
    fn to_string(&self, map: &mut AHashMap<PartialDateTime, usize>) -> String;
}

impl ItipMessageExt for ItipMessage<ICalendar> {
    fn to_string(&self, map: &mut AHashMap<PartialDateTime, usize>) -> String {
        use std::fmt::Write;
        let mut f = String::new();
        let mut to = self.to.iter().map(|t| t.as_str()).collect::<Vec<_>>();
        to.sort_unstable();
        writeln!(&mut f, "from: {}", self.from).unwrap();
        writeln!(&mut f, "to: {}", to.join(", ")).unwrap();
        write!(&mut f, "summary: ").unwrap();
        let mut fields = Vec::new();
        match &self.summary {
            ItipSummary::Invite(itip_fields) => {
                writeln!(&mut f, "invite").unwrap();
                fields.push(itip_fields);
            }
            ItipSummary::Update {
                method,
                current,
                previous,
            } => {
                writeln!(&mut f, "update {}", method.as_str()).unwrap();
                fields.push(current);
                fields.push(previous);
            }
            ItipSummary::Cancel(itip_fields) => {
                writeln!(&mut f, "cancel").unwrap();
                fields.push(itip_fields);
            }
            ItipSummary::Rsvp { part_stat, current } => {
                writeln!(&mut f, "rsvp {}", part_stat.as_str()).unwrap();
                fields.push(current);
            }
        }
        for (pos, fields) in fields.into_iter().enumerate() {
            let prefix = if pos > 0 { "~summary." } else { "summary." };
            let mut fields = fields
                .iter()
                .map(|f| format!("{}: {:?}", f.name.as_str().to_lowercase(), f.value))
                .collect::<Vec<_>>();
            fields.sort_unstable();
            for field in fields {
                writeln!(&mut f, "{prefix}{}", field).unwrap();
            }
        }

        write!(&mut f, "{}", normalize_ical(self.message.clone(), map)).unwrap();
        f
    }
}

fn normalize_ical(mut ical: ICalendar, map: &mut AHashMap<PartialDateTime, usize>) -> String {
    let mut comps = ical
        .components
        .iter()
        .enumerate()
        .filter(|(comp_id, _)| {
            ical.components[0]
                .component_ids
                .contains(&(*comp_id as u32))
        })
        .collect::<Vec<_>>();
    comps.sort_unstable_by_key(|(_, comp)| *comp);
    ical.components[0].component_ids = comps.iter().map(|(comp_id, _)| *comp_id as u32).collect();

    for comp in &mut ical.components {
        for entry in &mut comp.entries {
            if let (ICalendarProperty::Dtstamp, Some(ICalendarValue::PartialDateTime(dt))) =
                (&entry.name, entry.values.first())
            {
                if let Some(index) = map.get(dt) {
                    entry.values = vec![ICalendarValue::Integer(*index as i64)];
                } else {
                    let index = map.len();
                    map.insert(dt.as_ref().clone(), index);
                    entry.values = vec![ICalendarValue::Integer(index as i64)];
                }
            }
        }
        comp.entries.sort_unstable();
    }
    ical.to_string().replace("\r\n", "\n")
}
