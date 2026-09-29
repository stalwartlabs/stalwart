/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub fn truncate_plain(text: &str, mut max_len: usize) -> (bool, String) {
    if max_len != 0 && text.len() > max_len {
        let add_dots = max_len > 6;
        if add_dots {
            max_len -= 3;
        }
        let mut result = String::with_capacity(max_len);
        for ch in text.chars() {
            if ch != '\r' {
                if ch.len_utf8() + result.len() > max_len {
                    break;
                }
                result.push(ch);
            }
        }
        if add_dots {
            result.push_str("...");
        }
        (true, result)
    } else {
        (false, text.replace('\r', ""))
    }
}

pub fn truncate_html(html: &str, mut max_len: usize) -> (bool, String) {
    if max_len != 0 && html.len() > max_len {
        let add_dots = max_len > 6;
        if add_dots {
            max_len -= 3;
        }

        let mut result = String::with_capacity(max_len);
        let mut in_tag = false;
        let mut in_comment = false;
        let mut last_tag_end_pos = 0;
        let mut cr_count = 0;
        for (pos, ch) in html.char_indices() {
            let mut set_last_tag = 0;
            match ch {
                '<' if !in_tag => {
                    in_tag = true;
                    if let Some("!--") = html.get(pos + 1..pos + 4) {
                        in_comment = true;
                    }
                    set_last_tag = pos;
                }
                '>' if in_tag => {
                    if in_comment {
                        if let Some("--") = html.get(pos - 2..pos) {
                            in_comment = false;
                            in_tag = false;
                            set_last_tag = pos + 1;
                        }
                    } else {
                        in_tag = false;
                        set_last_tag = pos + 1;
                    }
                }
                '\r' => {
                    cr_count += 1;
                    continue;
                }
                _ => (),
            }
            if ch.len_utf8() + pos - cr_count > max_len {
                result.push_str(
                    &html[0..if (in_tag || set_last_tag > 0) && last_tag_end_pos > 0 {
                        last_tag_end_pos
                    } else {
                        pos
                    }]
                        .replace('\r', ""),
                );
                if add_dots {
                    result.push_str("...");
                }
                break;
            } else if set_last_tag > 0 {
                last_tag_end_pos = set_last_tag;
            }
        }
        (true, result)
    } else {
        (false, html.replace('\r', ""))
    }
}
