/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ContentTypePart, HeaderPart, Number, Value, VariableType,
    grammar::{
        Capability, Comparator,
        actions::{
            action_mime::MimeOpts,
            action_redirect::{ByTime, Notify},
            action_set::Modifier,
            action_vacation::Period,
        },
        expr::Expression,
        instruction::Instruction,
        test::Test,
        tests::{test_body::BodyTransform, test_date::Zone, test_duplicate::DupMatch},
    },
};
use crate::{
    FileCarbonCopy, Metadata, Sieve,
    bytecode::{
        emit::Emitter,
        ops::{self, Field, Match},
        rec::{Range, Rec, Str, tag},
    },
    runtime::tests::test_date::{ZONE_LOCAL, ZONE_NAMED, ZONE_OFFSET, ZONE_ORIGINAL},
    sieve::LoadError,
};

struct Codegen<'c> {
    emitter: Emitter,
    constants: &'c [String],
    constant_strs: Vec<Option<Str>>,
    patches: Vec<(u32, u32)>,
    scratch: Vec<Rec>,
}

pub(crate) fn emit(
    instructions: &[Instruction],
    constants: &[String],
    num_vars: u32,
    num_match_vars: u32,
) -> Result<Sieve<'static>, LoadError> {
    let mut codegen = Codegen {
        emitter: Emitter::new(),
        constants,
        constant_strs: vec![None; constants.len()],
        patches: Vec::with_capacity(16),
        scratch: Vec::with_capacity(64),
    };
    let mut offsets = Vec::with_capacity(instructions.len() + 1);
    for instruction in instructions {
        offsets.push(codegen.emitter.code.pos());
        codegen.instruction(instruction);
    }
    offsets.push(codegen.emitter.code.pos());
    for (at, target) in std::mem::take(&mut codegen.patches) {
        let target = offsets
            .get(target as usize)
            .copied()
            .unwrap_or(codegen.emitter.code.pos());
        codegen.emitter.code.patch_u32(at, target);
    }
    codegen
        .emitter
        .finish(num_vars as u16, num_match_vars as u16)
}

impl Codegen<'_> {
    fn str(&mut self, text: &str) -> Str {
        self.emitter.str(text)
    }

    fn constant(&mut self, id: super::ConstantId) -> Str {
        if let Some(Some(s)) = self.constant_strs.get(id.index()) {
            return *s;
        }
        let text = self
            .constants
            .get(id.index())
            .map(|c| c.as_str())
            .unwrap_or("");
        let s = self.emitter.str(text);
        if let Some(slot) = self.constant_strs.get_mut(id.index()) {
            *slot = Some(s);
        }
        s
    }

    fn flush_scratch(&mut self, start: usize) -> Range {
        let range = self.emitter.push_recs(&self.scratch[start..]);
        self.scratch.truncate(start);
        range
    }

    fn jump(&mut self, target: u32) -> ops::Jump {
        self.patches.push((self.emitter.code.pos() + 1, target));
        ops::Jump(u32::MAX)
    }

    fn jump_at(&mut self, offset_in_body: u32, target: u32) -> ops::Jump {
        self.patches
            .push((self.emitter.code.pos() + 1 + offset_in_body, target));
        ops::Jump(u32::MAX)
    }

    fn value_recs(&mut self, value: &Value) {
        match value {
            Value::Text(id) => {
                let s = self.constant(*id);
                self.scratch.push(Rec::tagged(tag::TEXT).with_str(s));
            }
            Value::Number(Number::Integer(n)) => self.scratch.push(Rec {
                e: *n as u64,
                ..Rec::tagged(tag::INT)
            }),
            Value::Number(Number::Float(n)) => self.scratch.push(Rec {
                e: n.to_bits(),
                ..Rec::tagged(tag::FLOAT)
            }),
            Value::Variable(var) => self.variable_recs(var),
            Value::Regex(regex) => {
                let s = self.str(&regex.expr);
                let slot = self.emitter.regex_slot();
                self.scratch.push(Rec {
                    c: slot,
                    ..Rec::tagged(tag::REGEX).with_str(s)
                });
            }
            Value::Glob(glob) => {
                let s = self.str(&glob.expr);
                let index = self.emitter.glob(&glob.glob);
                self.scratch.push(Rec {
                    c: index,
                    ..Rec::tagged(tag::GLOB).with_str(s)
                });
            }
            Value::Header(name) => {
                let index = self.emitter.header_name(name);
                self.scratch.push(Rec {
                    c: index,
                    ..Rec::tagged(tag::HEADER)
                });
            }
            Value::List(items) => {
                let range = self.list(items);
                self.scratch.push(Rec::tagged(tag::LIST).with_range(range));
            }
        }
    }

    fn variable_recs(&mut self, var: &VariableType) {
        match var {
            VariableType::Local(id) => self.scratch.push(Rec {
                c: *id,
                ..Rec::tagged(tag::VAR_LOCAL)
            }),
            VariableType::Match(id) => self.scratch.push(Rec {
                b: *id,
                ..Rec::tagged(tag::VAR_MATCH)
            }),
            VariableType::Global(name) => {
                let s = self.str(name);
                self.scratch.push(Rec::tagged(tag::VAR_GLOBAL).with_str(s));
            }
            VariableType::Environment(name) => {
                let s = self.str(name);
                self.scratch.push(Rec::tagged(tag::VAR_ENV).with_str(s));
            }
            VariableType::Envelope(envelope) => self.scratch.push(Rec {
                b: *envelope as u8,
                ..Rec::tagged(tag::VAR_ENVELOPE)
            }),
            VariableType::Part(part) => {
                let (kind, convert) = match part {
                    super::MessagePart::TextBody(convert) => (0, *convert),
                    super::MessagePart::HtmlBody(convert) => (1, *convert),
                    super::MessagePart::Contents => (2, false),
                    super::MessagePart::Raw => (3, false),
                };
                self.scratch.push(Rec {
                    b: kind,
                    c: u16::from(convert),
                    ..Rec::tagged(tag::VAR_PART)
                });
            }
            VariableType::Header(header) => {
                let names: Vec<Rec> = header
                    .name
                    .iter()
                    .map(|name| Rec {
                        c: self.emitter.header_name(name),
                        ..Rec::tagged(tag::HEADER)
                    })
                    .collect();
                let names = self.emitter.push_recs(&names);
                let (part, sub, attr) = match &header.part {
                    HeaderPart::Text => (0, 0, None),
                    HeaderPart::Date => (1, 0, None),
                    HeaderPart::Id => (2, 0, None),
                    HeaderPart::Address(part) => (3, *part as u16, None),
                    HeaderPart::ContentType(ct) => match ct {
                        ContentTypePart::Type => (4, 0, None),
                        ContentTypePart::Subtype => (4, 1, None),
                        ContentTypePart::Attribute(attr) => (4, 2, Some(attr.as_str())),
                    },
                    HeaderPart::Received(part) => (5, part.code(), None),
                    HeaderPart::Raw => (6, 0, None),
                    HeaderPart::RawName => (7, 0, None),
                    HeaderPart::Exists => (8, 0, None),
                };
                let attr = attr.map(|attr| self.str(attr)).unwrap_or_default();
                self.scratch.push(Rec {
                    b: part,
                    c: sub,
                    d: names.start,
                    e: ((header.index_hdr as u32 as u64) << 32) | (header.index_part as u32 as u64),
                    ..Rec::tagged(tag::VAR_HEADER)
                });
                self.scratch.push(Rec {
                    c: names.len as u16,
                    ..Rec::tagged(tag::CONT).with_str(attr)
                });
            }
        }
    }

    fn list(&mut self, items: &[Value]) -> Range {
        let start = self.scratch.len();
        for item in items {
            self.value_recs(item);
        }
        self.flush_scratch(start)
    }

    fn inline(&mut self, value: &Value) -> Rec {
        let start = self.scratch.len();
        self.value_recs(value);
        self.inline_recs(start)
    }

    fn inline_recs(&mut self, start: usize) -> Rec {
        match self.scratch.len() - start {
            1 => {
                let rec = self.scratch[start];
                self.scratch.truncate(start);
                rec
            }
            0 => Rec::tagged(tag::NONE),
            _ => {
                let range = self.flush_scratch(start);
                Rec {
                    d: range.start,
                    e: (range.len - 1) as u64,
                    ..Rec::tagged(tag::REF)
                }
            }
        }
    }

    fn inline_opt(&mut self, value: &Option<Value>) -> Rec {
        match value {
            Some(value) => self.inline(value),
            None => Rec::tagged(tag::NONE),
        }
    }

    fn variable(&mut self, var: &VariableType) -> Rec {
        let start = self.scratch.len();
        self.variable_recs(var);
        self.inline_recs(start)
    }

    fn variable_opt(&mut self, var: &Option<VariableType>) -> Rec {
        match var {
            Some(var) => self.variable(var),
            None => Rec::tagged(tag::VARIABLE_NONE),
        }
    }

    fn variable_list(&mut self, vars: &[VariableType]) -> Range {
        let start = self.scratch.len();
        for var in vars {
            self.variable_recs(var);
        }
        self.flush_scratch(start)
    }

    fn expressions(&mut self, exprs: &[Expression]) -> Range {
        let sizes: Vec<u32> = exprs
            .iter()
            .map(|expr| match expr {
                Expression::VariableOther(var)
                    if matches!(var.as_ref(), VariableType::Header(_)) =>
                {
                    2
                }
                _ => 1,
            })
            .collect();
        let start = self.scratch.len();
        for (index, expr) in exprs.iter().enumerate() {
            match expr {
                Expression::VariableLocal(id) => self.scratch.push(Rec {
                    c: *id,
                    ..Rec::tagged(tag::VAR_LOCAL)
                }),
                Expression::VariableMatch(id) => self.scratch.push(Rec {
                    b: *id,
                    ..Rec::tagged(tag::VAR_MATCH)
                }),
                Expression::VariableOther(var) => self.variable_recs(var),
                Expression::ConstantInteger(n) => self.scratch.push(Rec {
                    e: *n as u64,
                    ..Rec::tagged(tag::INT)
                }),
                Expression::ConstantFloat(n) => self.scratch.push(Rec {
                    e: n.to_bits(),
                    ..Rec::tagged(tag::FLOAT)
                }),
                Expression::ConstantString(id) => {
                    let s = self.constant(*id);
                    self.scratch.push(Rec::tagged(tag::TEXT).with_str(s));
                }
                Expression::BinaryOperator(op) => self.scratch.push(Rec {
                    b: *op as u8,
                    ..Rec::tagged(tag::BIN_OP)
                }),
                Expression::UnaryOperator(op) => self.scratch.push(Rec {
                    b: *op as u8,
                    ..Rec::tagged(tag::UN_OP)
                }),
                Expression::JmpIf { val, pos } => {
                    let skip: u32 = sizes.iter().skip(index + 1).take(*pos as usize).sum();
                    self.scratch.push(Rec {
                        b: u8::from(*val),
                        d: skip,
                        ..Rec::tagged(tag::JMP_IF)
                    });
                }
                Expression::Function { id, num_args } => self.scratch.push(Rec {
                    c: *num_args as u16,
                    d: *id,
                    ..Rec::tagged(tag::CALL)
                }),
                Expression::ArrayAccess => self.scratch.push(Rec::tagged(tag::ARRAY_ACCESS)),
                Expression::ArrayBuild(n) => self.scratch.push(Rec {
                    d: *n,
                    ..Rec::tagged(tag::ARRAY_BUILD)
                }),
            }
        }
        self.flush_scratch(start)
    }

    fn modifiers(&mut self, modifiers: &[Modifier]) -> Range {
        let start = self.scratch.len();
        for modifier in modifiers {
            self.scratch.push(Rec {
                b: modifier.code(),
                ..Rec::tagged(tag::MODIFIER)
            });
            if let Modifier::Replace(replacement) = modifier {
                let find = self.inline(&replacement.find);
                let replace = self.inline(&replacement.replace);
                self.scratch.push(find);
                self.scratch.push(replace);
            }
        }
        self.flush_scratch(start)
    }

    fn capabilities(&mut self, capabilities: &[Capability]) -> Range {
        let mut recs = Vec::with_capacity(capabilities.len());
        for capability in capabilities {
            recs.push(match capability {
                Capability::Comparator(Comparator::Other(name)) => {
                    let s = self.str(name);
                    Rec {
                        b: 5,
                        c: Comparator::Octet.code() as u16,
                        ..Rec::tagged(tag::CAPABILITY).with_str(s)
                    }
                }
                Capability::Comparator(comparator) => Rec {
                    b: 5,
                    c: comparator.code() as u16,
                    ..Rec::tagged(tag::CAPABILITY)
                },
                Capability::Other(name) => {
                    let s = self.str(name);
                    Rec {
                        b: 6,
                        ..Rec::tagged(tag::CAPABILITY).with_str(s)
                    }
                }
                other => Rec {
                    b: other.id(),
                    ..Rec::tagged(tag::CAPABILITY)
                },
            });
        }
        self.emitter.push_recs(&recs)
    }

    fn mime_opts(&mut self, opts: &MimeOpts<Value>) -> ops::MimeOpts {
        match opts {
            MimeOpts::Type => ops::MimeOpts {
                kind: 0,
                params: Range::EMPTY,
            },
            MimeOpts::Subtype => ops::MimeOpts {
                kind: 1,
                params: Range::EMPTY,
            },
            MimeOpts::ContentType => ops::MimeOpts {
                kind: 2,
                params: Range::EMPTY,
            },
            MimeOpts::Param(params) => ops::MimeOpts {
                kind: 3,
                params: self.list(params),
            },
            MimeOpts::None => ops::MimeOpts {
                kind: 4,
                params: Range::EMPTY,
            },
        }
    }

    fn fcc(&mut self, fcc: &Option<FileCarbonCopy<Value>>) -> ops::Fcc {
        match fcc {
            Some(fcc) => ops::Fcc {
                present: true,
                mailbox: self.inline(&fcc.mailbox),
                mailbox_id: self.inline_opt(&fcc.mailbox_id),
                create: fcc.create,
                flags: self.list(&fcc.flags),
                special_use: self.inline_opt(&fcc.special_use),
            },
            None => ops::Fcc::default(),
        }
    }

    fn by_time(&mut self, by_time: &ByTime<Value>) -> ops::ByTime {
        match by_time {
            ByTime::Relative {
                rlimit,
                mode,
                trace,
            } => ops::ByTime {
                kind: 0,
                mode: *mode as u8,
                trace: *trace,
                rlimit: *rlimit,
                alimit: Rec::tagged(tag::NONE),
            },
            ByTime::Absolute {
                alimit,
                mode,
                trace,
            } => ops::ByTime {
                kind: 1,
                mode: *mode as u8,
                trace: *trace,
                rlimit: 0,
                alimit: self.inline(alimit),
            },
            ByTime::None => ops::ByTime {
                kind: 2,
                mode: 2,
                trace: false,
                rlimit: 0,
                alimit: Rec::tagged(tag::NONE),
            },
        }
    }

    fn notify(&mut self, notify: &Notify) -> ops::NotifySpec {
        match notify {
            Notify::Never => ops::NotifySpec {
                kind: 0,
                items: Range::EMPTY,
            },
            Notify::Items(items) => {
                let recs: Vec<Rec> = items
                    .iter()
                    .map(|item| Rec {
                        b: *item as u8,
                        ..Rec::tagged(tag::NOTIFY_ITEM)
                    })
                    .collect();
                ops::NotifySpec {
                    kind: 1,
                    items: self.emitter.push_recs(&recs),
                }
            }
            Notify::Default => ops::NotifySpec {
                kind: 2,
                items: Range::EMPTY,
            },
        }
    }

    fn emit_op<T: OpEmit>(&mut self, op: &T) {
        op.emit_into(&mut self.emitter.code);
    }

    fn instruction(&mut self, instruction: &Instruction) {
        match instruction {
            Instruction::Require(capabilities) => {
                let capabilities = self.capabilities(capabilities);
                self.emit_op(&ops::Require { capabilities });
            }
            Instruction::Keep(keep) => {
                let flags = self.list(&keep.flags);
                self.emit_op(&ops::Keep { flags });
            }
            Instruction::FileInto(fi) => {
                let op = ops::FileInto {
                    copy: fi.copy,
                    create: fi.create,
                    folder: self.inline(&fi.folder),
                    flags: self.list(&fi.flags),
                    mailbox_id: self.inline_opt(&fi.mailbox_id),
                    special_use: self.inline_opt(&fi.special_use),
                };
                self.emit_op(&op);
            }
            Instruction::Redirect(redirect) => {
                let op = ops::Redirect {
                    copy: redirect.copy,
                    list: redirect.list,
                    address: self.inline(&redirect.address),
                    notify: self.notify(&redirect.notify),
                    ret: redirect.return_of_content as u8,
                    by_time: self.by_time(&redirect.by_time),
                };
                self.emit_op(&op);
            }
            Instruction::Discard => self.emit_op(&ops::Discard {}),
            Instruction::Stop => self.emit_op(&ops::Stop {}),
            Instruction::Invalid(invalid) => {
                let op = ops::Invalid {
                    name: self.str(&invalid.name),
                    line_num: invalid.line_num,
                    line_pos: invalid.line_pos,
                };
                self.emit_op(&op);
            }
            Instruction::Test(test) => self.test(test),
            Instruction::Jmp(target) => {
                let target = self.jump(*target);
                self.emit_op(&ops::Jmp { target });
            }
            Instruction::Jz(target) => {
                let target = self.jump(*target);
                self.emit_op(&ops::Jz { target });
            }
            Instruction::Jnz(target) => {
                let target = self.jump(*target);
                self.emit_op(&ops::Jnz { target });
            }
            Instruction::ForEveryPartPush => self.emit_op(&ops::ForEveryPartPush {}),
            Instruction::ForEveryPart(fep) => {
                let jz_pos = self.jump(fep.jz_pos);
                self.emit_op(&ops::ForEveryPart { jz_pos });
            }
            Instruction::ForEveryPartPop(num_pops) => {
                self.emit_op(&ops::ForEveryPartPop {
                    num_pops: *num_pops,
                });
            }
            Instruction::Replace(replace) => {
                let op = ops::Replace {
                    subject: self.inline_opt(&replace.subject),
                    from: self.inline_opt(&replace.from),
                    replacement: self.inline(&replace.replacement),
                    mime: replace.mime,
                };
                self.emit_op(&op);
            }
            Instruction::Enclose(enclose) => {
                let op = ops::Enclose {
                    subject: self.inline_opt(&enclose.subject),
                    headers: self.list(&enclose.headers),
                    value: self.inline(&enclose.value),
                };
                self.emit_op(&op);
            }
            Instruction::ExtractText(extract) => {
                let op = ops::ExtractText {
                    modifiers: self.modifiers(&extract.modifiers),
                    first: extract.first,
                    name: self.variable(&extract.name),
                };
                self.emit_op(&op);
            }
            Instruction::Convert(convert) => {
                let op = ops::Convert {
                    from_media_type: self.inline(&convert.from_media_type),
                    to_media_type: self.inline(&convert.to_media_type),
                    transcoding_params: self.list(&convert.transcoding_params),
                    is_not: convert.is_not,
                };
                self.emit_op(&op);
            }
            Instruction::AddHeader(add) => {
                let op = ops::AddHeader {
                    last: add.last,
                    field_name: self.inline(&add.field_name),
                    value: self.inline(&add.value),
                };
                self.emit_op(&op);
            }
            Instruction::DeleteHeader(delete) => {
                let op = ops::DeleteHeader {
                    index: delete.index,
                    comparator: delete.comparator.code(),
                    match_type: Match::from_match_type(&delete.match_type),
                    field_name: self.inline(&delete.field_name),
                    value_patterns: self.list(&delete.value_patterns),
                    mime_anychild: delete.mime_anychild,
                };
                self.emit_op(&op);
            }
            Instruction::Set(set) => {
                let op = ops::Set {
                    modifiers: self.modifiers(&set.modifiers),
                    name: self.variable(&set.name),
                    value: self.inline(&set.value),
                };
                self.emit_op(&op);
            }
            Instruction::Clear(clear) => self.emit_op(&ops::Clear {
                local_vars_idx: clear.local_vars_idx,
                local_vars_num: clear.local_vars_num,
                match_vars: clear.match_vars,
            }),
            Instruction::Notify(notify) => {
                let op = ops::Notify {
                    from: self.inline_opt(&notify.from),
                    importance: self.inline_opt(&notify.importance),
                    options: self.list(&notify.options),
                    message: self.inline_opt(&notify.message),
                    fcc: self.fcc(&notify.fcc),
                    method: self.inline(&notify.method),
                };
                self.emit_op(&op);
            }
            Instruction::Reject(reject) => {
                let op = ops::Reject {
                    ereject: reject.ereject,
                    reason: self.inline(&reject.reason),
                };
                self.emit_op(&op);
            }
            Instruction::Vacation(vacation) => {
                let op = ops::Vacation {
                    subject: self.inline_opt(&vacation.subject),
                    from: self.inline_opt(&vacation.from),
                    mime: vacation.mime,
                    fcc: self.fcc(&vacation.fcc),
                    reason: self.inline(&vacation.reason),
                };
                self.emit_op(&op);
            }
            Instruction::Error(error) => {
                let op = ops::Error {
                    message: self.inline(&error.message),
                };
                self.emit_op(&op);
            }
            Instruction::EditFlags(flags) => {
                let op = ops::EditFlags {
                    action: flags.action as u8,
                    name: self.variable_opt(&flags.name),
                    flags: self.list(&flags.flags),
                };
                self.emit_op(&op);
            }
            Instruction::Include(include) => {
                let op = ops::Include {
                    global: include.location as u8 == 1,
                    once: include.once,
                    optional: include.optional,
                    value: self.inline(&include.value),
                };
                self.emit_op(&op);
            }
            Instruction::Return => self.emit_op(&ops::Return {}),
            Instruction::While(while_) => {
                let expr = self.expressions(&while_.expr);
                let jz_pos = self.jump_at(8, while_.jz_pos);
                self.emit_op(&ops::While { expr, jz_pos });
            }
            Instruction::Eval(expr) => {
                let expr = self.expressions(expr);
                self.emit_op(&ops::Eval { expr });
            }
            Instruction::Let(let_) => {
                let op = ops::Let {
                    name: self.variable(&let_.name),
                    expr: self.expressions(&let_.expr),
                };
                self.emit_op(&op);
            }
            #[cfg(all(test, stalwart_tests))]
            Instruction::TestCmd(arguments) => {
                let arguments = self.list(arguments);
                self.emit_op(&ops::TestCmd { arguments });
            }
        }
    }

    fn test(&mut self, test: &Test) {
        match test {
            Test::True => self.emit_op(&ops::TestTrue {}),
            Test::False => self.emit_op(&ops::TestFalse {}),
            Test::Address(t) => {
                let op = ops::TestAddress {
                    header_list: self.list(&t.header_list),
                    key_list: self.list(&t.key_list),
                    address_part: t.address_part as u8,
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    index: t.index,
                    mime_anychild: t.mime_anychild,
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Envelope(t) => {
                let recs: Vec<Rec> = t
                    .envelope_list
                    .iter()
                    .map(|envelope| Rec {
                        b: *envelope as u8,
                        ..Rec::tagged(tag::ENVELOPE)
                    })
                    .collect();
                let op = ops::TestEnvelope {
                    envelope_list: self.emitter.push_recs(&recs),
                    key_list: self.list(&t.key_list),
                    address_part: t.address_part as u8,
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    zone: t.zone,
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Exists(t) => {
                let op = ops::TestExists {
                    header_names: self.list(&t.header_names),
                    mime_anychild: t.mime_anychild,
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Header(t) => {
                let op = ops::TestHeader {
                    header_list: self.list(&t.header_list),
                    key_list: self.list(&t.key_list),
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    index: t.index,
                    mime_opts: self.mime_opts(&t.mime_opts),
                    mime_anychild: t.mime_anychild,
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Size(t) => self.emit_op(&ops::TestSize {
                over: t.over,
                limit: t.limit,
                is_not: t.is_not,
            }),
            Test::Invalid(invalid) => {
                let op = ops::TestInvalid {
                    name: self.str(&invalid.name),
                    line_num: invalid.line_num,
                    line_pos: invalid.line_pos,
                };
                self.emit_op(&op);
            }
            Test::Body(t) => {
                let body_transform = match &t.body_transform {
                    BodyTransform::Raw => ops::BodyTransform {
                        kind: 0,
                        content_types: Range::EMPTY,
                    },
                    BodyTransform::Content(types) => ops::BodyTransform {
                        kind: 1,
                        content_types: self.list(types),
                    },
                    BodyTransform::Text => ops::BodyTransform {
                        kind: 2,
                        content_types: Range::EMPTY,
                    },
                };
                let op = ops::TestBody {
                    key_list: self.list(&t.key_list),
                    body_transform,
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    include_subject: t.include_subject,
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Convert(t) => {
                let op = ops::TestConvert {
                    from_media_type: self.inline(&t.from_media_type),
                    to_media_type: self.inline(&t.to_media_type),
                    transcoding_params: self.list(&t.transcoding_params),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Date(t) => {
                let op = ops::TestDate {
                    header_name: self.inline(&t.header_name),
                    key_list: self.list(&t.key_list),
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    index: t.index,
                    zone: t.zone.to_op(),
                    date_part: t.date_part as u8,
                    mime_anychild: t.mime_anychild,
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::CurrentDate(t) => {
                let op = ops::TestCurrentDate {
                    zone: t.zone.to_op(),
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    date_part: t.date_part as u8,
                    key_list: self.list(&t.key_list),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Duplicate(t) => {
                let dup_match = match &t.dup_match {
                    DupMatch::Header(value) => ops::DupMatch {
                        kind: 0,
                        value: self.inline(value),
                    },
                    DupMatch::UniqueId(value) => ops::DupMatch {
                        kind: 1,
                        value: self.inline(value),
                    },
                    DupMatch::Default => ops::DupMatch {
                        kind: 2,
                        value: Rec::tagged(tag::NONE),
                    },
                };
                let op = ops::TestDuplicate {
                    handle: self.inline_opt(&t.handle),
                    dup_match,
                    seconds: t.seconds,
                    last: t.last,
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::String(t) => {
                let op = ops::TestString {
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    source: self.list(&t.source),
                    key_list: self.list(&t.key_list),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Environment(t) => {
                let op = ops::TestEnvironment {
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    source: self.list(&t.source),
                    key_list: self.list(&t.key_list),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::NotifyMethodCapability(t) => {
                let op = ops::TestNotifyMethodCapability {
                    comparator: t.comparator.code(),
                    match_type: Match::from_match_type(&t.match_type),
                    notification_uri: self.inline(&t.notification_uri),
                    notification_capability: self.inline(&t.notification_capability),
                    key_list: self.list(&t.key_list),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::ValidNotifyMethod(t) => {
                let op = ops::TestValidNotifyMethod {
                    notification_uris: self.list(&t.notification_uris),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::ValidExtList(t) => {
                let op = ops::TestValidExtList {
                    list_names: self.list(&t.list_names),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Ihave(t) => {
                let op = ops::TestIhave {
                    capabilities: self.capabilities(&t.capabilities),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::HasFlag(t) => {
                let op = ops::TestHasFlag {
                    comparator: t.comparator.code(),
                    match_type: Match::from_match_type(&t.match_type),
                    variable_list: self.variable_list(&t.variable_list),
                    flags: self.list(&t.flags),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::MailboxExists(t) => {
                let op = ops::TestMailboxExists {
                    mailbox_names: self.list(&t.mailbox_names),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Metadata(t) => {
                let metadata = match &t.medatata {
                    Metadata::Server { annotation } => ops::MetadataRef {
                        kind: 0,
                        name: Rec::tagged(tag::NONE),
                        annotation: self.inline(annotation),
                    },
                    Metadata::Mailbox { name, annotation } => ops::MetadataRef {
                        kind: 1,
                        name: self.inline(name),
                        annotation: self.inline(annotation),
                    },
                };
                let op = ops::TestMetadata {
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    metadata,
                    key_list: self.list(&t.key_list),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::MetadataExists(t) => {
                let op = ops::TestMetadataExists {
                    mailbox: self.inline_opt(&t.mailbox),
                    annotation_names: self.list(&t.annotation_names),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::MailboxIdExists(t) => {
                let op = ops::TestMailboxIdExists {
                    mailbox_ids: self.list(&t.mailbox_ids),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::SpamTest(t) => {
                let op = ops::TestSpamTest {
                    value: self.inline(&t.value),
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    percent: t.percent,
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::VirusTest(t) => {
                let op = ops::TestVirusTest {
                    value: self.inline(&t.value),
                    match_type: Match::from_match_type(&t.match_type),
                    comparator: t.comparator.code(),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::SpecialUseExists(t) => {
                let op = ops::TestSpecialUseExists {
                    mailbox: self.inline_opt(&t.mailbox),
                    attributes: self.list(&t.attributes),
                    is_not: t.is_not,
                };
                self.emit_op(&op);
            }
            Test::Vacation(t) => {
                let period = match &t.period {
                    Period::Days(days) => ops::Period {
                        kind: 0,
                        value: *days,
                    },
                    Period::Seconds(seconds) => ops::Period {
                        kind: 1,
                        value: *seconds,
                    },
                    Period::Default => ops::Period { kind: 2, value: 0 },
                };
                let op = ops::TestVacation {
                    addresses: self.list(&t.addresses),
                    period,
                    handle: self.inline_opt(&t.handle),
                    reason: self.inline(&t.reason),
                };
                self.emit_op(&op);
            }
            #[cfg(all(test, stalwart_tests))]
            Test::TestCmd(cmd) => {
                let op = ops::TestCmdTest {
                    arguments: self.list(&cmd.arguments),
                    is_not: cmd.is_not,
                };
                self.emit_op(&op);
            }
        }
    }
}

pub(crate) trait OpEmit {
    fn emit_into(&self, code: &mut crate::bytecode::cursor::Code);
}

macro_rules! op_emit {
    ($($name:ident),* $(,)?) => {
        $(
            impl OpEmit for ops::$name {
                fn emit_into(&self, code: &mut crate::bytecode::cursor::Code) {
                    self.emit(code);
                }
            }
        )*
    };
}

op_emit!(
    Require,
    Keep,
    FileInto,
    Redirect,
    Discard,
    Stop,
    Invalid,
    TestTrue,
    TestFalse,
    TestAddress,
    TestEnvelope,
    TestExists,
    TestHeader,
    TestSize,
    TestInvalid,
    TestBody,
    TestConvert,
    Convert,
    TestDate,
    TestCurrentDate,
    TestDuplicate,
    TestString,
    TestEnvironment,
    TestNotifyMethodCapability,
    TestValidNotifyMethod,
    TestValidExtList,
    TestIhave,
    TestHasFlag,
    TestMailboxExists,
    TestMetadata,
    TestMetadataExists,
    TestMailboxIdExists,
    TestSpamTest,
    TestVirusTest,
    TestSpecialUseExists,
    TestVacation,
    Jmp,
    Jz,
    Jnz,
    ForEveryPartPush,
    ForEveryPart,
    ForEveryPartPop,
    Replace,
    Enclose,
    ExtractText,
    AddHeader,
    DeleteHeader,
    Set,
    Clear,
    Notify,
    Reject,
    Vacation,
    Error,
    EditFlags,
    Include,
    Return,
    While,
    Eval,
    Let,
    TestCmd,
    TestCmdTest,
);

impl Zone {
    fn to_op(self) -> ops::Zone {
        match self {
            Zone::Time(time) => ops::Zone {
                kind: ZONE_OFFSET,
                time,
            },
            Zone::Original => ops::Zone {
                kind: ZONE_ORIGINAL,
                time: 0,
            },
            Zone::Local => ops::Zone {
                kind: ZONE_LOCAL,
                time: 0,
            },
            Zone::Named(id) => ops::Zone {
                kind: ZONE_NAMED,
                time: i64::from(id),
            },
        }
    }
}

impl Field for () {
    fn read(_: &mut crate::bytecode::cursor::Cursor<'_>) -> crate::bytecode::Decoded<Self> {
        Ok(())
    }

    fn write(&self, _: &mut crate::bytecode::cursor::Code) {}
}
