/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    access::{LogonAccess, RESPONSE_FLAG_OOF},
    execute::{MailboxView, RopContext, RopError, RopResult},
    state::{LogonObject, MAX_LOGON_MAILBOXES, ServerObject},
    store::{ReceiveFolder, SpecialFolders, StoreGuids, visible_folder},
};
use crate::{
    folders::{
        FolderNode, FolderTree, FolderWriteError, FolderWrites, FolderWritten, SYNC_ISSUES_FOLDERS,
        SpecialFolder,
    },
    identity::principal_from_dn,
    mapi::ids::{MapiId, fixed},
    store::{FolderRef, account::ExchangeAccountStore},
    vacation::{VacationEdit, VacationState, VacationWrite, vacation_in_effect, write_vacation},
};
use common::cache::exchange::MAX_FOREIGN_REPLICAS;
use exchange_proto::{
    common::{FileTime, Guid, UtcSeconds},
    ids::{Eid, Gid, Globcnt, LongTermId, ReplGuid, ReplId},
    mapi::{
        ErrorCode,
        prop::{PropTag, PropType, PropValue, row::RowSetLayout, tags},
        rop::{
            DecodedRop, ResponseHeader,
            requests::{
                DeleteProperties, GetReceiveFolder, IdFromLongTermId, Logon, LongTermIdFromId,
                SetProperties, SetReceiveFolder,
            },
            responses::{
                DeletePropertiesResponse, GetReceiveFolderResponse, GetTransportFolderResponse,
                IdFromLongTermIdResponse, LogonPrivateResponse, LogonResponse, LogonTime,
                LongTermIdFromIdResponse, NotGhostedResponse, PropertyProblem,
                SetPropertiesResponse, table_row_options,
            },
            writer::RopResponse,
        },
    },
};
use smallvec::SmallVec;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use types::type_state::DataType;

const RECEIVE_FOLDER_COLUMNS: [PropTag; 3] = [
    tags::FOLDER_ID,
    tags::MESSAGE_CLASS.with_type(PropType::String8),
    tags::LAST_MODIFICATION_TIME,
];

struct EmptyLongTermIds;

impl RopResponse for EmptyLongTermIds {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&0u16.to_le_bytes());
    }

    fn encoded_len_hint(&self) -> usize {
        2
    }
}

const OPEN_USE_ADMIN_PRIVILEGE: u32 = 0x0000_0001;
const OPEN_USE_PER_MDB_REPLID_MAPPING: u32 = 0x0100_0000;
const DELEGATE_REPLICA_LIMIT: usize = MAX_FOREIGN_REPLICAS / 2;
const SECONDS_PER_DAY: i64 = 86_400;
const ZERO_EID: Eid = Eid::from_le_u64(0);
const ZERO_REPLID: ReplId = ReplId(0);
const ZERO_REPL_GUID: ReplGuid = ReplGuid(Guid([0; 16]));
const ZERO_LONG_TERM_ID: LongTermId = LongTermId {
    gid: Gid {
        guid: ZERO_REPL_GUID,
        counter: Globcnt::from_wire([0; 6]),
    },
};

impl RopContext<'_, '_> {
    pub async fn logon(&mut self, rop: &DecodedRop<'_>, request: &Logon<'_>) -> RopResult {
        let index = request.output_handle_index;
        if request.logon_flags & Logon::FLAG_PRIVATE == 0 {
            return Err(RopError::Code(ErrorCode::LOGIN_FAILURE));
        }
        let access_token = self.request.access_token;
        let mailbox_id = if request.essdn.is_empty() {
            access_token.account_id()
        } else {
            principal_from_dn(request.essdn).ok_or(ErrorCode::UNKNOWN_USER)?
        };
        let access = LogonAccess::of(access_token, mailbox_id).ok_or(ErrorCode::LOGIN_FAILURE)?;
        if access != LogonAccess::Owner && request.open_flags & OPEN_USE_ADMIN_PRIVILEGE != 0 {
            return Err(RopError::Code(ErrorCode::LOGIN_PERM));
        }
        let held = self.state.logon_mailboxes(Some(rop.header.logon_id));
        if !held.contains(&mailbox_id) {
            if !held.is_empty() && request.open_flags & OPEN_USE_PER_MDB_REPLID_MAPPING == 0 {
                return Err(RopError::Code(ErrorCode::INVALID_PARAM));
            }
            if held.len() >= MAX_LOGON_MAILBOXES {
                return Err(RopError::Code(ErrorCode::TOO_MANY_OPEN_OBJECTS));
            }
        }
        let tree = if access == LogonAccess::Owner {
            self.materialize_specials(mailbox_id).await?
        } else {
            self.folder_tree(mailbox_id).await?
        };
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let folder_ids = SpecialFolders::new(mailbox.messages.as_deref())
            .logon_ids()
            .map(|id| visible_folder(&tree, id).to_eid());
        let time = now();
        let out_of_office = if self.types.contains(DataType::VacationResponse)
            && vacation_in_effect(
                self.request.server,
                mailbox_id,
                u64::try_from(time.0).unwrap_or(0),
            )
            .await?
        {
            RESPONSE_FLAG_OOF
        } else {
            0
        };
        self.state.release_logon(rop.header.logon_id);
        let handle = self.state.insert(
            rop.header.logon_id,
            ServerObject::Logon(LogonObject {
                mailbox_id,
                private: true,
                logon_flags: request.logon_flags,
                open_flags: request.open_flags,
            }),
        )?;
        self.set_output(index, handle)?;
        self.respond(
            rop,
            index,
            &LogonResponse::Private(LogonPrivateResponse {
                logon_flags: request.logon_flags,
                folder_ids,
                response_flags: access.response_flags() | out_of_office,
                mailbox_guid: guids.mailbox,
                repl_id: ReplId::LOCAL,
                repl_guid: guids.replica,
                logon_time: logon_time(time),
                gwart_time: 0,
            }),
        )
    }

    async fn materialize_specials(&mut self, mailbox_id: u32) -> trc::Result<Arc<FolderTree>> {
        let tree = self.folder_tree(mailbox_id).await?;
        let is_virtual = |folder| {
            tree.special(folder)
                .is_some_and(|entry| entry.node == FolderNode::Special(folder))
        };
        let groupware = self.types.contains(DataType::CalendarEvent);
        let tasks = groupware && is_virtual(SpecialFolder::Tasks);
        let calendar = groupware && is_virtual(SpecialFolder::Calendar);
        let mail = self.types.contains(DataType::Email);
        let notes = mail && is_virtual(SpecialFolder::Notes);
        let sync_issues = mail
            && (is_virtual(SpecialFolder::SyncIssues)
                || SYNC_ISSUES_FOLDERS.into_iter().any(is_virtual));
        if !tasks && !calendar && !notes && !sync_issues {
            return Ok(tree);
        }
        let server = self.request.server;
        let access_token = self.request.access_token;
        let mut created = false;
        if tasks {
            created |= special_created(
                server.folder_task_list(access_token, mailbox_id).await,
                mailbox_id,
                "MAPI logon kept the virtual Tasks folder",
            );
        }
        if calendar {
            created |= special_created(
                server.folder_event_calendar(access_token, mailbox_id).await,
                mailbox_id,
                "MAPI logon kept the virtual Calendar folder",
            );
        }
        if notes {
            created |= special_created(
                server.folder_notes(access_token, mailbox_id).await,
                mailbox_id,
                "MAPI logon kept the virtual Notes folder",
            );
        }
        if sync_issues {
            let result = server.folder_sync_issues(access_token, mailbox_id).await;
            let written = matches!(
                result,
                Ok(Ok(FolderWritten {
                    change_id: Some(_),
                    ..
                }))
            );
            special_created(
                result.map(|result| result.map(|written| written.folder)),
                mailbox_id,
                "MAPI logon kept a virtual Sync Issues folder",
            );
            created |= written;
        }
        if !created {
            return Ok(tree);
        }
        self.invalidate_mailbox();
        self.folder_tree(mailbox_id).await
    }

    pub async fn set_store_properties(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetProperties<'_>,
    ) -> RopResult {
        let mailbox_id = self.private_logon(rop)?;
        let may_set_oof = self.logon_access(mailbox_id) == Some(LogonAccess::Owner)
            && self.types.contains(DataType::VacationResponse);
        let mut problems = SmallVec::<[PropertyProblem; 8]>::new();
        let mut out_of_office = None;
        for (position, (tag, value)) in request.property_values.iter().enumerate() {
            let error = if is_computed_store_prop(tag) {
                ErrorCode::COMPUTED
            } else if tag == tags::OUT_OF_OFFICE_STATE && may_set_oof {
                if let PropValue::Bool(value) = value {
                    out_of_office = Some(value);
                    continue;
                }
                ErrorCode::INVALID_PARAM
            } else {
                ErrorCode::ACCESS_DENIED
            };
            problems.push(PropertyProblem {
                index: u16::try_from(position).unwrap_or(u16::MAX),
                tag,
                error,
            });
        }
        if let Some(out_of_office) = out_of_office {
            let edit = VacationEdit {
                state: Some(if out_of_office {
                    VacationState::Global
                } else {
                    VacationState::Disabled
                }),
                reply: None,
            };
            let request_ctx = self.request;
            let written = write_vacation(
                request_ctx.server,
                mailbox_id,
                request_ctx.access_token,
                &edit,
            )
            .await?;
            if written == VacationWrite::Busy {
                return Err(RopError::Code(ErrorCode::SERVER_BUSY));
            }
        }
        self.respond(
            rop,
            index,
            &SetPropertiesResponse {
                property_problems: &problems,
            },
        )
    }

    pub fn delete_store_properties(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &DeleteProperties<'_>,
    ) -> RopResult {
        self.private_logon(rop)?;
        if request.property_tags.iter().any(is_computed_store_prop) {
            return Err(RopError::Code(ErrorCode::ERROR));
        }
        self.respond(
            rop,
            index,
            &DeletePropertiesResponse {
                property_problems: &[],
            },
        )
    }

    async fn logon_view(&mut self, rop: &DecodedRop<'_>) -> Result<MailboxView, RopError> {
        let mailbox_id = self.logon_mailbox(rop)?;
        Ok(self.mailbox(mailbox_id).await?)
    }

    fn private_logon(&self, rop: &DecodedRop<'_>) -> Result<u32, RopError> {
        let handle = self.input(rop.header.input_handle)?;
        match self.state.get(handle) {
            Some(ServerObject::Logon(logon)) if logon.private => Ok(logon.mailbox_id),
            Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    async fn inbox(&mut self, mailbox_id: u32) -> Result<MapiId, RopError> {
        let mailbox = self.mailbox(mailbox_id).await?;
        Ok(SpecialFolders::new(mailbox.messages.as_deref()).inbox)
    }

    pub async fn get_receive_folder(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &GetReceiveFolder<'_>,
    ) -> RopResult {
        let mailbox_id = self.private_logon(rop)?;
        if !ReceiveFolder::is_valid_class(request.message_class) {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let inbox = self.inbox(mailbox_id).await?;
        let resolved = ReceiveFolder::resolve(request.message_class, inbox);
        self.respond(
            rop,
            index,
            &GetReceiveFolderResponse {
                folder_id: resolved.folder.to_eid(),
                explicit_message_class: resolved.message_class,
            },
        )
    }

    pub fn get_transport_folder(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        self.logon_mailbox(rop)?;
        self.respond(
            rop,
            index,
            &GetTransportFolderResponse {
                folder_id: fixed::OUTBOX.to_eid(),
            },
        )
    }

    pub async fn set_receive_folder(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetReceiveFolder<'_>,
    ) -> RopResult {
        let mailbox_id = self.private_logon(rop)?;
        let message_class = request.message_class;
        if !ReceiveFolder::is_valid_class(message_class) {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        if ReceiveFolder::is_protected_class(message_class) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let removes = request.folder_id == ZERO_EID;
        if !ReceiveFolder::is_mapped_class(message_class) {
            return if removes {
                self.respond_empty(rop, index)
            } else {
                Err(RopError::Code(ErrorCode::NOT_SUPPORTED))
            };
        }
        if removes && message_class.is_empty() {
            return Err(RopError::Code(ErrorCode::ERROR));
        }
        let inbox = self.inbox(mailbox_id).await?;
        if ReceiveFolder::resolve(message_class, inbox).folder.to_eid() == request.folder_id {
            self.respond_empty(rop, index)
        } else {
            Err(RopError::Code(ErrorCode::NOT_SUPPORTED))
        }
    }

    pub fn public_folder_is_ghosted(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        self.private_logon(rop)?;
        self.respond(rop, index, &NotGhostedResponse)
    }

    pub async fn get_receive_folder_table(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        let mailbox_id = self.private_logon(rop)?;
        let inbox = self.inbox(mailbox_id).await?;
        let modified = FileTime::from_utc(now(), 0);
        let options = table_row_options(false, self.code_page());
        let mut rows = self.writer.row_writer(
            ResponseHeader::new(rop.header.id.response_id(), index, ErrorCode::SUCCESS),
            RowSetLayout::ReceiveFolderTable,
            options,
        )?;
        for entry in ReceiveFolder::table(inbox) {
            let mut row = rows.row(&RECEIVE_FOLDER_COLUMNS, true)?;
            row.i64(i64::from_le_bytes(entry.folder.to_eid().to_wire()));
            row.string8(entry.message_class);
            row.time(modified);
        }
        rows.finish()?;
        Ok(())
    }

    pub fn get_per_user_long_term_ids(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        self.private_logon(rop)?;
        self.respond(rop, index, &EmptyLongTermIds)
    }

    pub async fn long_term_id_from_id(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &LongTermIdFromId,
    ) -> RopResult {
        let mailbox = self.logon_view(rop).await?;
        let guid = if request.object_id == ZERO_EID {
            None
        } else if request.object_id.replid == ReplId::LOCAL {
            Some(StoreGuids::new(mailbox.exchange.store_instance, mailbox.id).replica)
        } else {
            let guid = mailbox
                .exchange
                .replica_guid(request.object_id.replid.0)
                .ok_or(ErrorCode::NOT_FOUND)?;
            Some(ReplGuid(Guid(*guid)))
        };
        let long_term_id = guid.map_or(ZERO_LONG_TERM_ID, |guid| LongTermId {
            gid: Gid {
                guid,
                counter: request.object_id.counter,
            },
        });
        self.respond(rop, index, &LongTermIdFromIdResponse { long_term_id })
    }

    pub async fn id_from_long_term_id(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &IdFromLongTermId,
    ) -> RopResult {
        let mailbox = self.logon_view(rop).await?;
        let gid = &request.long_term_id.gid;
        let object_id = if gid.guid == ZERO_REPL_GUID {
            Eid::new(ZERO_REPLID, gid.counter)
        } else if gid.guid == StoreGuids::new(mailbox.exchange.store_instance, mailbox.id).replica {
            Eid::new(ReplId::LOCAL, gid.counter)
        } else {
            let guid = gid.guid.0.0;
            let replid = match mailbox.exchange.replica_id(&guid) {
                Some(replid) => replid,
                None => {
                    let (limit, exhausted) = if self.request.access_token.is_account_id(mailbox.id)
                    {
                        (MAX_FOREIGN_REPLICAS, ErrorCode::PARAMETER_OVERFLOW)
                    } else {
                        (DELEGATE_REPLICA_LIMIT, ErrorCode::NOT_FOUND)
                    };
                    let registered = self
                        .request
                        .server
                        .register_exchange_replica(mailbox.id, guid, limit)
                        .await?;
                    self.invalidate_mailbox();
                    registered.ok_or(exhausted)?
                }
            };
            Eid::new(ReplId(replid), gid.counter)
        };
        self.respond(rop, index, &IdFromLongTermIdResponse { object_id })
    }
}

fn is_computed_store_prop(tag: PropTag) -> bool {
    tag.id() == tags::CONTENT_COUNT.id() || tag.id() == tags::MESSAGE_SIZE.id()
}

fn now() -> UtcSeconds {
    UtcSeconds(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0)),
    )
}

fn logon_time(time: UtcSeconds) -> LogonTime {
    let days = time.0.div_euclid(SECONDS_PER_DAY);
    let seconds = time.0.rem_euclid(SECONDS_PER_DAY);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let narrow = |value: i64| u8::try_from(value).unwrap_or(0);
    LogonTime {
        seconds: narrow(seconds % 60),
        minutes: narrow(seconds % 3600 / 60),
        hour: narrow(seconds / 3600),
        day_of_week: narrow((days + 4).rem_euclid(7)),
        day: narrow(day),
        month: narrow(month),
        year: u16::try_from(year).unwrap_or(0),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/logon/tests.rs"]
mod tests;

fn special_created(
    result: trc::Result<Result<FolderRef, FolderWriteError>>,
    account_id: u32,
    details: &'static str,
) -> bool {
    let err = match result {
        Ok(Ok(_)) => return true,
        Ok(Err(err)) => trc::ResourceEvent::Error
            .into_err()
            .ctx(trc::Key::Reason, format!("{err:?}")),
        Err(err) => err,
    };
    trc::error!(
        err.account_id(account_id)
            .details(details)
            .caused_by(trc::location!())
    );
    false
}
