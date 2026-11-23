/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod fai;
mod streams;

use self::{
    fai::{find_config, find_config_id},
    streams::{StreamKeys, Streams},
};
use super::{
    context::{EwsCaller, EwsContext},
    folder::{FolderSelector, resolve_folder},
    reply::{RESPONSE_CAPACITY, ews_response},
};
use crate::{
    eas::folder_sync::MAX_STATE_ATTEMPTS,
    folders::FolderNode,
    mapi::emsmdb::message::fai::fai_data_type,
    store::{
        ExchangeProperty, FolderKind, FolderRef,
        account::ExchangeAccountStore,
        folder::{FaiChange, FaiCommit, FaiFolder, FaiKind, FaiMessage, FolderStore},
        object::ObjectVersion,
    },
};
use common::Server;
use exchange_proto::{
    convert::{roaming::decode_dictionary, work_hours::WorkHours},
    ews::{
        EwsLimits, MessageResult, Operation, ResponseMessage, Status,
        requests::config::{DeleteUserConfiguration, GetUserConfiguration, UserConfigurationWrite},
        responses::{config::GetUserConfigurationMessage, folder::EmptyMessage},
        schema::{ResponseCode, UserConfigurationProperty},
        types::{
            config::{UserConfiguration, UserConfigurationName},
            ids::TargetFolderId,
            value::XBinary,
        },
    },
    ids::ews::EwsObjectId,
    mapi::prop::{PropTag, tags},
};
use http_proto::HttpResponse;
use store::write::serialize::rkyv_deserialize;
use trc::{AddContext, EventType, LimitEvent};
use types::type_state::DataType;

const CONFIGURATION_CLASS: &str = "IPM.Configuration.";
const WORK_HOURS: ConfigName<'static> = ConfigName("WorkHours");
const RESERVED_PREFIX: &str = "IPM.Configuration";
const MAX_NAME_LEN: usize = 236;
const MAX_DICTIONARY_ENTRIES: usize = EwsLimits::DEFAULT.max_ids as usize;
const BASE64_BLOCK_LEN: usize = 3;
const STREAM_TAGS: [PropTag; 3] = [
    tags::ROAMING_DICTIONARY,
    tags::ROAMING_XML_STREAM,
    tags::ROAMING_BINARY_STREAM,
];

const NOT_FOUND: &str = "The user configuration object was not found.";
const EXISTS: &str = "A user configuration object with this name already exists.";
const INVALID_NAME: &str = "The user configuration name is invalid.";
const INVALID_VALUE: &str = "The user configuration contains an invalid value.";
const ACCESS_DENIED: &str = "User configuration objects are only available in your own mailbox.";
const FOLDER_NOT_FOUND: &str = "The specified folder could not be found in the store.";
const TOO_LARGE: &str = "The user configuration object exceeds the maximum size.";
const QUOTA: &str = "The mailbox quota is exceeded.";
const STALE: &str = "The user configuration object changed while it was being saved.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigError {
    NotFound,
    Exists,
    InvalidName,
    InvalidValue,
    AccessDenied,
    FolderNotFound,
    TooLarge,
    Quota,
    Stale,
}

impl ConfigError {
    fn status(self) -> Status<'static> {
        match self {
            ConfigError::NotFound => Status::error(ResponseCode::ErrorItemNotFound, NOT_FOUND),
            ConfigError::Exists => Status::error(ResponseCode::ErrorItemSave, EXISTS),
            ConfigError::InvalidName => {
                Status::error(ResponseCode::ErrorInvalidArgument, INVALID_NAME)
            }
            ConfigError::InvalidValue => {
                Status::error(ResponseCode::ErrorInvalidArgument, INVALID_VALUE)
            }
            ConfigError::AccessDenied => {
                Status::error(ResponseCode::ErrorAccessDenied, ACCESS_DENIED)
            }
            ConfigError::FolderNotFound => {
                Status::error(ResponseCode::ErrorFolderNotFound, FOLDER_NOT_FOUND)
            }
            ConfigError::TooLarge => Status::error(ResponseCode::ErrorItemSave, TOO_LARGE),
            ConfigError::Quota => Status::error(ResponseCode::ErrorQuotaExceeded, QUOTA),
            ConfigError::Stale => Status::error(ResponseCode::ErrorIrresolvableConflict, STALE),
        }
    }

    fn from_write(err: trc::Error) -> trc::Result<Self> {
        match err.as_ref() {
            EventType::Limit(LimitEvent::SizeRequest) => Ok(ConfigError::TooLarge),
            EventType::Limit(LimitEvent::Quota) => Ok(ConfigError::Quota),
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota) => Ok(ConfigError::Quota),
            _ => Err(err),
        }
    }
}

type Outcome<T> = trc::Result<Result<T, ConfigError>>;

#[derive(Clone, Copy)]
struct ConfigName<'x>(&'x str);

impl<'x> ConfigName<'x> {
    fn parse(name: &'x str) -> Result<Self, ConfigError> {
        let reserved = name
            .as_bytes()
            .get(..RESERVED_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(RESERVED_PREFIX.as_bytes()));
        if (1..=MAX_NAME_LEN).contains(&name.len())
            && !reserved
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
        {
            Ok(ConfigName(name))
        } else {
            Err(ConfigError::InvalidName)
        }
    }

    fn message_class(self) -> String {
        let mut class = String::with_capacity(CONFIGURATION_CLASS.len() + self.0.len());
        class.push_str(CONFIGURATION_CLASS);
        class.push_str(self.0);
        class
    }

    fn matches(self, class: &str) -> bool {
        class
            .as_bytes()
            .split_at_checked(CONFIGURATION_CLASS.len())
            .is_some_and(|(prefix, name)| {
                prefix.eq_ignore_ascii_case(CONFIGURATION_CLASS.as_bytes())
                    && name.eq_ignore_ascii_case(self.0.as_bytes())
            })
    }
}

async fn config_folder(
    server: &Server,
    ctx: &EwsContext,
    folder: &TargetFolderId<'_>,
) -> Outcome<FaiFolder> {
    let account_id = ctx.account.account_id;
    let foreign = match folder {
        TargetFolderId::Folder(id) => matches!(
            EwsObjectId::decode(id.id.as_str()),
            Some(EwsObjectId::Folder { account, .. }) if account != account_id
        ),
        TargetFolderId::Distinguished(id) => match id
            .mailbox
            .as_ref()
            .and_then(|mailbox| mailbox.email_address.as_deref())
            .filter(|address| !address.is_empty())
        {
            Some(address) => {
                server.account_id_from_email(address, false).await? != Some(account_id)
            }
            None => false,
        },
        TargetFolderId::AddressList(_) => return Ok(Err(ConfigError::FolderNotFound)),
    };
    if foreign {
        return Ok(Err(ConfigError::AccessDenied));
    }
    let tree = ctx.folder_tree(server).await?;
    let Ok(entry) = resolve_folder(server, ctx, &tree, FolderSelector::from(folder)).await? else {
        return Ok(Err(ConfigError::FolderNotFound));
    };
    let data_type = fai_node_data_type(entry.node);
    Ok(FaiFolder::new(entry.node)
        .filter(|_| ctx.account.data_types.contains(data_type))
        .ok_or(ConfigError::FolderNotFound))
}

pub(crate) fn fai_node_data_type(node: FolderNode) -> DataType {
    match node {
        FolderNode::Stored(folder) => fai_data_type(folder.kind),
        FolderNode::Special(_) => DataType::Email,
    }
}

pub(crate) async fn calendar_work_hours(
    server: &Server,
    account_id: u32,
    calendar_id: u32,
) -> trc::Result<Option<WorkHours>> {
    let folder = FaiFolder::from(FolderRef {
        kind: FolderKind::Calendar,
        id: calendar_id,
    });
    let mut work_hours = None;
    server
        .fai_messages(account_id, folder, |_, message| {
            if !WORK_HOURS.matches(message.message_class.as_str()) {
                return Ok(true);
            }
            work_hours = Streams::from_stored(message.properties.as_slice())
                .xml
                .as_deref()
                .and_then(WorkHours::parse);
            Ok(work_hours.is_none())
        })
        .await
        .caused_by(trc::location!())?;
    Ok(work_hours)
}

pub(crate) async fn get_user_configuration(
    server: &Server,
    ctx: &EwsContext,
    request: &GetUserConfiguration<'_>,
) -> trc::Result<HttpResponse> {
    let target = &request.user_configuration_name;
    let streams = match read_config(server, ctx, target).await? {
        Ok(streams) => streams,
        Err(err) => {
            return Ok(config_response(
                ctx,
                Operation::GetUserConfiguration,
                MessageResult::<GetUserConfigurationMessage> {
                    status: err.status(),
                    body: None,
                },
            ));
        }
    };
    let properties = request.user_configuration_properties;
    let wants = |property| {
        properties.contains(property) || properties.contains(UserConfigurationProperty::All)
    };
    let configuration = UserConfiguration {
        name: target.clone(),
        item_id: None,
        dictionary: streams
            .dictionary
            .as_deref()
            .filter(|_| wants(UserConfigurationProperty::Dictionary))
            .and_then(|stream| decode_dictionary(stream, MAX_DICTIONARY_ENTRIES)),
        xml_data: streams
            .xml
            .as_deref()
            .filter(|_| wants(UserConfigurationProperty::XmlData))
            .map(XBinary::Borrowed),
        binary_data: streams
            .binary
            .as_deref()
            .filter(|_| wants(UserConfigurationProperty::BinaryData))
            .map(XBinary::Borrowed),
    };
    Ok(config_response(
        ctx,
        Operation::GetUserConfiguration,
        MessageResult {
            status: Status::SUCCESS,
            body: Some(GetUserConfigurationMessage {
                configuration: Some(configuration),
            }),
        },
    ))
}

async fn read_config(
    server: &Server,
    ctx: &EwsContext,
    target: &UserConfigurationName<'_>,
) -> Outcome<Streams> {
    let (name, folder) = match target_of(server, ctx, target).await? {
        Ok(target) => target,
        Err(err) => return Ok(Err(err)),
    };
    let account_id = ctx.account.account_id;
    let mut streams = None;
    server
        .fai_messages(account_id, folder, |_, message| {
            if name.matches(message.message_class.as_str()) {
                streams = Some(Streams::from_stored(message.properties.as_slice()));
                Ok(false)
            } else {
                Ok(true)
            }
        })
        .await
        .caused_by(trc::location!())?;
    Ok(streams.ok_or(ConfigError::NotFound))
}

pub(crate) async fn create_user_configuration(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &UserConfigurationWrite<'_>,
) -> trc::Result<HttpResponse> {
    let status = match create_config(server, ctx, caller, &request.user_configuration).await? {
        Ok(()) => Status::SUCCESS,
        Err(err) => err.status(),
    };
    Ok(status_response(
        ctx,
        Operation::CreateUserConfiguration,
        status,
    ))
}

async fn create_config(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    configuration: &UserConfiguration<'_>,
) -> Outcome<()> {
    let (name, folder) = match target_of(server, ctx, &configuration.name).await? {
        Ok(target) => target,
        Err(err) => return Ok(Err(err)),
    };
    let streams = match Streams::from_request(configuration, server.core.exchange.max_object_size) {
        Ok(streams) => streams,
        Err(err) => return Ok(Err(err)),
    };
    let message = FaiMessage {
        change: 0,
        message_class: name.message_class(),
        properties: streams.into_properties(Vec::new()),
        recipients: Vec::new(),
        conflict: None,
        kind: FaiKind::Associated,
    };
    let account_id = ctx.account.account_id;
    let owner = server
        .exchange_quota_owner(caller.access_token, account_id)
        .await?;
    for _ in 0..MAX_STATE_ATTEMPTS {
        if find_config_id(server, account_id, folder, name)
            .await?
            .is_some()
        {
            return Ok(Err(ConfigError::Exists));
        }
        let change = FaiChange::Create {
            message: message.clone(),
            version: ObjectVersion::Server,
        };
        match server.commit_fai(owner, folder, change).await {
            Ok(FaiCommit::Written { .. }) => return Ok(Ok(())),
            Ok(FaiCommit::Conflict) => {}
            Err(err) => return ConfigError::from_write(err).map(Err),
        }
    }
    Ok(Err(ConfigError::Stale))
}

pub(crate) async fn update_user_configuration(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &UserConfigurationWrite<'_>,
) -> trc::Result<HttpResponse> {
    let status = match update_config(server, ctx, caller, &request.user_configuration).await? {
        Ok(()) => Status::SUCCESS,
        Err(err) => err.status(),
    };
    Ok(status_response(
        ctx,
        Operation::UpdateUserConfiguration,
        status,
    ))
}

async fn update_config(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    configuration: &UserConfiguration<'_>,
) -> Outcome<()> {
    let (name, folder) = match target_of(server, ctx, &configuration.name).await? {
        Ok(target) => target,
        Err(err) => return Ok(Err(err)),
    };
    let provided = match Streams::from_request(configuration, server.core.exchange.max_object_size)
    {
        Ok(streams) => streams,
        Err(err) => return Ok(Err(err)),
    };
    let account_id = ctx.account.account_id;
    let owner = server
        .exchange_quota_owner(caller.access_token, account_id)
        .await?;
    let keys = StreamKeys::new();
    for _ in 0..MAX_STATE_ATTEMPTS {
        let Some((id, row)) = find_config(server, account_id, folder, name).await? else {
            return Ok(Err(ConfigError::NotFound));
        };
        let previous = row.unarchive::<FaiMessage>()?;
        let mut streams = Streams::from_stored(previous.properties.as_slice());
        for (stream, replacement) in [
            (&mut streams.dictionary, &provided.dictionary),
            (&mut streams.xml, &provided.xml),
            (&mut streams.binary, &provided.binary),
        ] {
            if replacement.is_some() {
                stream.clone_from(replacement);
            }
        }
        let kept = previous
            .properties
            .iter()
            .filter(|property| !keys.is_roaming(property.key.as_slice()))
            .map(|property| ExchangeProperty {
                key: property.key.as_slice().to_vec(),
                value: property.value.as_slice().to_vec(),
            })
            .collect();
        let message = FaiMessage {
            change: 0,
            message_class: previous.message_class.as_str().into(),
            properties: streams.into_properties(kept),
            recipients: rkyv_deserialize(&previous.recipients)?,
            conflict: None,
            kind: FaiKind::Associated,
        };
        let change = FaiChange::Update {
            id,
            previous: &row,
            message,
            version: ObjectVersion::Server,
        };
        match server.commit_fai(owner, folder, change).await {
            Ok(FaiCommit::Written { .. }) => return Ok(Ok(())),
            Ok(FaiCommit::Conflict) => {}
            Err(err) => return ConfigError::from_write(err).map(Err),
        }
    }
    Ok(Err(ConfigError::Stale))
}

pub(crate) async fn delete_user_configuration(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &DeleteUserConfiguration<'_>,
) -> trc::Result<HttpResponse> {
    let status = match delete_config(server, ctx, caller, &request.user_configuration_name).await? {
        Ok(()) => Status::SUCCESS,
        Err(err) => err.status(),
    };
    Ok(status_response(
        ctx,
        Operation::DeleteUserConfiguration,
        status,
    ))
}

async fn delete_config(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    target: &UserConfigurationName<'_>,
) -> Outcome<()> {
    let (name, folder) = match target_of(server, ctx, target).await? {
        Ok(target) => target,
        Err(err) => return Ok(Err(err)),
    };
    let account_id = ctx.account.account_id;
    let owner = server
        .exchange_quota_owner(caller.access_token, account_id)
        .await?;
    for _ in 0..MAX_STATE_ATTEMPTS {
        let Some((id, row)) = find_config(server, account_id, folder, name).await? else {
            return Ok(Err(ConfigError::NotFound));
        };
        let change = FaiChange::Delete { id, previous: &row };
        match server.commit_fai(owner, folder, change).await {
            Ok(FaiCommit::Written { .. }) => return Ok(Ok(())),
            Ok(FaiCommit::Conflict) => {}
            Err(err) => return ConfigError::from_write(err).map(Err),
        }
    }
    Ok(Err(ConfigError::Stale))
}

async fn target_of<'x>(
    server: &Server,
    ctx: &EwsContext,
    target: &'x UserConfigurationName<'_>,
) -> Outcome<(ConfigName<'x>, FaiFolder)> {
    let name = match ConfigName::parse(&target.name) {
        Ok(name) => name,
        Err(err) => return Ok(Err(err)),
    };
    Ok(config_folder(server, ctx, &target.folder)
        .await?
        .map(|folder| (name, folder)))
}

fn config_response<R: ResponseMessage>(
    ctx: &EwsContext,
    operation: Operation,
    result: MessageResult<'_, R>,
) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(operation);
    messages.message(&result);
    messages.finish();
    ews_response(out)
}

fn status_response(
    ctx: &EwsContext,
    operation: Operation,
    status: Status<'static>,
) -> HttpResponse {
    config_response(
        ctx,
        operation,
        MessageResult::<EmptyMessage> { status, body: None },
    )
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/config/tests.rs"]
mod tests;
