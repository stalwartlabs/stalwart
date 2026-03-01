/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{
    RegistryGetResponse,
    account::account_get,
    deleted_item::deleted_item_get,
    log::log_get,
    queued_message::queued_message_get,
    report::report_get,
    spam_sample::spam_sample_get,
    task::task_get,
    telemetry::{metric_get, trace_get},
};
use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::registry::Registry,
};
use jmap_tools::Key;
use registry::{
    jmap::{IntoValue, JmapValue, RegistryValue},
    schema::{
        enums::Permission,
        prelude::{
            OBJ_FILTER_ACCOUNT, OBJ_FILTER_TENANT, OBJ_SINGLETON, Object, ObjectInner, ObjectType,
            Property,
        },
    },
    types::id::ObjectId,
};
use store::{ahash::AHashSet, registry::RegistryQuery};
use trc::AddContext;
use types::id::Id;

pub trait RegistryGet: Sync + Send {
    fn registry_get(
        &self,
        object_type: ObjectType,
        request: GetRequest<Registry>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<Registry>>> + Send;
}

impl RegistryGet for Server {
    async fn registry_get(
        &self,
        object_type: ObjectType,
        mut request: GetRequest<Registry>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<Registry>> {
        let object_flags = object_type.flags();
        let is_tenant_filtered =
            (object_flags & OBJ_FILTER_TENANT) != 0 && access_token.tenant_id().is_some();
        let is_account_filtered = (object_flags & OBJ_FILTER_ACCOUNT) != 0
            && !access_token.has_permission(Permission::Impersonate);
        let mut get = RegistryGetResponse {
            access_token,
            server: self,
            account_id: request.account_id.document_id(),
            object_type,
            ids: request.unwrap_ids(self.core.jmap.get_max_objects)?,
            properties: request
                .properties
                .take()
                .map(|p| p.unwrap())
                .unwrap_or_default()
                .into_iter()
                .filter_map(|prop| prop.try_unwrap())
                .collect::<AHashSet<_>>(),
            response: GetResponse {
                account_id: request.account_id.into(),
                state: None,
                list: vec![],
                not_found: vec![],
            },
            object_flags,
            is_tenant_filtered,
            is_account_filtered,
        };
        if !get.properties.is_empty() {
            get.properties.insert(Property::Id);
        }

        match object_type {
            ObjectType::AcmeProvider
            | ObjectType::AddressBook
            | ObjectType::AiModel
            | ObjectType::Alert
            | ObjectType::AllowedIp
            | ObjectType::Application
            | ObjectType::Asn
            | ObjectType::Authentication
            | ObjectType::BlobStore
            | ObjectType::BlockedIp
            | ObjectType::Cache
            | ObjectType::Calendar
            | ObjectType::CalendarAlarm
            | ObjectType::CalendarScheduling
            | ObjectType::Certificate
            | ObjectType::Coordinator
            | ObjectType::DataRetention
            | ObjectType::DataStore
            | ObjectType::Directory
            | ObjectType::DkimReportSettings
            | ObjectType::DmarcReportSettings
            | ObjectType::DnsResolver
            | ObjectType::DnsServer
            | ObjectType::Email
            | ObjectType::Enterprise
            | ObjectType::EventTracingLevel
            | ObjectType::FileStorage
            | ObjectType::Http
            | ObjectType::HttpForm
            | ObjectType::HttpLookup
            | ObjectType::Imap
            | ObjectType::InMemoryStore
            | ObjectType::Jmap
            | ObjectType::LocalSettings
            | ObjectType::MemoryLookupKey
            | ObjectType::MemoryLookupKeyValue
            | ObjectType::Metrics
            | ObjectType::MetricsStore
            | ObjectType::MtaConnectionStrategy
            | ObjectType::MtaDeliverySchedule
            | ObjectType::MtaExtensions
            | ObjectType::MtaHook
            | ObjectType::MtaInboundSession
            | ObjectType::MtaInboundThrottle
            | ObjectType::MtaMilter
            | ObjectType::MtaOutboundStrategy
            | ObjectType::MtaOutboundThrottle
            | ObjectType::MtaQueueQuota
            | ObjectType::MtaRoute
            | ObjectType::MtaStageAuth
            | ObjectType::MtaStageConnect
            | ObjectType::MtaStageData
            | ObjectType::MtaStageEhlo
            | ObjectType::MtaStageMail
            | ObjectType::MtaStageRcpt
            | ObjectType::MtaSts
            | ObjectType::MtaTlsStrategy
            | ObjectType::MtaVirtualQueue
            | ObjectType::NetworkListener
            | ObjectType::Node
            | ObjectType::NodeRole
            | ObjectType::NodeShard
            | ObjectType::OidcProvider
            | ObjectType::RegistryBundle
            | ObjectType::ReportSettings
            | ObjectType::Search
            | ObjectType::SearchStore
            | ObjectType::Security
            | ObjectType::SenderAuth
            | ObjectType::Sharing
            | ObjectType::SieveSystemInterpreter
            | ObjectType::SieveSystemScript
            | ObjectType::SieveUserInterpreter
            | ObjectType::SieveUserScript
            | ObjectType::SpamClassifier
            | ObjectType::SpamDnsblServer
            | ObjectType::SpamDnsblSettings
            | ObjectType::SpamFileExtension
            | ObjectType::SpamLlm
            | ObjectType::SpamPyzor
            | ObjectType::SpamRule
            | ObjectType::SpamSettings
            | ObjectType::SpamTag
            | ObjectType::SpfReportSettings
            | ObjectType::StoreLookup
            | ObjectType::TaskManager
            | ObjectType::TlsReportSettings
            | ObjectType::Tracer
            | ObjectType::TracingStore
            | ObjectType::WebDav
            | ObjectType::WebHook
            | ObjectType::Account
            | ObjectType::DsnReportSettings
            | ObjectType::MailingList
            | ObjectType::OAuthClient
            | ObjectType::Role
            | ObjectType::Tenant
            | ObjectType::MaskedEmail
            | ObjectType::PublicKey
            | ObjectType::DkimSignature
            | ObjectType::Domain => {
                let is_singleton = (get.object_flags & OBJ_SINGLETON) != 0;

                let ids = if let Some(ids) = get.ids.take() {
                    ids
                } else {
                    let mut ids = self
                        .registry()
                        .query::<AHashSet<u64>>(
                            RegistryQuery::new(object_type)
                                .with_tenant(access_token.tenant_id())
                                .with_account_opt(is_account_filtered.then_some(get.account_id)),
                        )
                        .await
                        .caused_by(trc::location!())?
                        .into_iter()
                        .take(self.core.jmap.get_max_objects)
                        .map(Id::new)
                        .collect::<Vec<_>>();
                    ids.sort_unstable();
                    ids
                };
                get.response.list.reserve(ids.len());

                for id in ids {
                    let object = if let Some(object) = self
                        .registry()
                        .get(ObjectId::new(object_type, id))
                        .await
                        .caused_by(trc::location!())?
                    {
                        if (is_tenant_filtered
                            && access_token.tenant_id().map(Id::from)
                                != object.inner.member_tenant_id())
                            || (is_account_filtered
                                && object.inner.account_id() != Some(Id::from(get.account_id)))
                        {
                            get.not_found(id);
                            continue;
                        }
                        object
                    } else if id.is_singleton() && is_singleton {
                        Object::from(object_type)
                    } else {
                        get.not_found(id);
                        continue;
                    };

                    match &object.inner {
                        ObjectInner::DkimSignature(obj)
                            if get.properties.is_empty()
                                || get.properties.contains(&Property::PublicKey) =>
                        {
                            let todo = "dkim public key";
                            todo!()
                        }
                        ObjectInner::Domain(obj)
                            if get.properties.is_empty()
                                || get.properties.contains(&Property::DnsZoneFile) =>
                        {
                            let todo = "domain dns zone file";
                            todo!()
                        }
                        _ => {}
                    }

                    get.insert(id, object.into_value());
                }

                Ok(get.into_response())
            }
            ObjectType::QueuedMessage => {
                queued_message_get(get).await.map(|get| get.into_response())
            }
            ObjectType::Task => task_get(get).await.map(|get| get.into_response()),

            ObjectType::ArfExternalReport
            | ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::DmarcInternalReport
            | ObjectType::TlsInternalReport => report_get(get).await.map(|get| get.into_response()),

            ObjectType::DeletedItem => deleted_item_get(get).await.map(|get| get.into_response()),
            ObjectType::SpamTrainingSample => {
                spam_sample_get(get).await.map(|get| get.into_response())
            }
            ObjectType::Metric => metric_get(get).await.map(|get| get.into_response()),
            ObjectType::Trace => trace_get(get).await.map(|get| get.into_response()),
            ObjectType::Log => log_get(get).await.map(|get| get.into_response()),
            ObjectType::AccountSettings | ObjectType::Credential => {
                account_get(get).await.map(|get| get.into_response())
            }
        }
    }
}

impl RegistryGetResponse<'_> {
    pub fn insert(&mut self, id: Id, mut object: JmapValue<'static>) {
        let object_map = object.as_object_mut().unwrap();

        if self.is_tenant_filtered
            && let Some(tenant_id) = self.access_token.tenant_id()
        {
            let expected_value = JmapValue::Element(RegistryValue::Id(Id::from(tenant_id)));
            for (key, value) in object_map.iter() {
                if matches!(key, Key::Property(Property::MemberTenantId))
                    && (value != &expected_value
                        || value
                            .as_array()
                            .is_none_or(|arr| !arr.contains(&expected_value)))
                {
                    self.not_found(id);
                    return;
                }
            }
            object_map.remove(&Key::Property(Property::MemberTenantId));
        } else if self.is_account_filtered {
            let expected_value = JmapValue::Element(RegistryValue::Id(self.account_id.into()));
            for (key, value) in object_map.iter() {
                if matches!(key, Key::Property(Property::AccountId)) && value != &expected_value {
                    self.not_found(id);
                    return;
                }
            }
            object_map.remove(&Key::Property(Property::AccountId));
        }

        object_map.insert_unchecked(Property::Id, RegistryValue::Id(id));
        if !self.properties.is_empty() {
            object_map.as_mut_vec().retain_mut(|(prop, _)| {
                prop.as_property()
                    .is_some_and(|prop| self.properties.contains(prop))
            });
        }
        self.response.list.push(object);
    }

    pub fn not_found(&mut self, id: Id) {
        self.response.not_found.push(id);
    }

    pub fn not_found_any(mut self) -> Self {
        self.response.not_found = self.ids.take().unwrap_or_default();
        self
    }

    pub fn into_response(self) -> GetResponse<Registry> {
        self.response
    }
}
