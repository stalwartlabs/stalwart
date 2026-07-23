/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::{
    EnterpriseRegistry,
    mapping::{
        RegistryGetResponse, account::account_get, bootstrap::bootstrap_get,
        cluster::cluster_node_get, log::log_get, queued_message::queued_message_get,
        report::report_get, spam_sample::spam_sample_get, task::task_get,
    },
};
use common::{Server, auth::AccessToken, network::dkim::generate_dkim_public_key};
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
        structs::Account,
    },
    types::id::ObjectId,
};
use store::{ahash::AHashSet, registry::RegistryQuery};
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

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
        // Initial assertions
        if self.registry().is_bootstrap_mode() && !matches!(object_type, ObjectType::Bootstrap) {
            return Err(trc::JmapEvent::Forbidden.into_err().details(concat!(
                "The server is in bootstrap mode. Only the 'Bootstrap' object type ",
                "can be accessed until the bootstrap process is complete.",
            )));
        }
        self.assert_enterprise_object(object_type)?;

        let object_flags = object_type.flags();
        let is_tenant_filtered =
            (object_flags & OBJ_FILTER_TENANT) != 0 && access_token.tenant_id().is_some();
        let is_account_filtered = (object_flags & OBJ_FILTER_ACCOUNT) != 0
            && !access_token.has_permission(Permission::Impersonate);
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let mut get = RegistryGetResponse {
            access_token,
            server: self,
            account_id: request.account_id.document_id(),
            object_type,
            ids,
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
                not_found: not_found_ids,
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
            | ObjectType::SystemSettings
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
            | ObjectType::ClusterRole
            | ObjectType::OidcProvider
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
                    self.registry()
                        .query::<Vec<Id>>(
                            RegistryQuery::new(object_type)
                                .with_tenant(access_token.tenant_id())
                                .with_account_opt(is_account_filtered.then_some(get.account_id))
                                .with_limit(self.core.jmap.get_max_objects),
                        )
                        .await
                        .caused_by(trc::location!())?
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

                    let mut extra_properties: VecMap<Property, _> = VecMap::new();
                    match &object.inner {
                        ObjectInner::DkimSignature(obj)
                            if get.properties.is_empty()
                                || get.properties.contains(&Property::PublicKey) =>
                        {
                            if let Ok(public_key) = generate_dkim_public_key(obj).await {
                                extra_properties
                                    .append(Property::PublicKey, JmapValue::Str(public_key.into()));
                            }
                        }
                        ObjectInner::Account(obj) => {
                            if get.properties.is_empty()
                                || get.properties.contains(&Property::UsedDiskQuota)
                            {
                                let quota = self.get_used_quota_account(id.document_id()).await?;
                                extra_properties.append(
                                    Property::UsedDiskQuota,
                                    JmapValue::Number(quota.into()),
                                );
                            }
                            if get.properties.is_empty()
                                || get.properties.contains(&Property::EmailAddress)
                            {
                                let (name, domain_id) = match &obj {
                                    Account::User(obj) => (obj.name.as_str(), obj.domain_id),
                                    Account::Group(obj) => (obj.name.as_str(), obj.domain_id),
                                };
                                let domain = self.domain_by_id(domain_id.document_id()).await?;
                                let email = format!(
                                    "{}@{}",
                                    name,
                                    domain.as_ref().map(|d| d.name()).unwrap_or_default()
                                );
                                extra_properties
                                    .append(Property::EmailAddress, JmapValue::Str(email.into()));
                            }
                        }
                        ObjectInner::MailingList(obj)
                            if get.properties.is_empty()
                                || get.properties.contains(&Property::EmailAddress) =>
                        {
                            let domain = self.domain_by_id(obj.domain_id.document_id()).await?;
                            let email = format!(
                                "{}@{}",
                                obj.name,
                                domain.as_ref().map(|d| d.name()).unwrap_or_default()
                            );
                            extra_properties
                                .append(Property::EmailAddress, JmapValue::Str(email.into()));
                        }
                        ObjectInner::Tenant(obj)
                            if get.properties.is_empty()
                                || get.properties.contains(&Property::UsedDiskQuota) =>
                        {
                            let quota = self.get_used_quota_tenant(id.document_id()).await?;
                            extra_properties
                                .append(Property::UsedDiskQuota, JmapValue::Number(quota.into()));
                        }
                        ObjectInner::Domain(obj)
                            if get.properties.is_empty()
                                || get.properties.contains(&Property::DnsZoneFile) =>
                        {
                            extra_properties.append(
                                Property::DnsZoneFile,
                                JmapValue::Str(self.build_bind_dns_records(id, obj).await?.into()),
                            );
                        }
                        _ => {}
                    }

                    let mut object = object.into_value();
                    if !extra_properties.is_empty()
                        && let JmapValue::Object(obj) = &mut object
                    {
                        for (key, value) in extra_properties {
                            obj.insert_unchecked(key, value);
                        }
                    }

                    get.insert(id, object);
                }

                Ok(get.into_response())
            }
            ObjectType::QueuedMessage => {
                queued_message_get(get).await.map(|get| get.into_response())
            }
            ObjectType::Task => task_get(get).await.map(|get| get.into_response()),
            ObjectType::ClusterNode => cluster_node_get(get).await.map(|get| get.into_response()),
            ObjectType::ArfExternalReport
            | ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::DmarcInternalReport
            | ObjectType::TlsInternalReport => report_get(get).await.map(|get| get.into_response()),

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => {
                crate::registry::mapping::archived_item::archived_item_get(get)
                    .await
                    .map(|get| get.into_response())
            }
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => crate::registry::mapping::telemetry::metric_get(get)
                .await
                .map(|get| get.into_response()),
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => crate::registry::mapping::telemetry::trace_get(get)
                .await
                .map(|get| get.into_response()),
            // SPDX-SnippetEnd
            ObjectType::SpamTrainingSample => {
                spam_sample_get(get).await.map(|get| get.into_response())
            }
            ObjectType::Log => log_get(get).await.map(|get| get.into_response()),
            ObjectType::Bootstrap => bootstrap_get(get).await.map(|get| get.into_response()),
            ObjectType::AccountSettings
            | ObjectType::ApiKey
            | ObjectType::AccountPassword
            | ObjectType::AppPassword => account_get(get).await.map(|get| get.into_response()),
            ObjectType::Action => Ok(get.not_found_any().into_response()),
            #[cfg(not(feature = "enterprise"))]
            _ => Ok(get.not_found_any().into_response()),
        }
    }
}

impl RegistryGetResponse<'_> {
    pub fn insert(&mut self, id: Id, mut object: JmapValue<'static>) {
        let object_map = object.as_object_mut().unwrap();

        if self.is_tenant_filtered && self.access_token.tenant_id().is_some() {
            object_map.remove(&Key::Property(Property::MemberTenantId));
        } else if self.is_account_filtered {
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
        self.response.push_not_found(id);
    }

    pub fn not_found_any(mut self) -> Self {
        for id in self.ids.take().unwrap_or_default() {
            self.response.push_not_found(id);
        }
        self
    }

    pub fn into_response(self) -> GetResponse<Registry> {
        self.response
    }
}
