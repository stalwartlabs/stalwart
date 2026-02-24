/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

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
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let mut properties = request
            .properties
            .take()
            .map(|p| p.unwrap())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|prop| prop.try_unwrap())
            .collect::<AHashSet<_>>();
        if !properties.is_empty() {
            properties.insert(Property::Id);
        }

        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: None,
            list: vec![],
            not_found: vec![],
        };

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
                let flags = object_type.flags();
                let is_singleton = (flags & OBJ_SINGLETON) != 0;
                let is_tenant_filtered =
                    (flags & OBJ_FILTER_TENANT) != 0 && access_token.tenant_id().is_some();
                let is_account_filtered = (flags & OBJ_FILTER_ACCOUNT) != 0
                    && !access_token.has_permission(Permission::Impersonate);

                let ids = if let Some(ids) = ids {
                    ids
                } else {
                    self.registry()
                        .query::<AHashSet<u64>>(
                            RegistryQuery::new(object_type)
                                .with_tenant(access_token.tenant_id())
                                .with_account_opt(
                                    is_account_filtered.then_some(request.account_id.into()),
                                ),
                        )
                        .await
                        .caused_by(trc::location!())?
                        .into_iter()
                        .take(self.core.jmap.get_max_objects)
                        .map(Id::new)
                        .collect()
                };
                response.list.reserve(ids.len());

                'outer: for id in ids {
                    let object = if let Some(object) = self
                        .registry()
                        .get(ObjectId::new(object_type, id))
                        .await
                        .caused_by(trc::location!())?
                    {
                        object
                    } else if id.is_singleton() && is_singleton {
                        Object::new(ObjectInner::from(object_type))
                    } else {
                        response.not_found.push(id);
                        continue;
                    };

                    match &object.inner {
                        ObjectInner::DkimSignature(obj)
                            if properties.is_empty()
                                || properties.contains(&Property::PublicKey) =>
                        {
                            let todo = "dkim public key";
                            todo!()
                        }
                        ObjectInner::Domain(obj)
                            if properties.is_empty()
                                || properties.contains(&Property::DnsZoneFile) =>
                        {
                            let todo = "domain dns zone file";
                            todo!()
                        }
                        _ => {}
                    }

                    let todo = "compact pickle";
                    let todo = "app passwords, apis and user change pass/OTP";

                    let mut object = object.into_value();
                    let object_map = object.as_object_mut().unwrap();
                    if is_tenant_filtered && let Some(tenant_id) = access_token.tenant_id() {
                        let expected_value =
                            JmapValue::Element(RegistryValue::Id(Id::from(tenant_id)));
                        for (key, value) in object_map.iter() {
                            if matches!(key, Key::Property(Property::MemberTenantId))
                                && value != &expected_value
                            {
                                response.not_found.push(id);
                                continue 'outer;
                            }
                        }
                        object_map.remove(&Key::Property(Property::MemberTenantId));
                    } else if is_account_filtered {
                        let expected_value =
                            JmapValue::Element(RegistryValue::Id(request.account_id));
                        for (key, value) in object_map.iter() {
                            if matches!(key, Key::Property(Property::AccountId))
                                && value != &expected_value
                            {
                                response.not_found.push(id);
                                continue 'outer;
                            }
                        }
                        object_map.remove(&Key::Property(Property::AccountId));
                    }

                    object_map.insert_unchecked(Property::Id, RegistryValue::Id(id));
                    if !properties.is_empty() {
                        object_map.as_mut_vec().retain_mut(|(prop, _)| {
                            prop.as_property()
                                .is_some_and(|prop| properties.contains(prop))
                        });
                    }
                    response.list.push(object);
                }
            }
            ObjectType::Log => {}
            ObjectType::QueuedMessage => {}
            ObjectType::Task => {}
            ObjectType::ArfFeedbackReport => {}
            ObjectType::DmarcReport => {}
            ObjectType::TlsReport => {}
            ObjectType::DeletedItem => {}
            ObjectType::Metric => {}
            ObjectType::Trace => {}
            ObjectType::SpamTrainingSample => {}
        }

        Ok(response)
    }
}
