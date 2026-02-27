/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::RegistrySetResponse;
use common::{Server, auth::AccessToken};
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::registry::Registry,
    request::IntoValid,
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key};
use registry::{
    jmap::JsonPointerPatch,
    schema::{
        enums::Permission,
        prelude::{
            OBJ_FILTER_ACCOUNT, OBJ_FILTER_TENANT, OBJ_SINGLETON, Object, ObjectType, Property,
        },
    },
    types::id::ObjectId,
};
use trc::AddContext;
use types::id::Id;

pub trait RegistrySet: Sync + Send {
    fn registry_set(
        &self,
        object_type: ObjectType,
        request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse<Registry>>> + Send;
}

enum Modification {
    Create(String),
    Update(Id),
}

impl RegistrySet for Server {
    async fn registry_set(
        &self,
        object_type: ObjectType,
        mut request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse<Registry>> {
        let object_flags = object_type.flags();
        let is_singleton = (object_flags & OBJ_SINGLETON) != 0;
        let is_tenant_filtered =
            (object_flags & OBJ_FILTER_TENANT) != 0 && access_token.tenant_id().is_some();
        let is_account_filtered = (object_flags & OBJ_FILTER_ACCOUNT) != 0
            && !access_token.has_permission(Permission::Impersonate);

        // Build response
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;

        // Initial create validation for singletons
        let mut create = request.unwrap_create();
        if is_singleton && !create.is_empty() {
            response
                .not_created
                .extend(create.drain().map(|(id, _)| (id, SetError::singleton())));
        }

        // Initial destroy validation for singletons
        let mut destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();
        if is_singleton && !destroy.is_empty() {
            response
                .not_destroyed
                .extend(destroy.drain(..).map(|id| (id, SetError::singleton())));
        }

        // Update validation for willDestroy
        let update = request
            .unwrap_update()
            .into_valid()
            .filter_map(|(id, value)| {
                if is_singleton {
                    if id.is_singleton() {
                        Some((id, value))
                    } else {
                        response.not_updated.append(id, SetError::not_found());
                        None
                    }
                } else if !destroy.contains(&id) {
                    Some((id, value))
                } else {
                    response.not_updated.append(id, SetError::will_destroy());
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut set = RegistrySetResponse {
            access_token,
            server: self,
            account_id: request.account_id.document_id(),
            object_type,
            response,
            object_flags,
            is_tenant_filtered,
            is_account_filtered,
            create,
            update,
            destroy,
        };
        match object_type {
            ObjectType::AddressBook
            | ObjectType::Asn
            | ObjectType::Authentication
            | ObjectType::BlobStore
            | ObjectType::Cache
            | ObjectType::Calendar
            | ObjectType::CalendarAlarm
            | ObjectType::CalendarScheduling
            | ObjectType::Coordinator
            | ObjectType::DataRetention
            | ObjectType::DataStore
            | ObjectType::DkimReportSettings
            | ObjectType::DmarcReportSettings
            | ObjectType::DnsResolver
            | ObjectType::Email
            | ObjectType::Enterprise
            | ObjectType::FileStorage
            | ObjectType::Http
            | ObjectType::HttpForm
            | ObjectType::Imap
            | ObjectType::InMemoryStore
            | ObjectType::Jmap
            | ObjectType::LocalSettings
            | ObjectType::Metrics
            | ObjectType::MetricsStore
            | ObjectType::MtaConnectionStrategy
            | ObjectType::MtaExtensions
            | ObjectType::MtaInboundSession
            | ObjectType::MtaOutboundStrategy
            | ObjectType::MtaOutboundThrottle
            | ObjectType::MtaStageAuth
            | ObjectType::MtaStageConnect
            | ObjectType::MtaStageData
            | ObjectType::MtaStageEhlo
            | ObjectType::MtaStageMail
            | ObjectType::MtaStageRcpt
            | ObjectType::MtaSts
            | ObjectType::OidcProvider
            | ObjectType::ReportSettings
            | ObjectType::Search
            | ObjectType::SearchStore
            | ObjectType::Security
            | ObjectType::SenderAuth
            | ObjectType::Sharing
            | ObjectType::SieveSystemInterpreter
            | ObjectType::SieveUserInterpreter
            | ObjectType::SpamClassifier
            | ObjectType::SpamDnsblSettings
            | ObjectType::SpamLlm
            | ObjectType::SpamPyzor
            | ObjectType::SpamSettings
            | ObjectType::SpfReportSettings
            | ObjectType::TaskManager
            | ObjectType::TlsReportSettings
            | ObjectType::TracingStore
            | ObjectType::WebDav
            | ObjectType::DsnReportSettings
            | ObjectType::AcmeProvider
            | ObjectType::AiModel
            | ObjectType::Alert
            | ObjectType::AllowedIp
            | ObjectType::Application
            | ObjectType::BlockedIp
            | ObjectType::Certificate
            | ObjectType::Directory
            | ObjectType::DnsServer
            | ObjectType::EventTracingLevel
            | ObjectType::HttpLookup
            | ObjectType::MemoryLookupKey
            | ObjectType::MemoryLookupKeyValue
            | ObjectType::MtaVirtualQueue
            | ObjectType::MtaQueueQuota
            | ObjectType::MtaRoute
            | ObjectType::MtaDeliverySchedule
            | ObjectType::MtaInboundThrottle
            | ObjectType::MtaTlsStrategy
            | ObjectType::MtaMilter
            | ObjectType::MtaHook
            | ObjectType::NetworkListener
            | ObjectType::Node
            | ObjectType::NodeRole
            | ObjectType::NodeShard
            | ObjectType::RegistryBundle
            | ObjectType::SieveSystemScript
            | ObjectType::SieveUserScript
            | ObjectType::SpamDnsblServer
            | ObjectType::SpamFileExtension
            | ObjectType::SpamRule
            | ObjectType::SpamTag
            | ObjectType::StoreLookup
            | ObjectType::Tracer
            | ObjectType::WebHook
            | ObjectType::PublicKey
            | ObjectType::DkimSignature
            | ObjectType::MaskedEmail
            | ObjectType::Account
            | ObjectType::MailingList
            | ObjectType::OAuthClient
            | ObjectType::Role
            | ObjectType::Tenant
            | ObjectType::Domain => {
                // Bundle modifications together
                let mut modifications = Vec::with_capacity(set.create.len() + set.update.len());
                for (id, value) in set.create {
                    modifications.push((
                        Modification::Create(id),
                        value,
                        Object::from(set.object_type),
                    ));
                }
                for (id, value) in set.update {
                    if let Some(object) = self
                        .registry()
                        .get(ObjectId::new(object_type, id))
                        .await
                        .caused_by(trc::location!())?
                    {
                        modifications.push((Modification::Update(id), value, object));
                    } else if is_singleton {
                        modifications.push((
                            Modification::Update(id),
                            value,
                            Object::from(set.object_type),
                        ));
                    } else {
                        set.response.not_updated.append(id, SetError::not_found());
                    }
                }

                // Process modifications
                'outer: for (modification, value, mut object) in modifications {
                    for (key, value) in value.into_expanded_object() {
                        let ptr = match (key, &modification) {
                            (Key::Property(prop), _) => {
                                JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                            }
                            (Key::Borrowed(other), Modification::Update(_)) => {
                                JsonPointer::parse(other)
                            }
                            (Key::Owned(other), Modification::Update(_)) => {
                                JsonPointer::parse(&other)
                            }
                            (key, Modification::Create(_)) => {
                                set.response.failed(
                                    modification,
                                    SetError::invalid_properties().with_property(key.into_owned()),
                                );
                                continue 'outer;
                            }
                        };

                        // Initial validations
                        let is_create = matches!(modification, Modification::Create(_));

                        // SPDX-SnippetBegin
                        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                        // SPDX-License-Identifier: LicenseRef-SEL

                        #[cfg(feature = "enterprise")]
                        if is_create
                            && object_type == ObjectType::Account
                            && self.core.is_enterprise_edition()
                            && !self.can_create_account().await?
                        {
                            set.response.failed(
                                modification,
                                SetError::forbidden().with_description(format!(
                                "Enterprise licensed account limit reached: {} accounts licensed.",
                                self.licensed_accounts()
                            )),
                            );
                            continue 'outer;
                        }
                        // SPDX-SnippetEnd

                        /*
                           Principal creation:

                           - Add tenantId
                           - Add default roles on account creation
                           - Invalidate cache + logo cache
                           - Validate effective permissions to grant access

                           Principal update:

                           - Remove tenantId, or return error
                           - Invalidate cache + logo cache
                           - Validate effective permissions to grant access

                           Principal deletion:

                           - Validate tenantId ownership
                           - Invalidate cache
                           - Schedule account deletion (if account)

                        */

                        // Patch object
                        if let Err(err) =
                            object.patch(JsonPointerPatch::new(&ptr).with_create(is_create), value)
                        {
                        }
                    }
                }

                // Process destroy
                for id in set.destroy {}
            }
            ObjectType::QueuedMessage => {}
            ObjectType::Task => {}
            ObjectType::ArfExternalReport => {}
            ObjectType::DmarcExternalReport => {}
            ObjectType::TlsExternalReport => {}
            ObjectType::DeletedItem => {}
            ObjectType::Metric => {}
            ObjectType::Trace => {}
            ObjectType::SpamTrainingSample => {}
            ObjectType::DmarcInternalReport => {}
            ObjectType::TlsInternalReport => {}
            ObjectType::Log => {}
            ObjectType::AccountSettings => {}
            ObjectType::Credential => {}
        }

        let todo = "read only properties";
        let todo = "password encryption";
        let todo = "management objects for actions (reload, etc)";
        // MaskedEmail: Generate masked email + Enforce count
        // DkimSignature = Generate keys + Enforce count?
        // PublicKey = Validate PK? Store decoded?

        todo!()
    }
}

trait SetModification {
    fn failed(&mut self, modification: Modification, error: SetError<Property>);
}

impl SetModification for SetResponse<Registry> {
    fn failed(&mut self, modification: Modification, error: SetError<Property>) {
        match modification {
            Modification::Create(id) => self.not_created.append(id, error),
            Modification::Update(id) => self.not_updated.append(id, error),
        }
    }
}
