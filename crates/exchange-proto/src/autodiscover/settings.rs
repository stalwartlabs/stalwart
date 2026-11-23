/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingKind {
    String,
    WebClientUrls,
    ProtocolConnections,
    AlternateMailboxes,
    Unsupported,
}

macro_rules! user_setting_names {
    ($($variant:ident : $name:literal = $kind:ident),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum UserSettingName {
            $($variant),+
        }

        impl UserSettingName {
            pub const ALL: &'static [UserSettingName] = &[$(UserSettingName::$variant),+];

            pub fn parse(name: &[u8]) -> Option<Self> {
                hashify::map!(
                    name,
                    UserSettingName,
                    $($name => UserSettingName::$variant),+
                )
                .copied()
            }

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(UserSettingName::$variant => $name),+
                }
            }

            pub const fn kind(self) -> SettingKind {
                match self {
                    $(UserSettingName::$variant => SettingKind::$kind),+
                }
            }
        }
    };
}

user_setting_names! {
    UserDisplayName: "UserDisplayName" = String,
    UserDN: "UserDN" = String,
    UserDeploymentId: "UserDeploymentId" = String,
    InternalMailboxServer: "InternalMailboxServer" = String,
    InternalRpcClientServer: "InternalRpcClientServer" = String,
    InternalMailboxServerDN: "InternalMailboxServerDN" = String,
    InternalEcpUrl: "InternalEcpUrl" = String,
    InternalEcpVoicemailUrl: "InternalEcpVoicemailUrl" = String,
    InternalEcpEmailSubscriptionsUrl: "InternalEcpEmailSubscriptionsUrl" = String,
    InternalEcpTextMessagingUrl: "InternalEcpTextMessagingUrl" = String,
    InternalEcpDeliveryReportUrl: "InternalEcpDeliveryReportUrl" = String,
    InternalEcpRetentionPolicyTagsUrl: "InternalEcpRetentionPolicyTagsUrl" = String,
    InternalEcpPublishingUrl: "InternalEcpPublishingUrl" = String,
    InternalEcpPhotoUrl: "InternalEcpPhotoUrl" = String,
    InternalEcpConnectUrl: "InternalEcpConnectUrl" = String,
    InternalEcpTeamMailboxUrl: "InternalEcpTeamMailboxUrl" = String,
    InternalEcpTeamMailboxCreatingUrl: "InternalEcpTeamMailboxCreatingUrl" = String,
    InternalEcpTeamMailboxEditingUrl: "InternalEcpTeamMailboxEditingUrl" = String,
    InternalEcpTeamMailboxHidingUrl: "InternalEcpTeamMailboxHidingUrl" = String,
    InternalEcpExtensionInstallationUrl: "InternalEcpExtensionInstallationUrl" = String,
    InternalEwsUrl: "InternalEwsUrl" = String,
    InternalEmwsUrl: "InternalEmwsUrl" = String,
    InternalOABUrl: "InternalOABUrl" = String,
    InternalPhotosUrl: "InternalPhotosUrl" = String,
    InternalUMUrl: "InternalUMUrl" = String,
    InternalWebClientUrls: "InternalWebClientUrls" = WebClientUrls,
    MailboxDN: "MailboxDN" = String,
    PublicFolderServer: "PublicFolderServer" = String,
    ActiveDirectoryServer: "ActiveDirectoryServer" = String,
    ExternalMailboxServer: "ExternalMailboxServer" = String,
    ExternalMailboxServerRequiresSSL: "ExternalMailboxServerRequiresSSL" = String,
    ExternalMailboxServerAuthenticationMethods: "ExternalMailboxServerAuthenticationMethods" = String,
    EcpVoicemailUrlFragment: "EcpVoicemailUrlFragment" = String,
    EcpEmailSubscriptionsUrlFragment: "EcpEmailSubscriptionsUrlFragment" = String,
    EcpTextMessagingUrlFragment: "EcpTextMessagingUrlFragment" = String,
    EcpDeliveryReportUrlFragment: "EcpDeliveryReportUrlFragment" = String,
    EcpRetentionPolicyTagsUrlFragment: "EcpRetentionPolicyTagsUrlFragment" = String,
    EcpPublishingUrlFragment: "EcpPublishingUrlFragment" = String,
    EcpPhotoUrlFragment: "EcpPhotoUrlFragment" = String,
    EcpConnectUrlFragment: "EcpConnectUrlFragment" = String,
    EcpTeamMailboxUrlFragment: "EcpTeamMailboxUrlFragment" = String,
    EcpTeamMailboxCreatingUrlFragment: "EcpTeamMailboxCreatingUrlFragment" = String,
    EcpTeamMailboxEditingUrlFragment: "EcpTeamMailboxEditingUrlFragment" = String,
    EcpExtensionInstallationUrlFragment: "EcpExtensionInstallationUrlFragment" = String,
    ExternalEcpUrl: "ExternalEcpUrl" = String,
    ExternalEcpVoicemailUrl: "ExternalEcpVoicemailUrl" = String,
    ExternalEcpEmailSubscriptionsUrl: "ExternalEcpEmailSubscriptionsUrl" = String,
    ExternalEcpTextMessagingUrl: "ExternalEcpTextMessagingUrl" = String,
    ExternalEcpDeliveryReportUrl: "ExternalEcpDeliveryReportUrl" = String,
    ExternalEcpRetentionPolicyTagsUrl: "ExternalEcpRetentionPolicyTagsUrl" = String,
    ExternalEcpPublishingUrl: "ExternalEcpPublishingUrl" = String,
    ExternalEcpPhotoUrl: "ExternalEcpPhotoUrl" = String,
    ExternalEcpConnectUrl: "ExternalEcpConnectUrl" = String,
    ExternalEcpTeamMailboxUrl: "ExternalEcpTeamMailboxUrl" = String,
    ExternalEcpTeamMailboxCreatingUrl: "ExternalEcpTeamMailboxCreatingUrl" = String,
    ExternalEcpTeamMailboxEditingUrl: "ExternalEcpTeamMailboxEditingUrl" = String,
    ExternalEcpTeamMailboxHidingUrl: "ExternalEcpTeamMailboxHidingUrl" = String,
    ExternalEcpExtensionInstallationUrl: "ExternalEcpExtensionInstallationUrl" = String,
    ExternalEwsUrl: "ExternalEwsUrl" = String,
    ExternalEmwsUrl: "ExternalEmwsUrl" = String,
    ExternalOABUrl: "ExternalOABUrl" = String,
    ExternalPhotosUrl: "ExternalPhotosUrl" = String,
    ExternalUMUrl: "ExternalUMUrl" = String,
    ExternalWebClientUrls: "ExternalWebClientUrls" = WebClientUrls,
    CrossOrganizationSharingEnabled: "CrossOrganizationSharingEnabled" = String,
    AlternateMailboxes: "AlternateMailboxes" = AlternateMailboxes,
    CasVersion: "CasVersion" = String,
    EwsSupportedSchemas: "EwsSupportedSchemas" = String,
    InternalPop3Connections: "InternalPop3Connections" = ProtocolConnections,
    ExternalPop3Connections: "ExternalPop3Connections" = ProtocolConnections,
    InternalImap4Connections: "InternalImap4Connections" = ProtocolConnections,
    ExternalImap4Connections: "ExternalImap4Connections" = ProtocolConnections,
    InternalSmtpConnections: "InternalSmtpConnections" = ProtocolConnections,
    ExternalSmtpConnections: "ExternalSmtpConnections" = ProtocolConnections,
    InternalServerExclusiveConnect: "InternalServerExclusiveConnect" = String,
    ExternalServerExclusiveConnect: "ExternalServerExclusiveConnect" = String,
    ExchangeRpcUrl: "ExchangeRpcUrl" = String,
    ShowGalAsDefaultView: "ShowGalAsDefaultView" = String,
    AutoDiscoverSMTPAddress: "AutoDiscoverSMTPAddress" = String,
    InteropExternalEwsUrl: "InteropExternalEwsUrl" = String,
    ExternalEwsVersion: "ExternalEwsVersion" = String,
    InteropExternalEwsVersion: "InteropExternalEwsVersion" = String,
    MobileMailboxPolicy: "MobileMailboxPolicy" = String,
    DocumentSharingLocations: "DocumentSharingLocations" = Unsupported,
    UserMSOnline: "UserMSOnline" = String,
    InternalMailboxServerAuthenticationMethods: "InternalMailboxServerAuthenticationMethods" = String,
    MailboxVersion: "MailboxVersion" = String,
    SPMySiteHostURL: "SPMySiteHostURL" = String,
    SiteMailboxCreationURL: "SiteMailboxCreationURL" = String,
    InternalRpcHttpServer: "InternalRpcHttpServer" = String,
    InternalRpcHttpConnectivityRequiresSsl: "InternalRpcHttpConnectivityRequiresSsl" = String,
    InternalRpcHttpAuthenticationMethod: "InternalRpcHttpAuthenticationMethod" = String,
    PublicFolderInformation: "PublicFolderInformation" = String,
    RedirectUrl: "RedirectUrl" = String,
    EwsPartnerUrl: "EwsPartnerUrl" = String,
    CertPrincipalName: "CertPrincipalName" = String,
    GroupingInformation: "GroupingInformation" = String,
    InternalOutlookServiceUrl: "InternalOutlookServiceUrl" = String,
    ExternalOutlookServiceUrl: "ExternalOutlookServiceUrl" = String,
}
