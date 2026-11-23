/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    DomainResponse, RequestedSetting, SoapErrorCode, SoapOperation, SoapParseError,
    SoapParseErrorKind, UserResponse, UserSettingValue,
};
use crate::{
    autodiscover::{
        pox::{AltMailboxTarget, Encryption},
        settings::UserSettingName,
    },
    ews::version::ServerVersionInfo,
    xml::{Ns, XmlWriter},
};

const ACTION_PREFIX: &str = "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/";
const SOAP: &str = "s";
const WSA: &str = "a";
const HDR: &str = "h";

fn begin_envelope(w: &mut XmlWriter<'_>, version: &ServerVersionInfo, op: SoapOperation) {
    w.decl();
    w.start(SOAP, "Envelope")
        .ns_decl(SOAP, Ns::Soap11.uri())
        .ns_decl(WSA, Ns::WsAddressing.uri())
        .close_start();
    w.start(SOAP, "Header").close_start();
    w.start(WSA, "Action")
        .attr("s:mustUnderstand", "1")
        .close_start();
    w.text(ACTION_PREFIX);
    w.text(op.name());
    w.text("Response");
    w.end(WSA, "Action");
    w.start(HDR, "ServerVersionInfo")
        .ns_decl(HDR, Ns::AdSoap.uri())
        .ns_decl("i", Ns::Xsi.uri())
        .close_start();
    w.leaf_u64(HDR, "MajorVersion", u64::from(version.major));
    w.leaf_u64(HDR, "MinorVersion", u64::from(version.minor));
    w.leaf_u64(HDR, "MajorBuildNumber", u64::from(version.major_build));
    w.leaf_u64(HDR, "MinorBuildNumber", u64::from(version.minor_build));
    w.leaf(HDR, "Version", version.version.as_str());
    w.end(HDR, "ServerVersionInfo");
    w.end(SOAP, "Header");
    w.start(SOAP, "Body").close_start();
    w.start("", op.response_root())
        .ns_decl("", Ns::AdSoap.uri())
        .close_start();
    w.start("", "Response")
        .ns_decl("i", Ns::Xsi.uri())
        .close_start();
}

fn end_envelope(w: &mut XmlWriter<'_>, op: SoapOperation) {
    w.end("", "Response");
    w.end("", op.response_root());
    w.end(SOAP, "Body");
    w.end(SOAP, "Envelope");
}

fn write_top_status(w: &mut XmlWriter<'_>, code: SoapErrorCode, message: &str) {
    w.leaf("", "ErrorCode", code.as_str());
    leaf_or_empty(w, "ErrorMessage", message);
}

fn leaf_or_empty(w: &mut XmlWriter<'_>, local: &str, text: &str) {
    if text.is_empty() {
        w.empty_leaf("", local);
    } else {
        w.leaf("", local, text);
    }
}

fn nil(w: &mut XmlWriter<'_>, local: &str) {
    w.start("", local).attr("i:nil", "true");
    w.empty();
}

fn leaf_or_nil(w: &mut XmlWriter<'_>, local: &str, text: Option<&str>) {
    match text {
        Some(text) => w.leaf("", local, text),
        None => nil(w, local),
    }
}

fn write_setting_errors<'x>(
    w: &mut XmlWriter<'_>,
    wrapper: &str,
    item: &str,
    errors: &[(RequestedSetting<'x>, SoapErrorCode)],
) {
    w.start("", wrapper).close_start();
    for (setting, code) in errors {
        w.start("", item).close_start();
        w.leaf("", "ErrorCode", code.as_str());
        w.leaf("", "ErrorMessage", code.default_message());
        w.leaf("", "SettingName", setting.as_str());
        w.end("", item);
    }
    w.end("", wrapper);
}

pub fn write_get_user_settings(
    out: &mut Vec<u8>,
    version: &ServerVersionInfo,
    responses: &[UserResponse<'_>],
) {
    let op = SoapOperation::GetUserSettings;
    let mut w = XmlWriter::new(out);
    begin_envelope(&mut w, version, op);
    write_top_status(&mut w, SoapErrorCode::NoError, "");
    w.start("", "UserResponses").close_start();
    for response in responses {
        w.start("", "UserResponse").close_start();
        w.leaf("", "ErrorCode", response.error.as_str());
        w.leaf("", "ErrorMessage", &response.message);
        leaf_or_nil(
            &mut w,
            "RedirectTarget",
            response.redirect_target.as_deref(),
        );
        write_setting_errors(
            &mut w,
            "UserSettingErrors",
            "UserSettingError",
            &response.setting_errors,
        );
        w.start("", "UserSettings").close_start();
        for (name, value) in &response.settings {
            write_user_setting(&mut w, *name, value);
        }
        w.end("", "UserSettings");
        w.end("", "UserResponse");
    }
    w.end("", "UserResponses");
    end_envelope(&mut w, op);
}

fn write_user_setting(w: &mut XmlWriter<'_>, name: UserSettingName, value: &UserSettingValue<'_>) {
    debug_assert_eq!(name.kind(), value.kind());
    let xsi_type = match value {
        UserSettingValue::String(_) => "StringSetting",
        UserSettingValue::ProtocolConnections(_) => "ProtocolConnectionCollectionSetting",
        UserSettingValue::WebClientUrls(_) => "WebClientUrlCollectionSetting",
        UserSettingValue::AlternateMailboxes(_) => "AlternateMailboxCollectionSetting",
    };
    w.start("", "UserSetting")
        .attr("i:type", xsi_type)
        .close_start();
    w.leaf("", "Name", name.as_str());
    match value {
        UserSettingValue::String(text) => w.leaf("", "Value", text),
        UserSettingValue::ProtocolConnections(connections) => {
            w.start("", "ProtocolConnections").close_start();
            for connection in connections {
                w.start("", "ProtocolConnection").close_start();
                w.leaf("", "Hostname", &connection.hostname);
                w.leaf_u64("", "Port", u64::from(connection.port));
                leaf_or_nil(
                    w,
                    "EncryptionMethod",
                    connection.encryption.map(Encryption::as_str),
                );
                w.end("", "ProtocolConnection");
            }
            w.end("", "ProtocolConnections");
        }
        UserSettingValue::WebClientUrls(urls) => {
            w.start("", "WebClientUrls").close_start();
            for url in urls {
                w.start("", "WebClientUrl").close_start();
                w.leaf("", "AuthenticationMethods", &url.auth_methods.to_text());
                w.leaf("", "Url", &url.url);
                w.end("", "WebClientUrl");
            }
            w.end("", "WebClientUrls");
        }
        UserSettingValue::AlternateMailboxes(mailboxes) => {
            w.start("", "AlternateMailboxes").close_start();
            for mailbox in mailboxes {
                w.start("", "AlternateMailbox").close_start();
                w.leaf("", "Type", mailbox.kind.as_str());
                w.leaf("", "DisplayName", &mailbox.display_name);
                match &mailbox.target {
                    AltMailboxTarget::Smtp(smtp) => {
                        nil(w, "LegacyDN");
                        nil(w, "Server");
                        w.leaf("", "SmtpAddress", smtp);
                    }
                    AltMailboxTarget::LegacyDn { legacy_dn, server } => {
                        w.leaf("", "LegacyDN", legacy_dn);
                        w.leaf("", "Server", server);
                        nil(w, "SmtpAddress");
                    }
                }
                if let Some(owner) = &mailbox.owner_smtp_address {
                    w.leaf("", "OwnerSmtpAddress", owner);
                }
                w.end("", "AlternateMailbox");
            }
            w.end("", "AlternateMailboxes");
        }
    }
    w.end("", "UserSetting");
}

pub fn write_get_domain_settings(
    out: &mut Vec<u8>,
    version: &ServerVersionInfo,
    responses: &[DomainResponse<'_>],
) {
    let op = SoapOperation::GetDomainSettings;
    let mut w = XmlWriter::new(out);
    begin_envelope(&mut w, version, op);
    write_top_status(&mut w, SoapErrorCode::NoError, "");
    w.start("", "DomainResponses").close_start();
    for response in responses {
        w.start("", "DomainResponse").close_start();
        w.leaf("", "ErrorCode", response.error.as_str());
        w.leaf("", "ErrorMessage", &response.message);
        write_setting_errors(
            &mut w,
            "DomainSettingErrors",
            "DomainSettingError",
            &response.setting_errors,
        );
        w.start("", "DomainSettings").close_start();
        for (name, value) in &response.settings {
            w.start("", "DomainSetting")
                .attr("i:type", "DomainStringSetting")
                .close_start();
            w.leaf("", "Name", name.as_str());
            w.leaf("", "Value", value);
            w.end("", "DomainSetting");
        }
        w.end("", "DomainSettings");
        leaf_or_nil(
            &mut w,
            "RedirectTarget",
            response.redirect_target.as_deref(),
        );
        w.end("", "DomainResponse");
    }
    w.end("", "DomainResponses");
    end_envelope(&mut w, op);
}

pub fn write_soap_error(
    out: &mut Vec<u8>,
    version: &ServerVersionInfo,
    op: SoapOperation,
    code: SoapErrorCode,
    message: &str,
) {
    let mut w = XmlWriter::new(out);
    begin_envelope(&mut w, version, op);
    write_top_status(&mut w, code, message);
    end_envelope(&mut w, op);
}

pub fn write_federation_not_federated(out: &mut Vec<u8>, version: &ServerVersionInfo) {
    let code = SoapErrorCode::NotFederated;
    write_soap_error(
        out,
        version,
        SoapOperation::GetFederationInformation,
        code,
        code.default_message(),
    );
}

pub fn write_soap_fault(out: &mut Vec<u8>, err: &SoapParseError) {
    let reason = match err.kind {
        SoapParseErrorKind::Xml(_) => "The request is not well-formed XML.",
        SoapParseErrorKind::NotEnvelope => "The request is not a SOAP envelope.",
        SoapParseErrorKind::MissingBody => "The SOAP envelope has no body.",
        SoapParseErrorKind::UnknownOperation => "The requested operation is not supported.",
        SoapParseErrorKind::Invalid(..) => "The request is invalid.",
    };
    let mut w = XmlWriter::new(out);
    w.decl();
    w.start(SOAP, "Envelope")
        .ns_decl(SOAP, Ns::Soap11.uri())
        .close_start();
    w.start(SOAP, "Body").close_start();
    w.start(SOAP, "Fault").close_start();
    w.leaf("", "faultcode", "s:Client");
    w.start("", "faultstring")
        .attr("xml:lang", "en-US")
        .close_start();
    w.text(reason);
    w.end("", "faultstring");
    w.end(SOAP, "Fault");
    w.end(SOAP, "Body");
    w.end(SOAP, "Envelope");
}
