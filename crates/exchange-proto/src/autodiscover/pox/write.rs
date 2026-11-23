/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::PoxErrorCode;
use super::model::{
    AltMailboxTarget, AlternativeMailbox, ExchangeProtocol, MailProtocol, MailboxAccess,
    OutlookRedirect, OutlookResponse, RpcBlocks, UrlPair, WebBlock, WebBlocks,
};
use crate::{
    common::{Braces, HexCase, UtcSeconds},
    xml::{Ns, XmlWriter},
};
use std::{borrow::Cow, iter, num::NonZeroU32};

const SECONDS_PER_DAY: i64 = 86_400;

pub(crate) fn newline(w: &mut XmlWriter<'_>) {
    w.buffer().push(b'\n');
}

pub(crate) fn open(w: &mut XmlWriter<'_>, local: &str) {
    w.start("", local).close_start();
    newline(w);
}

pub(crate) fn open_ns(w: &mut XmlWriter<'_>, local: &str, ns: Ns) {
    w.start("", local).ns_decl("", ns.uri()).close_start();
    newline(w);
}

pub(crate) fn close(w: &mut XmlWriter<'_>, local: &str) {
    w.end("", local);
    newline(w);
}

pub(crate) fn line(w: &mut XmlWriter<'_>, local: &str, text: &str) {
    w.leaf("", local, text);
    newline(w);
}

fn line_opt(w: &mut XmlWriter<'_>, local: &str, text: Option<&Cow<'_, str>>) {
    if let Some(text) = text {
        line(w, local, text);
    }
}

pub(crate) fn begin_document(w: &mut XmlWriter<'_>) {
    w.decl();
    newline(w);
    open_ns(w, "Autodiscover", Ns::AdResponseOuter);
}

const fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

const fn on_off_title(value: bool) -> &'static str {
    if value { "On" } else { "Off" }
}

const fn true_false_title(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

pub fn write_outlook_response(out: &mut Vec<u8>, resp: &OutlookResponse<'_>) {
    let mut w = XmlWriter::new(out);
    begin_document(&mut w);
    open_ns(&mut w, "Response", Ns::AdResponseOutlook);

    let user = &resp.user;
    open(&mut w, "User");
    line(&mut w, "DisplayName", &user.display_name);
    line(&mut w, "LegacyDN", &user.legacy_dn);
    line(&mut w, "AutoDiscoverSMTPAddress", &user.smtp_address);
    w.start("", "DeploymentId").close_start();
    user.deployment_id
        .write_text(w.buffer(), HexCase::Lower, Braces::None);
    w.end("", "DeploymentId");
    newline(&mut w);
    if user.default_ab_view_contacts {
        line(&mut w, "DefaultABView", "contacts");
    }
    close(&mut w, "User");

    let account = &resp.account;
    open(&mut w, "Account");
    line(&mut w, "AccountType", "email");
    line(&mut w, "Action", "settings");
    line(
        &mut w,
        "MicrosoftOnline",
        true_false_title(account.microsoft_online),
    );
    match &account.mailbox {
        Some(MailboxAccess::MapiHttp {
            version,
            mail_store,
            address_book,
        }) => write_mapi_http(&mut w, *version, mail_store, address_book),
        Some(MailboxAccess::Rpc(RpcBlocks::Exch(exch))) => write_exchange(&mut w, "EXCH", exch),
        Some(MailboxAccess::Rpc(RpcBlocks::Expr(expr))) => write_exchange(&mut w, "EXPR", expr),
        Some(MailboxAccess::Rpc(RpcBlocks::Both { exch, expr })) => {
            write_exchange(&mut w, "EXCH", exch);
            write_exchange(&mut w, "EXPR", expr);
        }
        None => {}
    }
    if let Some(ex_http) = &account.ex_http {
        write_exchange(&mut w, "EXHTTP", ex_http);
    }
    if let Some(web) = &account.web {
        write_web(&mut w, web);
    }
    for (kind, mail) in [
        ("IMAP", &account.imap),
        ("POP3", &account.pop3),
        ("SMTP", &account.smtp),
    ] {
        if let Some(mail) = mail {
            write_mail(&mut w, kind, mail);
        }
    }
    for mailbox in &account.alternative_mailboxes {
        write_alternative_mailbox(&mut w, mailbox);
    }
    if let Some(smtp) = &account.public_folder_smtp {
        open(&mut w, "PublicFolderInformation");
        line(&mut w, "SmtpAddress", smtp);
        close(&mut w, "PublicFolderInformation");
    }
    close(&mut w, "Account");

    close(&mut w, "Response");
    close(&mut w, "Autodiscover");
}

pub fn write_outlook_redirect(out: &mut Vec<u8>, redirect: &OutlookRedirect<'_>) {
    let mut w = XmlWriter::new(out);
    begin_document(&mut w);
    open_ns(&mut w, "Response", Ns::AdResponseOutlook);
    open(&mut w, "Account");
    match redirect {
        OutlookRedirect::Addr(addr) => {
            line(&mut w, "Action", "redirectAddr");
            line(&mut w, "RedirectAddr", addr);
        }
        OutlookRedirect::Url(url) => {
            line(&mut w, "Action", "redirectUrl");
            line(&mut w, "RedirectUrl", url);
        }
    }
    close(&mut w, "Account");
    close(&mut w, "Response");
    close(&mut w, "Autodiscover");
}

pub fn write_pox_error(
    out: &mut Vec<u8>,
    code: PoxErrorCode,
    message: &str,
    debug_data: &str,
    time: UtcSeconds,
    id: u32,
) {
    let mut w = XmlWriter::new(out);
    begin_document(&mut w);
    open(&mut w, "Response");
    w.start("", "Error");
    let seconds = time.0.rem_euclid(SECONDS_PER_DAY);
    let mut stamp = [0u8; 16];
    let stamp = format_time_of_day(seconds, &mut stamp);
    w.attr("Time", stamp)
        .attr_u64("Id", u64::from(id))
        .close_start();
    newline(&mut w);
    w.leaf_u64("", "ErrorCode", u64::from(code.code()));
    newline(&mut w);
    line(&mut w, "Message", message);
    line(&mut w, "DebugData", debug_data);
    close(&mut w, "Error");
    close(&mut w, "Response");
    close(&mut w, "Autodiscover");
}

fn format_time_of_day(seconds: i64, buf: &mut [u8; 16]) -> &str {
    let hours = seconds / 3600;
    let minutes = (seconds / 60) % 60;
    let seconds = seconds % 60;
    let digits = [
        hours / 10,
        hours % 10,
        minutes / 10,
        minutes % 10,
        seconds / 10,
        seconds % 10,
    ];
    let [h1, h2, m1, m2, s1, s2] = digits.map(|digit| b'0' + u8::try_from(digit).unwrap_or(0));
    *buf = [
        h1, h2, b':', m1, m2, b':', s1, s2, b'.', b'0', b'0', b'0', b'0', b'0', b'0', b'0',
    ];
    std::str::from_utf8(buf).unwrap_or("00:00:00.0000000")
}

fn write_mapi_http(
    w: &mut XmlWriter<'_>,
    version: NonZeroU32,
    mail_store: &UrlPair<'_>,
    address_book: &UrlPair<'_>,
) {
    w.start("", "Protocol")
        .attr("Type", "mapiHttp")
        .attr_u64("Version", u64::from(version.get()))
        .close_start();
    newline(w);
    write_url_pair(w, "MailStore", mail_store);
    write_url_pair(w, "AddressBook", address_book);
    close(w, "Protocol");
}

fn write_web(w: &mut XmlWriter<'_>, web: &WebBlocks<'_>) {
    open(w, "Protocol");
    line(w, "Type", "WEB");
    let (internal, external) = match web {
        WebBlocks::Internal(internal) => (Some(internal), None),
        WebBlocks::External(external) => (None, Some(external)),
        WebBlocks::Both { internal, external } => (Some(internal), Some(external)),
    };
    if let Some(block) = internal {
        write_web_block(w, "Internal", "EXCH", block);
    }
    if let Some(block) = external {
        write_web_block(w, "External", "EXPR", block);
    }
    close(w, "Protocol");
}

fn write_mail(w: &mut XmlWriter<'_>, kind: &str, mail: &MailProtocol<'_>) {
    open(w, "Protocol");
    line(w, "Type", kind);
    line(w, "Server", &mail.server);
    w.leaf_u64("", "Port", u64::from(mail.port));
    newline(w);
    line(w, "LoginName", &mail.login_name);
    line(w, "SSL", on_off_title(mail.ssl));
    if let Some(encryption) = mail.encryption {
        line(w, "Encryption", encryption.as_str());
    }
    line(w, "SPA", on_off_title(mail.spa));
    line(w, "AuthRequired", on_off_title(mail.auth_required));
    close(w, "Protocol");
}

fn write_url_pair(w: &mut XmlWriter<'_>, local: &str, pair: &UrlPair<'_>) {
    open(w, local);
    match pair {
        UrlPair::Internal(internal) => line(w, "InternalUrl", internal),
        UrlPair::External(external) => line(w, "ExternalUrl", external),
        UrlPair::Both { internal, external } => {
            line(w, "InternalUrl", internal);
            line(w, "ExternalUrl", external);
        }
    }
    close(w, local);
}

fn write_web_block(w: &mut XmlWriter<'_>, local: &str, kind: &str, block: &WebBlock<'_>) {
    open(w, local);
    for owa in iter::once(&block.owa_url).chain(&block.more_owa_urls) {
        w.start("", "OWAUrl")
            .attr("AuthenticationMethod", &owa.auth_methods.to_text())
            .close_start();
        w.text(&owa.url);
        w.end("", "OWAUrl");
        newline(w);
    }
    open(w, "Protocol");
    line(w, "Type", kind);
    line(w, "ASUrl", &block.as_url);
    close(w, "Protocol");
    close(w, local);
}

fn write_exchange(w: &mut XmlWriter<'_>, kind: &str, proto: &ExchangeProtocol<'_>) {
    open(w, "Protocol");
    line(w, "Type", kind);
    line(w, "Server", &proto.server);
    line(w, "SSL", on_off_title(proto.ssl));
    line(w, "AuthPackage", proto.auth_package.as_str());
    line_opt(w, "ServerDN", proto.server_dn.as_ref());
    line_opt(w, "ServerVersion", proto.server_version.as_ref());
    line_opt(w, "MdbDN", proto.mdb_dn.as_ref());
    line_opt(w, "PublicFolderServer", proto.public_folder_server.as_ref());
    line(w, "ASUrl", &proto.as_url);
    line(w, "EwsUrl", &proto.ews_url);
    line_opt(w, "OOFUrl", proto.oof_url.as_ref());
    line_opt(w, "OABUrl", proto.oab_url.as_ref());
    line(
        w,
        "ServerExclusiveConnect",
        on_off(proto.server_exclusive_connect),
    );
    line_opt(w, "CertPrincipalName", proto.cert_principal_name.as_ref());
    close(w, "Protocol");
}

fn write_alternative_mailbox(w: &mut XmlWriter<'_>, mailbox: &AlternativeMailbox<'_>) {
    open(w, "AlternativeMailbox");
    line(w, "Type", mailbox.kind.as_str());
    line(w, "DisplayName", &mailbox.display_name);
    match &mailbox.target {
        AltMailboxTarget::Smtp(smtp) => line(w, "SmtpAddress", smtp),
        AltMailboxTarget::LegacyDn { legacy_dn, server } => {
            line(w, "LegacyDN", legacy_dn);
            line(w, "Server", server);
        }
    }
    line_opt(w, "OwnerSmtpAddress", mailbox.owner_smtp_address.as_ref());
    close(w, "AlternativeMailbox");
}
