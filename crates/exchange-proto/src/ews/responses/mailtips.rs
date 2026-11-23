/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MessageResult, ResponseMessage};
use crate::{
    common::time::UtcSeconds,
    ews::types::{
        generated::{MailTips, MailTipsServiceConfiguration},
        value::{DateTime, M},
    },
    xml::XmlWriter,
};

const NEVER_EXPIRES: UtcSeconds = UtcSeconds(253_402_300_799);
const MAIL_TIPS_MESSAGE: &str = "MailTipsResponseMessageType";
const SERVICE_CONFIGURATION_MESSAGE: &str = "ServiceConfigurationResponseMessageType";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MailTipsMessage<'x> {
    pub mail_tips: Option<MailTips<'x>>,
}

impl ResponseMessage for MailTipsMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(tips) = &self.mail_tips {
            w.start(M, "MailTips");
            tips.write_children(w);
            w.end(M, "MailTips");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetMailTipsBody<'x> {
    pub messages: Vec<MessageResult<'x, MailTipsMessage<'x>>>,
}

impl ResponseMessage for GetMailTipsBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "ResponseMessages");
        for message in &self.messages {
            message.write(w, MAIL_TIPS_MESSAGE);
        }
        w.end(M, "ResponseMessages");
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServiceConfigurationMessage<'x> {
    pub mail_tips: Option<MailTipsServiceConfiguration<'x>>,
}

impl ResponseMessage for ServiceConfigurationMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(config) = &self.mail_tips {
            w.start(M, "MailTipsConfiguration");
            config.write_children(w);
            w.end(M, "MailTipsConfiguration");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetServiceConfigurationBody<'x> {
    pub messages: Vec<MessageResult<'x, ServiceConfigurationMessage<'x>>>,
}

impl ResponseMessage for GetServiceConfigurationBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "ResponseMessages");
        for message in &self.messages {
            message.write(w, SERVICE_CONFIGURATION_MESSAGE);
        }
        w.end(M, "ResponseMessages");
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetPasswordExpirationDateBody {
    pub expiration: DateTime,
}

impl GetPasswordExpirationDateBody {
    pub fn never_expires() -> Self {
        GetPasswordExpirationDateBody {
            expiration: DateTime::utc(NEVER_EXPIRES),
        }
    }
}

impl ResponseMessage for GetPasswordExpirationDateBody {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "PasswordExpirationDate");
        w.close_start();
        self.expiration.write_text(w);
        w.end(M, "PasswordExpirationDate");
    }

    fn write_required(w: &mut XmlWriter<'_>) {
        GetPasswordExpirationDateBody::never_expires().write_body(w);
    }
}
