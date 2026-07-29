/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    #[prost(message, optional, tag = "1")]
    pub context: Option<Context>,
    #[prost(message, optional, tag = "2")]
    pub envelope: Option<Envelope>,
    #[prost(message, optional, tag = "3")]
    pub message: Option<Message>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Context {
    #[prost(enumeration = "Stage", tag = "1")]
    pub stage: i32,
    #[prost(message, optional, tag = "2")]
    pub client: Option<Client>,
    #[prost(message, optional, tag = "3")]
    pub sasl: Option<Sasl>,
    #[prost(message, optional, tag = "4")]
    pub tls: Option<Tls>,
    #[prost(message, optional, tag = "5")]
    pub server: Option<Server>,
    #[prost(message, optional, tag = "6")]
    pub queue: Option<Queue>,
    #[prost(message, optional, tag = "7")]
    pub protocol: Option<Protocol>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Stage {
    Unspecified = 0,
    Connect = 1,
    Ehlo = 2,
    Auth = 3,
    Mail = 4,
    Rcpt = 5,
    Data = 6,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Client {
    #[prost(string, tag = "1")]
    pub ip: String,
    #[prost(uint32, tag = "2")]
    pub port: u32,
    #[prost(string, optional, tag = "3")]
    pub ptr: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub helo: Option<String>,
    #[prost(uint32, tag = "5")]
    pub active_connections: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Sasl {
    #[prost(string, tag = "1")]
    pub login: String,
    #[prost(string, optional, tag = "2")]
    pub method: Option<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Tls {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub cipher: String,
    #[prost(uint32, optional, tag = "3")]
    pub cipher_bits: Option<u32>,
    #[prost(string, optional, tag = "4")]
    pub cert_issuer: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub cert_subject: Option<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Server {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(uint32, tag = "2")]
    pub port: u32,
    #[prost(string, optional, tag = "3")]
    pub ip: Option<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Queue {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Protocol {
    #[prost(uint32, tag = "1")]
    pub version: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Address {
    #[prost(string, tag = "1")]
    pub address: String,
    #[prost(map = "string, string", tag = "2")]
    pub parameters: std::collections::HashMap<String, String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Envelope {
    #[prost(message, optional, tag = "1")]
    pub from: Option<Address>,
    #[prost(message, repeated, tag = "2")]
    pub to: Vec<Address>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Header {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Message {
    #[prost(message, repeated, tag = "1")]
    pub headers: Vec<Header>,
    #[prost(message, repeated, tag = "2")]
    pub server_headers: Vec<Header>,
    #[prost(string, tag = "3")]
    pub contents: String,
    #[prost(uint64, tag = "4")]
    pub size: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    #[prost(enumeration = "Action", tag = "1")]
    pub action: i32,
    #[prost(message, optional, tag = "2")]
    pub response: Option<SmtpResponse>,
    #[prost(message, repeated, tag = "3")]
    pub modifications: Vec<Modification>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Action {
    Unspecified = 0,
    Accept = 1,
    Discard = 2,
    Reject = 3,
    Quarantine = 4,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SmtpResponse {
    #[prost(uint32, optional, tag = "1")]
    pub status: Option<u32>,
    #[prost(string, optional, tag = "2")]
    pub enhanced_status: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub message: Option<String>,
    #[prost(bool, tag = "4")]
    pub disconnect: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Modification {
    #[prost(oneof = "modification::Kind", tags = "1, 2, 3, 4, 5, 6, 7, 8")]
    pub kind: Option<modification::Kind>,
}

pub mod modification {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        ChangeFrom(super::ChangeFrom),
        #[prost(message, tag = "2")]
        AddRecipient(super::AddRecipient),
        #[prost(message, tag = "3")]
        DeleteRecipient(super::DeleteRecipient),
        #[prost(message, tag = "4")]
        ReplaceContents(super::ReplaceContents),
        #[prost(message, tag = "5")]
        AddHeader(super::AddHeader),
        #[prost(message, tag = "6")]
        InsertHeader(super::InsertHeader),
        #[prost(message, tag = "7")]
        ChangeHeader(super::ChangeHeader),
        #[prost(message, tag = "8")]
        DeleteHeader(super::DeleteHeader),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Parameter {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, optional, tag = "2")]
    pub value: Option<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChangeFrom {
    #[prost(string, tag = "1")]
    pub value: String,
    #[prost(message, repeated, tag = "2")]
    pub parameters: Vec<Parameter>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddRecipient {
    #[prost(string, tag = "1")]
    pub value: String,
    #[prost(message, repeated, tag = "2")]
    pub parameters: Vec<Parameter>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteRecipient {
    #[prost(string, tag = "1")]
    pub value: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplaceContents {
    #[prost(string, tag = "1")]
    pub value: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddHeader {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InsertHeader {
    #[prost(uint32, tag = "1")]
    pub index: u32,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub value: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChangeHeader {
    #[prost(uint32, tag = "1")]
    pub index: u32,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub value: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteHeader {
    #[prost(uint32, tag = "1")]
    pub index: u32,
    #[prost(string, tag = "2")]
    pub name: String,
}

impl From<super::Request> for Request {
    fn from(value: super::Request) -> Self {
        Request {
            context: Some(value.context.into()),
            envelope: value.envelope.map(Into::into),
            message: value.message.map(Into::into),
        }
    }
}

impl From<super::Context> for Context {
    fn from(value: super::Context) -> Self {
        Context {
            stage: Stage::from(value.stage) as i32,
            client: Some(value.client.into()),
            sasl: value.sasl.map(Into::into),
            tls: value.tls.map(Into::into),
            server: Some(value.server.into()),
            queue: value.queue.map(Into::into),
            protocol: Some(Protocol {
                version: value.protocol.version,
            }),
        }
    }
}

impl From<super::Stage> for Stage {
    fn from(value: super::Stage) -> Self {
        match value {
            super::Stage::Connect => Stage::Connect,
            super::Stage::Ehlo => Stage::Ehlo,
            super::Stage::Auth => Stage::Auth,
            super::Stage::Mail => Stage::Mail,
            super::Stage::Rcpt => Stage::Rcpt,
            super::Stage::Data => Stage::Data,
        }
    }
}

impl From<super::Client> for Client {
    fn from(value: super::Client) -> Self {
        Client {
            ip: value.ip,
            port: value.port as u32,
            ptr: value.ptr,
            helo: value.helo,
            active_connections: value.active_connections,
        }
    }
}

impl From<super::Sasl> for Sasl {
    fn from(value: super::Sasl) -> Self {
        Sasl {
            login: value.login,
            method: value.method,
        }
    }
}

impl From<super::Tls> for Tls {
    fn from(value: super::Tls) -> Self {
        Tls {
            version: value.version,
            cipher: value.cipher,
            cipher_bits: value.bits.map(|bits| bits as u32),
            cert_issuer: value.issuer,
            cert_subject: value.subject,
        }
    }
}

impl From<super::Server> for Server {
    fn from(value: super::Server) -> Self {
        Server {
            name: value.name,
            port: value.port as u32,
            ip: value.ip,
        }
    }
}

impl From<super::Queue> for Queue {
    fn from(value: super::Queue) -> Self {
        Queue { id: value.id }
    }
}

impl From<super::Address> for Address {
    fn from(value: super::Address) -> Self {
        Address {
            address: value.address,
            parameters: value
                .parameters
                .map(|parameters| parameters.into_iter().collect())
                .unwrap_or_default(),
        }
    }
}

impl From<super::Envelope> for Envelope {
    fn from(value: super::Envelope) -> Self {
        Envelope {
            from: Some(value.from.into()),
            to: value.to.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<super::Message> for Message {
    fn from(value: super::Message) -> Self {
        Message {
            headers: value.headers.into_iter().map(into_header).collect(),
            server_headers: value.server_headers.into_iter().map(into_header).collect(),
            contents: value.contents,
            size: value.size as u64,
        }
    }
}

fn into_header((name, value): (String, String)) -> Header {
    Header { name, value }
}

impl TryFrom<Response> for super::Response {
    type Error = String;

    fn try_from(value: Response) -> Result<Self, Self::Error> {
        Ok(super::Response {
            action: match value.action() {
                Action::Accept => super::Action::Accept,
                Action::Discard => super::Action::Discard,
                Action::Reject => super::Action::Reject,
                Action::Quarantine => super::Action::Quarantine,
                Action::Unspecified => {
                    return Err(format!("Unknown action {} in Hook response", value.action));
                }
            },
            response: value.response.map(|response| super::SmtpResponse {
                status: response.status.map(|status| status as u16),
                enhanced_status: response.enhanced_status,
                message: response.message,
                disconnect: response.disconnect,
            }),
            modifications: value
                .modifications
                .into_iter()
                .map(super::Modification::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl TryFrom<Modification> for super::Modification {
    type Error = String;

    fn try_from(value: Modification) -> Result<Self, Self::Error> {
        match value
            .kind
            .ok_or_else(|| "Empty modification in Hook response".to_string())?
        {
            modification::Kind::ChangeFrom(value) => Ok(super::Modification::ChangeFrom {
                value: value.value,
                parameters: into_parameters(value.parameters),
            }),
            modification::Kind::AddRecipient(value) => Ok(super::Modification::AddRecipient {
                value: value.value,
                parameters: into_parameters(value.parameters),
            }),
            modification::Kind::DeleteRecipient(value) => {
                Ok(super::Modification::DeleteRecipient { value: value.value })
            }
            modification::Kind::ReplaceContents(value) => {
                Ok(super::Modification::ReplaceContents { value: value.value })
            }
            modification::Kind::AddHeader(value) => Ok(super::Modification::AddHeader {
                name: value.name,
                value: value.value,
            }),
            modification::Kind::InsertHeader(value) => Ok(super::Modification::InsertHeader {
                index: value.index,
                name: value.name,
                value: value.value,
            }),
            modification::Kind::ChangeHeader(value) => Ok(super::Modification::ChangeHeader {
                index: value.index,
                name: value.name,
                value: value.value,
            }),
            modification::Kind::DeleteHeader(value) => Ok(super::Modification::DeleteHeader {
                index: value.index,
                name: value.name,
            }),
        }
    }
}

fn into_parameters(parameters: Vec<Parameter>) -> AHashMap<String, Option<String>> {
    parameters
        .into_iter()
        .map(|parameter| (parameter.key, parameter.value))
        .collect()
}

impl TryFrom<Request> for super::Request {
    type Error = String;

    fn try_from(value: Request) -> Result<Self, Self::Error> {
        Ok(super::Request {
            context: value
                .context
                .ok_or_else(|| "Missing context in Hook request".to_string())?
                .try_into()?,
            envelope: value.envelope.map(TryInto::try_into).transpose()?,
            message: value.message.map(Into::into),
        })
    }
}

impl TryFrom<Context> for super::Context {
    type Error = String;

    fn try_from(value: Context) -> Result<Self, Self::Error> {
        Ok(super::Context {
            stage: match value.stage() {
                Stage::Connect => super::Stage::Connect,
                Stage::Ehlo => super::Stage::Ehlo,
                Stage::Auth => super::Stage::Auth,
                Stage::Mail => super::Stage::Mail,
                Stage::Rcpt => super::Stage::Rcpt,
                Stage::Data => super::Stage::Data,
                Stage::Unspecified => {
                    return Err(format!("Unknown stage {} in Hook request", value.stage));
                }
            },
            client: value
                .client
                .ok_or_else(|| "Missing client in Hook request".to_string())
                .map(|client| super::Client {
                    ip: client.ip,
                    port: client.port as u16,
                    ptr: client.ptr,
                    helo: client.helo,
                    active_connections: client.active_connections,
                })?,
            sasl: value.sasl.map(|sasl| super::Sasl {
                login: sasl.login,
                method: sasl.method,
            }),
            tls: value.tls.map(|tls| super::Tls {
                version: tls.version,
                cipher: tls.cipher,
                bits: tls.cipher_bits.map(|bits| bits as u16),
                issuer: tls.cert_issuer,
                subject: tls.cert_subject,
            }),
            server: value
                .server
                .ok_or_else(|| "Missing server in Hook request".to_string())
                .map(|server| super::Server {
                    name: server.name,
                    port: server.port as u16,
                    ip: server.ip,
                })?,
            queue: value.queue.map(|queue| super::Queue { id: queue.id }),
            protocol: value
                .protocol
                .ok_or_else(|| "Missing protocol in Hook request".to_string())
                .map(|protocol| super::Protocol {
                    version: protocol.version,
                })?,
        })
    }
}

impl TryFrom<Envelope> for super::Envelope {
    type Error = String;

    fn try_from(value: Envelope) -> Result<Self, Self::Error> {
        Ok(super::Envelope {
            from: value
                .from
                .ok_or_else(|| "Missing envelope sender in Hook request".to_string())?
                .into(),
            to: value.to.into_iter().map(Into::into).collect(),
        })
    }
}

impl From<Address> for super::Address {
    fn from(value: Address) -> Self {
        super::Address {
            address: value.address,
            parameters: (!value.parameters.is_empty())
                .then(|| value.parameters.into_iter().collect()),
        }
    }
}

impl From<Message> for super::Message {
    fn from(value: Message) -> Self {
        super::Message {
            headers: value.headers.into_iter().map(from_header).collect(),
            server_headers: value.server_headers.into_iter().map(from_header).collect(),
            contents: value.contents,
            size: value.size as usize,
        }
    }
}

fn from_header(header: Header) -> (String, String) {
    (header.name, header.value)
}

impl From<super::Response> for Response {
    fn from(value: super::Response) -> Self {
        Response {
            action: match value.action {
                super::Action::Accept => Action::Accept,
                super::Action::Discard => Action::Discard,
                super::Action::Reject => Action::Reject,
                super::Action::Quarantine => Action::Quarantine,
            } as i32,
            response: value.response.map(|response| SmtpResponse {
                status: response.status.map(|status| status as u32),
                enhanced_status: response.enhanced_status,
                message: response.message,
                disconnect: response.disconnect,
            }),
            modifications: value.modifications.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<super::Modification> for Modification {
    fn from(value: super::Modification) -> Self {
        Modification {
            kind: Some(match value {
                super::Modification::ChangeFrom { value, parameters } => {
                    modification::Kind::ChangeFrom(ChangeFrom {
                        value,
                        parameters: from_parameters(parameters),
                    })
                }
                super::Modification::AddRecipient { value, parameters } => {
                    modification::Kind::AddRecipient(AddRecipient {
                        value,
                        parameters: from_parameters(parameters),
                    })
                }
                super::Modification::DeleteRecipient { value } => {
                    modification::Kind::DeleteRecipient(DeleteRecipient { value })
                }
                super::Modification::ReplaceContents { value } => {
                    modification::Kind::ReplaceContents(ReplaceContents { value })
                }
                super::Modification::AddHeader { name, value } => {
                    modification::Kind::AddHeader(AddHeader { name, value })
                }
                super::Modification::InsertHeader { index, name, value } => {
                    modification::Kind::InsertHeader(InsertHeader { index, name, value })
                }
                super::Modification::ChangeHeader { index, name, value } => {
                    modification::Kind::ChangeHeader(ChangeHeader { index, name, value })
                }
                super::Modification::DeleteHeader { index, name } => {
                    modification::Kind::DeleteHeader(DeleteHeader { index, name })
                }
            }),
        }
    }
}

fn from_parameters(parameters: AHashMap<String, Option<String>>) -> Vec<Parameter> {
    parameters
        .into_iter()
        .map(|(key, value)| Parameter { key, value })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    fn as_json<T: serde::Serialize>(value: &T) -> serde_json::Value {
        serde_json::to_value(value).unwrap()
    }

    fn as_request(request: &super::super::Request) -> super::super::Request {
        serde_json::from_value(as_json(request)).unwrap()
    }

    fn as_response(response: &super::super::Response) -> super::super::Response {
        serde_json::from_value(as_json(response)).unwrap()
    }

    #[test]
    fn request_round_trip() {
        let request = super::super::Request {
            context: super::super::Context {
                stage: super::super::Stage::Data,
                client: super::super::Client {
                    ip: "10.0.0.1".into(),
                    port: 15417,
                    ptr: Some("mx.doe.org".into()),
                    helo: Some("doe.org".into()),
                    active_connections: 3,
                },
                sasl: Some(super::super::Sasl {
                    login: "jane@doe.org".into(),
                    method: Some("PLAIN".into()),
                }),
                tls: Some(super::super::Tls {
                    version: "TLSv1.3".into(),
                    cipher: "TLS_AES_256_GCM_SHA384".into(),
                    bits: Some(256),
                    issuer: Some("Let's Encrypt".into()),
                    subject: Some("mx.doe.org".into()),
                }),
                server: super::super::Server {
                    name: Some("Stalwart".into()),
                    port: 25,
                    ip: Some("10.0.0.2".into()),
                },
                queue: Some(super::super::Queue {
                    id: "abc123".into(),
                }),
                protocol: super::super::Protocol { version: 1 },
            },
            envelope: Some(super::super::Envelope {
                from: super::super::Address {
                    address: "jane@doe.org".into(),
                    parameters: Some([("BODY".to_string(), "8BITMIME".to_string())].into()),
                },
                to: vec![super::super::Address {
                    address: "bill@foobar.org".into(),
                    parameters: None,
                }],
            }),
            message: Some(super::super::Message {
                headers: vec![
                    ("Received".into(), "from a".into()),
                    ("Received".into(), "from b".into()),
                    ("Subject".into(), "Is dinner ready?".into()),
                ],
                server_headers: vec![("X-Spam".into(), "No".into())],
                contents: "Are you hungry yet?".into(),
                size: 19,
            }),
        };

        let encoded = Request::from(as_request(&request)).encode_to_vec();
        let decoded: super::super::Request = Request::decode(encoded.as_slice())
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(as_json(&request), as_json(&decoded));
    }

    #[test]
    fn response_round_trip() {
        let response = super::super::Response {
            action: super::super::Action::Quarantine,
            response: Some(super::super::SmtpResponse {
                status: Some(451),
                enhanced_status: Some("4.3.5".into()),
                message: Some("Try again later.".into()),
                disconnect: true,
            }),
            modifications: vec![
                super::super::Modification::ChangeFrom {
                    value: "jane@doe.org".into(),
                    parameters: [("BODY".to_string(), Some("8BITMIME".to_string()))].into(),
                },
                super::super::Modification::AddRecipient {
                    value: "bill@foobar.org".into(),
                    parameters: [("NOTIFY".to_string(), None)].into(),
                },
                super::super::Modification::DeleteRecipient {
                    value: "john@doe.org".into(),
                },
                super::super::Modification::ReplaceContents {
                    value: "123456".into(),
                },
                super::super::Modification::AddHeader {
                    name: "X-Hello".into(),
                    value: "World".into(),
                },
                super::super::Modification::InsertHeader {
                    index: 1,
                    name: "X-Inserted".into(),
                    value: "Yes".into(),
                },
                super::super::Modification::ChangeHeader {
                    index: 2,
                    name: "Subject".into(),
                    value: "[SPAM] Saying Hello".into(),
                },
                super::super::Modification::DeleteHeader {
                    index: 3,
                    name: "References".into(),
                },
            ],
        };

        let encoded = Response::from(as_response(&response)).encode_to_vec();
        let decoded: super::super::Response = Response::decode(encoded.as_slice())
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(as_json(&response), as_json(&decoded));
    }

    #[test]
    fn unspecified_action_is_rejected() {
        let response = Response {
            action: Action::Unspecified as i32,
            ..Default::default()
        };

        assert!(super::super::Response::try_from(response).is_err());
    }

    #[test]
    fn empty_modification_is_rejected() {
        let response = Response {
            action: Action::Accept as i32,
            response: None,
            modifications: vec![Modification { kind: None }],
        };

        assert!(super::super::Response::try_from(response).is_err());
    }
}
