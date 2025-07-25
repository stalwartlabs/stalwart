/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;

use compact_str::ToCompactString;

use crate::{
    method::{
        changes::ChangesRequest,
        copy::{CopyBlobRequest, CopyRequest},
        get::GetRequest,
        import::ImportEmailRequest,
        lookup::BlobLookupRequest,
        parse::ParseEmailRequest,
        query::QueryRequest,
        query_changes::QueryChangesRequest,
        search_snippet::GetSearchSnippetRequest,
        set::SetRequest,
        upload::BlobUploadRequest,
        validate::ValidateSieveScriptRequest,
    },
    parser::{Ignore, JsonObjectParser, Token, json::Parser},
    types::any_id::AnyId,
};

use super::{
    Call, Request, RequestMethod,
    capability::Capability,
    echo::Echo,
    method::{MethodFunction, MethodName, MethodObject},
};

impl Request {
    pub fn parse(json: &[u8], max_calls: usize, max_size: usize) -> trc::Result<Self> {
        if json.len() <= max_size {
            let mut request = Request {
                using: 0,
                method_calls: Vec::new(),
                created_ids: None,
            };
            let mut found_valid_keys = false;
            let mut parser = Parser::new(json);
            parser.next_token::<String>()?.assert(Token::DictStart)?;
            while let Some(key) = parser.next_dict_key::<u128>()? {
                found_valid_keys |= request.parse_key(&mut parser, max_calls, key)?;
            }

            if found_valid_keys {
                Ok(request)
            } else {
                Err(trc::JmapEvent::NotRequest
                    .into_err()
                    .details("Invalid JMAP request"))
            }
        } else {
            Err(trc::LimitEvent::SizeRequest.into_err())
        }
    }

    pub(crate) fn parse_key(
        &mut self,
        parser: &mut Parser,
        max_calls: usize,
        key: u128,
    ) -> trc::Result<bool> {
        match key {
            0x0067_6e69_7375 => {
                parser.next_token::<Ignore>()?.assert(Token::ArrayStart)?;
                loop {
                    match parser.next_token::<Capability>()? {
                        Token::String(capability) => {
                            self.using |= capability as u32;
                        }
                        Token::Comma => (),
                        Token::ArrayEnd => break,
                        token => return Err(token.error("capability", &token.to_string())),
                    }
                }
                Ok(true)
            }
            0x0073_6c6c_6143_646f_6874_656d => {
                parser
                    .next_token::<Ignore>()?
                    .assert_jmap(Token::ArrayStart)?;
                loop {
                    match parser.next_token::<Ignore>()? {
                        Token::ArrayStart => (),
                        Token::Comma => continue,
                        Token::ArrayEnd => break,
                        _ => {
                            return Err(trc::JmapEvent::NotRequest
                                .into_err()
                                .details("Invalid JMAP request"));
                        }
                    };
                    if self.method_calls.len() < max_calls {
                        let method_name = match parser.next_token::<MethodName>() {
                            Ok(Token::String(method)) => method,
                            Ok(_) => {
                                return Err(trc::JmapEvent::NotRequest
                                    .into_err()
                                    .details("Invalid JMAP request"));
                            }
                            Err(err)
                                if err.matches(trc::EventType::Jmap(
                                    trc::JmapEvent::InvalidArguments,
                                )) =>
                            {
                                MethodName::error()
                            }
                            Err(err) => {
                                return Err(err);
                            }
                        };
                        parser.next_token::<Ignore>()?.assert_jmap(Token::Comma)?;
                        parser.ctx = method_name.obj;
                        let start_depth_array = parser.depth_array;
                        let start_depth_dict = parser.depth_dict;

                        let method = match (&method_name.fnc, &method_name.obj) {
                            (
                                MethodFunction::Get,
                                MethodObject::Email
                                | MethodObject::Mailbox
                                | MethodObject::Thread
                                | MethodObject::Identity
                                | MethodObject::EmailSubmission
                                | MethodObject::PushSubscription
                                | MethodObject::VacationResponse
                                | MethodObject::SieveScript
                                | MethodObject::Principal
                                | MethodObject::Quota
                                | MethodObject::Blob,
                            ) => GetRequest::parse(parser).map(RequestMethod::Get),
                            (MethodFunction::Get, MethodObject::SearchSnippet) => {
                                GetSearchSnippetRequest::parse(parser)
                                    .map(RequestMethod::SearchSnippet)
                            }
                            (MethodFunction::Query, _) => {
                                QueryRequest::parse(parser).map(RequestMethod::Query)
                            }
                            (MethodFunction::Set, _) => {
                                SetRequest::parse(parser).map(RequestMethod::Set)
                            }
                            (MethodFunction::Changes, _) => {
                                ChangesRequest::parse(parser).map(RequestMethod::Changes)
                            }
                            (MethodFunction::QueryChanges, _) => {
                                QueryChangesRequest::parse(parser).map(RequestMethod::QueryChanges)
                            }
                            (MethodFunction::Copy, MethodObject::Email) => {
                                CopyRequest::parse(parser).map(RequestMethod::Copy)
                            }
                            (MethodFunction::Copy, MethodObject::Blob) => {
                                CopyBlobRequest::parse(parser).map(RequestMethod::CopyBlob)
                            }
                            (MethodFunction::Lookup, MethodObject::Blob) => {
                                BlobLookupRequest::parse(parser).map(RequestMethod::LookupBlob)
                            }
                            (MethodFunction::Upload, MethodObject::Blob) => {
                                BlobUploadRequest::parse(parser).map(RequestMethod::UploadBlob)
                            }
                            (MethodFunction::Import, MethodObject::Email) => {
                                ImportEmailRequest::parse(parser).map(RequestMethod::ImportEmail)
                            }
                            (MethodFunction::Parse, MethodObject::Email) => {
                                ParseEmailRequest::parse(parser).map(RequestMethod::ParseEmail)
                            }
                            (MethodFunction::Validate, MethodObject::SieveScript) => {
                                ValidateSieveScriptRequest::parse(parser)
                                    .map(RequestMethod::ValidateScript)
                            }
                            (MethodFunction::Echo, MethodObject::Core) => {
                                Echo::parse(parser).map(RequestMethod::Echo)
                            }
                            _ => Err(trc::JmapEvent::UnknownMethod
                                .into_err()
                                .details(method_name.to_compact_string())),
                        };

                        let method = match method {
                            Ok(method) => method,
                            Err(err) if !err.is_jmap_method_error() => {
                                parser.skip_token(start_depth_array, start_depth_dict)?;
                                RequestMethod::Error(err)
                            }
                            Err(err) => {
                                return Err(err);
                            }
                        };

                        parser.next_token::<Ignore>()?.assert_jmap(Token::Comma)?;
                        let id = parser.next_token::<String>()?.unwrap_string("")?;
                        parser
                            .next_token::<Ignore>()?
                            .assert_jmap(Token::ArrayEnd)?;
                        self.method_calls.push(Call {
                            id,
                            method,
                            name: method_name,
                        });
                    } else {
                        return Err(trc::LimitEvent::CallsIn.into_err());
                    }
                }
                Ok(true)
            }
            0x7364_4964_6574_6165_7263 => {
                let mut created_ids = HashMap::new();
                parser.next_token::<Ignore>()?.assert(Token::DictStart)?;
                while let Some(key) = parser.next_dict_key::<String>()? {
                    created_ids.insert(
                        key,
                        parser.next_token::<AnyId>()?.unwrap_string("createdIds")?,
                    );
                }
                self.created_ids = Some(created_ids);
                Ok(true)
            }
            _ => {
                parser.skip_token(parser.depth_array, parser.depth_dict)?;
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::request::Request;

    const TEST: &str = r#"
    {
        "using": [ "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail" ],
        "methodCalls": [
          [ "method1", {
            "arg1": "arg1data",
            "arg2": "arg2data"
          }, "c1" ],
          [ "Core/echo", {
            "hello": true,
            "high": 5
          }, "c2" ],
          [ "method3", {"hello": [{"a": {"b": true}}]}, "c3" ]
        ],
        "createdIds": {
            "c1": "m1",
            "c2": "m2"
        }
      }
    "#;

    const TEST2: &str = r##"
    {
        "using": [
          "urn:ietf:params:jmap:submission",
          "urn:ietf:params:jmap:mail",
          "urn:ietf:params:jmap:core"
        ],
        "methodCalls": [
          [
            "Email/set",
            {
              "accountId": "c",
              "create": {
                "c37ee58b-e224-4799-88e6-1d7484e3b782": {
                  "mailboxIds": {
                    "9": true
                  },
                  "subject": "test",
                  "from": [
                    {
                      "name": "Foo",
                      "email": "foo@bar.com"
                    }
                  ],
                  "to": [
                    {
                      "name": null,
                      "email": "bar@foo.com"
                    }
                  ],
                  "cc": [],
                  "bcc": [],
                  "replyTo": [
                    {
                      "name": null,
                      "email": "foo@bar.com"
                    }
                  ],
                  "htmlBody": [
                    {
                      "partId": "c37ee58b-e224-4799-88e6-1d7484e3b782",
                      "type": "text/html"
                    }
                  ],
                  "bodyValues": {
                    "c37ee58b-e224-4799-88e6-1d7484e3b782": {
                      "value": "<p>test email<br></p>",
                      "isEncodingProblem": false,
                      "isTruncated": false
                    }
                  },
                  "header:User-Agent:asText": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0"
                }
              }
            },
            "c0"
          ],
          [
            "EmailSubmission/set",
            {
              "accountId": "c",
              "create": {
                "c37ee58b-e224-4799-88e6-1d7484e3b782": {
                  "identityId": "a",
                  "emailId": "#c37ee58b-e224-4799-88e6-1d7484e3b782",
                  "envelope": {
                    "mailFrom": {
                      "email": "foo@bar.com"
                    },
                    "rcptTo": [
                      {
                        "email": "bar@foo.com"
                      }
                    ]
                  }
                }
              },
              "onSuccessUpdateEmail": {
                "#c37ee58b-e224-4799-88e6-1d7484e3b782": {
                  "mailboxIds/d": true,
                  "mailboxIds/9": null,
                  "keywords/$seen": true,
                  "keywords/$draft": null
                }
              }
            },
            "c1"
          ]
        ]
      }
    "##;

    #[test]
    fn parse_request() {
        println!("{:?}", Request::parse(TEST.as_bytes(), 10, 10240));
        println!("{:?}", Request::parse(TEST2.as_bytes(), 10, 10240));
    }
}
