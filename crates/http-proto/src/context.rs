/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{HttpContext, HttpRequest, HttpSessionData};
use common::{
    Server,
    expr::{functions::ResolveVariable, *},
};
use compact_str::{ToCompactString, format_compact};
use hyper::StatusCode;
use registry::schema::enums::ExpressionVariable;

impl<'x> HttpContext<'x> {
    pub fn new(session: &'x HttpSessionData, req: &'x HttpRequest) -> Self {
        Self { session, req }
    }

    pub async fn has_endpoint_access(&self, server: &Server) -> StatusCode {
        server
            .eval_if(
                &server.core.network.http.allowed_endpoint,
                self,
                self.session.session_id,
            )
            .await
            .unwrap_or(StatusCode::OK)
    }
}

impl ResolveVariable for HttpContext<'_> {
    fn resolve_variable(&self, variable: ExpressionVariable) -> Variable<'_> {
        match variable {
            ExpressionVariable::RemoteIp => self.session.remote_ip.to_compact_string().into(),
            ExpressionVariable::RemotePort => self.session.remote_port.into(),
            ExpressionVariable::LocalIp => self.session.local_ip.to_compact_string().into(),
            ExpressionVariable::LocalPort => self.session.local_port.into(),
            ExpressionVariable::IsTls => self.session.is_tls.into(),
            ExpressionVariable::Protocol => {
                if self.session.is_tls { "https" } else { "http" }.into()
            }
            ExpressionVariable::Listener => self.session.instance.id.as_str().into(),
            ExpressionVariable::Url => self.req.uri().to_compact_string().into(),
            ExpressionVariable::Path => self.req.uri().path().into(),
            ExpressionVariable::Method => self.req.method().as_str().into(),
            ExpressionVariable::Headers => self
                .req
                .headers()
                .iter()
                .map(|(h, v)| {
                    Variable::String(
                        format_compact!("{}: {}", h.as_str(), v.to_str().unwrap_or_default())
                            .into(),
                    )
                })
                .collect::<Vec<_>>()
                .into(),
            _ => Variable::default(),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}
