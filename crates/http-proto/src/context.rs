/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{HttpContext, HttpRequest, HttpSessionData};
use common::{
    Server,
    expr::{
        Bump, Variable,
        bumpalo::{self, collections::Vec as BumpVec},
        functions::ResolveVariable,
    },
};
use hyper::StatusCode;
use registry::schema::enums::ExpressionVariable;

impl<'x> HttpContext<'x> {
    pub fn new(session: &'x HttpSessionData, req: &'x HttpRequest) -> Self {
        Self { session, req }
    }

    pub async fn has_endpoint_access(&self, server: &Server) -> StatusCode {
        let mut arena = Bump::new();
        server
            .eval_if(
                &server.core.network.http.allowed_endpoint,
                self,
                &mut arena,
                self.session.session_id,
            )
            .await
            .unwrap_or(StatusCode::OK)
    }
}

impl ResolveVariable for HttpContext<'_> {
    fn resolve_variable<'a>(
        &'a self,
        variable: ExpressionVariable,
        arena: &'a Bump,
    ) -> Variable<'a> {
        match variable {
            ExpressionVariable::RemoteIp => Variable::String(
                bumpalo::format!(in arena, "{}", self.session.remote_ip).into_bump_str(),
            ),
            ExpressionVariable::RemotePort => self.session.remote_port.into(),
            ExpressionVariable::LocalIp => Variable::String(
                bumpalo::format!(in arena, "{}", self.session.local_ip).into_bump_str(),
            ),
            ExpressionVariable::LocalPort => self.session.local_port.into(),
            ExpressionVariable::IsTls => self.session.is_tls.into(),
            ExpressionVariable::Protocol => {
                if self.session.is_tls { "https" } else { "http" }.into()
            }
            ExpressionVariable::Listener => self.session.instance.id.as_str().into(),
            ExpressionVariable::Url => {
                Variable::String(bumpalo::format!(in arena, "{}", self.req.uri()).into_bump_str())
            }
            ExpressionVariable::Path => self.req.uri().path().into(),
            ExpressionVariable::Method => self.req.method().as_str().into(),
            ExpressionVariable::Headers => {
                let headers = self.req.headers();
                let mut items = BumpVec::with_capacity_in(headers.len(), arena);
                items.extend(headers.iter().map(|(name, value)| {
                    Variable::String(
                        bumpalo::format!(
                            in arena,
                            "{}: {}",
                            name.as_str(),
                            value.to_str().unwrap_or_default()
                        )
                        .into_bump_str(),
                    )
                }));
                Variable::Array(items.into_bump_slice())
            }
            _ => Variable::default(),
        }
    }
}
