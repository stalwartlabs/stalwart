/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{SpamFilterContext, modules::classifier::SpamClassifier};
use common::Server;
use std::future::Future;

pub trait SpamFilterAnalyzeClassify: Sync + Send {
    fn spam_filter_analyze_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;

    fn spam_filter_analyze_spam_trap(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = bool> + Send;
}

impl SpamFilterAnalyzeClassify for Server {
    async fn spam_filter_analyze_classify(&self, ctx: &mut SpamFilterContext<'_>) {
        if self.core.spam.classifier.is_some()
            && !ctx.result.has_tag("SPAM_TRAP")
            && let Err(err) = self.spam_classify(ctx).await
        {
            trc::error!(err.span_id(ctx.input.span_id).caused_by(trc::location!()));
        }
    }

    async fn spam_filter_analyze_spam_trap(&self, ctx: &mut SpamFilterContext<'_>) -> bool {
        if let Some(store) = self.get_in_memory_store("spam-traps") {
            for addr in &ctx.output.env_to_addr {
                match store.key_exists(addr.address.as_str()).await {
                    Ok(true) => {
                        ctx.result.add_tag("SPAM_TRAP");
                        return true;
                    }
                    Ok(false) => (),
                    Err(err) => {
                        trc::error!(err.span_id(ctx.input.span_id).caused_by(trc::location!()));
                    }
                }
            }
        }

        false
    }
}
