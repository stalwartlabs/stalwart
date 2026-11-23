/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::TestResult;
use crate::{
    Context, Sieve,
    bytecode::ops,
    runtime::{RuntimeError, handler::Handler},
};

impl<'x> Context<'x> {
    pub(crate) fn test_valid_ext_list<H: Handler<'x>>(
        &self,
        script: &'x Sieve<'x>,
        test: &ops::TestValidExtList,
        handler: &mut H,
    ) -> Result<TestResult, RuntimeError> {
        let lists = self.eval_strings(script, test.list_names)?;
        TestResult::from_reply(handler.valid_ext_lists(self, &lists), test.is_not)
    }
}
