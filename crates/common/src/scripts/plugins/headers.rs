/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sieve::{FunctionMap, runtime::Variable};

use crate::scripts::ScriptModification;

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("add_header", plugin_id, 2);
}

pub fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable<'static>> {
    let mut arguments = ctx.arguments.into_iter();
    Ok(
        if let (Some(Variable::String(name)), Some(Variable::String(value))) =
            (arguments.next(), arguments.next())
        {
            ctx.modifications.push(ScriptModification::AddHeader {
                name: name.into_owned(),
                value: value.into_owned(),
            });
            true
        } else {
            false
        }
        .into(),
    )
}
