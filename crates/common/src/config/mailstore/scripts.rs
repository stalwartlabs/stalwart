/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    VERSION_PUBLIC,
    expr::if_block::{BootstrapExprExt, IfBlock},
    scripts::{
        functions::{register_functions_trusted, register_functions_untrusted},
        plugins::RegisterSievePlugins,
    },
};
use ahash::AHashMap;
use registry::{
    schema::{
        prelude::ObjectType,
        structs::{
            SieveSystemInterpreter, SieveSystemScript, SieveUserInterpreter, SieveUserScript,
            SystemSettings,
        },
    },
    types::EnumImpl,
};
use sieve::{Compiler, Runtime, Sieve, compiler::grammar::Capability};
use std::{collections::hash_map::Entry, sync::Arc};
use store::registry::bootstrap::Bootstrap;

pub struct Scripting {
    pub untrusted_compiler: Compiler,
    pub untrusted_runtime: Runtime,
    pub trusted_runtime: Runtime,
    pub trusted_compiler: Compiler,
    pub max_received_headers: usize,
    pub from_addr: IfBlock,
    pub from_name: IfBlock,
    pub return_path: IfBlock,
    pub sign: IfBlock,
    pub trusted_scripts: AHashMap<String, Arc<Sieve>>,
    pub untrusted_scripts: AHashMap<String, Arc<Sieve>>,
    pub http_client: reqwest::Client,
}

impl Scripting {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        // Parse untrusted compiler
        let untrusted = bp.setting_infallible::<SieveUserInterpreter>().await;
        let mut fnc_map_untrusted = register_functions_untrusted().register_plugins_untrusted();
        let untrusted_compiler = Compiler::new()
            .with_max_script_size(untrusted.max_script_size as usize)
            .with_max_string_size(untrusted.max_string_length as usize)
            .with_max_variable_name_size(untrusted.max_var_name_length as usize)
            .with_max_nested_blocks(untrusted.max_nested_blocks as usize)
            .with_max_nested_tests(untrusted.max_nested_tests as usize)
            .with_max_nested_foreverypart(untrusted.max_nested_for_every as usize)
            .with_max_match_variables(untrusted.max_match_vars as usize)
            .with_max_local_variables(untrusted.max_local_vars as usize)
            .with_max_header_size(untrusted.max_header_size as usize)
            .with_max_includes(untrusted.max_includes as usize)
            .register_functions(&mut fnc_map_untrusted);

        // Parse untrusted runtime
        let mut untrusted_runtime = Runtime::new()
            .with_functions(&mut fnc_map_untrusted)
            .with_max_nested_includes(untrusted.max_nested_includes as usize)
            .with_cpu_limit(untrusted.max_cpu_cycles as usize)
            .with_max_variable_size(untrusted.max_var_size as usize)
            .with_max_redirects(untrusted.max_redirects as usize)
            .with_max_received_headers(usize::MAX) // This is set to usize::MAX here, but the actual limit is enforced during ingestion.
            .with_max_header_size(untrusted.max_header_size as usize)
            .with_max_out_messages(untrusted.max_out_messages as usize)
            .with_default_vacation_expiry(untrusted.default_expiry_vacation.into_inner().as_secs())
            .with_default_duplicate_expiry(
                untrusted.default_expiry_duplicate.into_inner().as_secs(),
            )
            .with_capability(Capability::Expressions)
            .without_capabilities(
                untrusted
                    .disable_capabilities
                    .iter()
                    .map(|cap| cap.as_str()),
            )
            .with_valid_notification_uris(untrusted.allowed_notify_uris)
            .with_protected_headers(untrusted.protected_headers)
            .with_vacation_default_subject(untrusted.default_subject)
            .with_vacation_subject_prefix(untrusted.default_subject_prefix)
            .with_env_variable("name", "Stalwart Server")
            .with_env_variable("version", VERSION_PUBLIC)
            .with_env_variable("location", "MS")
            .with_env_variable("phase", "during");

        // Parse trusted compiler and runtime
        let mut fnc_map_trusted = register_functions_trusted().register_plugins_trusted();

        // Allocate compiler and runtime
        let trusted = bp.setting_infallible::<SieveSystemInterpreter>().await;
        let system = bp.setting_infallible::<SystemSettings>().await;
        let local_hostname = if !system.default_hostname.is_empty() {
            system.default_hostname.clone()
        } else {
            bp.registry.local_hostname().to_string()
        };
        let trusted_compiler = Compiler::new()
            .with_max_string_size(52428800)
            .with_max_variable_name_size(100)
            .with_max_nested_blocks(50)
            .with_max_nested_tests(50)
            .with_max_nested_foreverypart(10)
            .with_max_local_variables(8192)
            .with_max_header_size(10240)
            .with_max_includes(10)
            .with_no_capability_check(trusted.no_capability_check)
            .register_functions(&mut fnc_map_trusted);
        let mut trusted_runtime = Runtime::new()
            .without_capabilities([
                Capability::FileInto,
                Capability::Vacation,
                Capability::VacationSeconds,
                Capability::Fcc,
                Capability::Mailbox,
                Capability::MailboxId,
                Capability::MboxMetadata,
                Capability::ServerMetadata,
                Capability::ImapSieve,
                Capability::Duplicate,
            ])
            .with_capability(Capability::Expressions)
            .with_capability(Capability::While)
            .with_max_variable_size(trusted.max_var_size as usize)
            .with_max_header_size(10240)
            .with_valid_notification_uri("mailto")
            //.with_valid_ext_lists(stores.in_memory_stores.keys().map(|k| k.to_string()))
            .with_functions(&mut fnc_map_trusted)
            .with_max_redirects(trusted.max_redirects as usize)
            .with_max_out_messages(trusted.max_out_messages as usize)
            .with_cpu_limit(trusted.max_cpu_cycles as usize)
            .with_max_nested_includes(trusted.max_nested_includes as usize)
            .with_max_received_headers(trusted.max_received_headers as usize)
            .with_default_duplicate_expiry(trusted.duplicate_expiry.into_inner().as_secs());
        trusted_runtime.set_local_hostname(local_hostname.clone());
        untrusted_runtime.set_local_hostname(local_hostname);

        // Parse trusted scripts
        let mut trusted_scripts: AHashMap<String, Arc<Sieve>> = AHashMap::new();
        for script in bp.list_infallible::<SieveSystemScript>().await {
            if !script.object.is_active {
                continue;
            }

            match trusted_compiler.compile(script.object.contents.as_bytes()) {
                Ok(compiled) => match trusted_scripts.entry(script.object.name.to_lowercase()) {
                    Entry::Vacant(entry) => {
                        entry.insert(compiled.into());
                    }
                    Entry::Occupied(_) => {
                        bp.build_error(
                            script.id,
                            format!(
                                "Another active system Sieve script is already named {:?}, script names are case insensitive",
                                script.object.name
                            ),
                        );
                    }
                },
                Err(err) => {
                    bp.build_error(
                        script.id,
                        format!("Failed to compile system Sieve script: {err}"),
                    );
                }
            }
        }

        // Parse untrusted scripts
        let mut untrusted_scripts: AHashMap<String, Arc<Sieve>> = AHashMap::new();
        for script in bp.list_infallible::<SieveUserScript>().await {
            if !script.object.is_active {
                continue;
            }

            match untrusted_compiler.compile(script.object.contents.as_bytes()) {
                Ok(compiled) => match untrusted_scripts.entry(script.object.name.to_lowercase()) {
                    Entry::Vacant(entry) => {
                        entry.insert(compiled.into());
                    }
                    Entry::Occupied(_) => {
                        bp.build_error(
                            script.id,
                            format!(
                                "Another active user global Sieve script is already named {:?}, script names are case insensitive",
                                script.object.name
                            ),
                        );
                    }
                },
                Err(err) => {
                    bp.build_error(
                        script.id,
                        format!("Failed to compile user global Sieve script: {err}"),
                    );
                }
            }
        }

        Scripting {
            untrusted_compiler,
            untrusted_runtime,
            trusted_runtime,
            trusted_compiler,
            untrusted_scripts,
            trusted_scripts,
            http_client: utils::http::http_client_builder(cfg!(feature = "test_mode"))
                .pool_max_idle_per_host(0)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            max_received_headers: untrusted.max_received_headers as usize,
            from_addr: bp.compile_expr(
                ObjectType::SieveSystemScript.singleton(),
                &trusted.ctx_default_from_address(),
            ),
            from_name: bp.compile_expr(
                ObjectType::SieveSystemScript.singleton(),
                &trusted.ctx_default_from_name(),
            ),
            return_path: bp.compile_expr(
                ObjectType::SieveSystemScript.singleton(),
                &trusted.ctx_default_return_path(),
            ),
            sign: bp.compile_expr(
                ObjectType::SieveSystemScript.singleton(),
                &trusted.ctx_dkim_sign_domain(),
            ),
        }
    }

    pub fn trusted_script(&self, name: &str) -> Option<&Arc<Sieve>> {
        script_by_name(&self.trusted_scripts, name)
    }

    pub fn untrusted_script(&self, name: &str) -> Option<&Arc<Sieve>> {
        script_by_name(&self.untrusted_scripts, name)
    }
}

fn script_by_name<'x>(
    scripts: &'x AHashMap<String, Arc<Sieve>>,
    name: &str,
) -> Option<&'x Arc<Sieve>> {
    scripts
        .get(name)
        .or_else(|| scripts.get(name.to_lowercase().as_str()))
}

impl Clone for Scripting {
    fn clone(&self) -> Self {
        Self {
            untrusted_compiler: self.untrusted_compiler.clone(),
            untrusted_runtime: self.untrusted_runtime.clone(),
            trusted_runtime: self.trusted_runtime.clone(),
            from_addr: self.from_addr.clone(),
            from_name: self.from_name.clone(),
            return_path: self.return_path.clone(),
            max_received_headers: self.max_received_headers,
            sign: self.sign.clone(),
            trusted_scripts: self.trusted_scripts.clone(),
            untrusted_scripts: self.untrusted_scripts.clone(),
            trusted_compiler: self.trusted_compiler.clone(),
            http_client: self.http_client.clone(),
        }
    }
}
