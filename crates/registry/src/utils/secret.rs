/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::{
    SecretKey, SecretKeyEnvironmentVariable, SecretKeyFile, SecretKeyOptional, SecretKeyValue,
    SecretText, SecretTextOptional, SecretTextValue,
};
use std::borrow::Cow;

impl SecretKey {
    pub async fn secret(&self) -> Result<Cow<'_, str>, String> {
        match self {
            SecretKey::Value(value) => Ok(Cow::Borrowed(value.secret())),
            SecretKey::File(file) => file.secret().await.map(Cow::Owned),
            SecretKey::EnvironmentVariable(env_var) => env_var.secret().map(Cow::Owned),
        }
    }
}

impl SecretText {
    pub async fn secret(&self) -> Result<Cow<'_, str>, String> {
        match self {
            SecretText::Text(value) => Ok(Cow::Borrowed(value.secret())),
            SecretText::File(file) => file.secret().await.map(Cow::Owned),
            SecretText::EnvironmentVariable(env_var) => env_var.secret().map(Cow::Owned),
        }
    }
}

impl SecretKeyOptional {
    pub async fn secret(&self) -> Result<Option<Cow<'_, str>>, String> {
        match self {
            SecretKeyOptional::None => Ok(None),
            SecretKeyOptional::Value(secret_key_value) => {
                Ok(Some(Cow::Borrowed(secret_key_value.secret())))
            }
            SecretKeyOptional::EnvironmentVariable(secret_key_environment_variable) => {
                secret_key_environment_variable
                    .secret()
                    .map(|s| Some(Cow::Owned(s)))
            }
            SecretKeyOptional::File(secret_key_file) => {
                secret_key_file.secret().await.map(|s| Some(Cow::Owned(s)))
            }
        }
    }
}

impl SecretTextOptional {
    pub async fn secret(&self) -> Result<Option<Cow<'_, str>>, String> {
        match self {
            SecretTextOptional::None => Ok(None),
            SecretTextOptional::Text(secret_text_value) => {
                Ok(Some(Cow::Borrowed(secret_text_value.secret())))
            }
            SecretTextOptional::EnvironmentVariable(secret_text_environment_variable) => {
                secret_text_environment_variable
                    .secret()
                    .map(|s| Some(Cow::Owned(s)))
            }
            SecretTextOptional::File(secret_text_file) => {
                secret_text_file.secret().await.map(|s| Some(Cow::Owned(s)))
            }
        }
    }
}

impl SecretKeyValue {
    pub fn secret(&self) -> &str {
        self.secret.as_str()
    }
}

impl SecretTextValue {
    pub fn secret(&self) -> &str {
        self.secret.as_str()
    }
}

impl SecretKeyFile {
    pub async fn secret(&self) -> Result<String, String> {
        let path = self.file_path.trim();
        if !path.is_empty() {
            tokio::fs::read_to_string(path)
                .await
                .map_err(|err| format!("Failed to read secret from file '{}': {}", path, err))
                .and_then(|content| {
                    let secret = content.trim_end();
                    if !secret.is_empty() {
                        Ok(secret.to_string())
                    } else {
                        Err(format!("Secret in file '{}' is empty", path))
                    }
                })
        } else {
            Err("File path cannot be empty".to_string())
        }
    }
}

impl SecretKeyEnvironmentVariable {
    pub fn secret(&self) -> Result<String, String> {
        let var = self.variable_name.trim();
        if !var.is_empty() {
            std::env::var(var)
                .ok()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("Environment variable '{}' not found", var))
        } else {
            Err("Variable name cannot be empty".to_string())
        }
    }
}
