/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqlDirectory, SqlMappings};
use crate::{Account, Credentials, Recipient, core::secret::verify_secret_hash};
use store::{NamedRows, Rows, Value};
use trc::AddContext;
use utils::sanitize_email;

impl SqlDirectory {
    pub async fn authenticate(&self, credentials: &Credentials) -> trc::Result<Account> {
        let (username, secret) = match credentials {
            Credentials::Basic { username, secret } => (username, secret),
            Credentials::Bearer { .. } => {
                return Err(trc::AuthEvent::Error
                    .into_err()
                    .details("Unsupported credentials type for SQL authentication"));
            }
        };

        let Recipient::Account(mut account) = self.mappings.row_to_account(
            self.sql_store
                .sql_query::<NamedRows>(&self.mappings.query_login, vec![username.into()])
                .await
                .caused_by(trc::location!())?,
        ) else {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("SQL login query did not return an account")
                .ctx(trc::Key::AccountName, username.to_string()));
        };

        // Validate secret
        if let Some(account_secret) = &account.secret {
            if !verify_secret_hash(account_secret, secret.as_bytes()).await? {
                return Err(trc::AuthEvent::Failed
                    .into_err()
                    .details("Invalid credentials")
                    .ctx(trc::Key::AccountName, username.to_string()));
            }
        } else {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("Account does not have a secret")
                .ctx(trc::Key::AccountName, username.to_string()));
        }

        // Obtain members
        if let Some(query) = &self.mappings.query_member_of {
            for row in self
                .sql_store
                .sql_query::<Rows>(query, vec![username.into()])
                .await
                .caused_by(trc::location!())?
                .rows
            {
                if let Some(Value::Text(address)) = row.values.first()
                    && let Some(email) = sanitize_email(address)
                {
                    account.groups.push(email);
                }
            }
        }

        // Obtain emails
        if let Some(query) = &self.mappings.query_email_aliases {
            account.email_aliases.extend(
                self.sql_store
                    .sql_query::<Rows>(query, vec![username.into()])
                    .await
                    .caused_by(trc::location!())?
                    .rows
                    .into_iter()
                    .flat_map(|v| {
                        v.values
                            .into_iter()
                            .filter_map(|v| sanitize_email(v.to_str().as_ref()))
                    }),
            );
        }

        if account.email.is_empty() {
            account.email = sanitize_email(username).unwrap_or_else(|| username.to_lowercase());
        }

        Ok(account)
    }

    pub async fn recipient(&self, address: &str) -> trc::Result<Recipient> {
        let recipient = self.mappings.row_to_account(
            self.sql_store
                .sql_query::<NamedRows>(&self.mappings.query_recipient, vec![address.into()])
                .await
                .caused_by(trc::location!())?,
        );

        match recipient {
            Recipient::Account(mut account) => {
                // Obtain members
                if let Some(query) = &self.mappings.query_member_of {
                    for row in self
                        .sql_store
                        .sql_query::<Rows>(query, vec![account.email.as_str().into()])
                        .await
                        .caused_by(trc::location!())?
                        .rows
                    {
                        if let Some(Value::Text(address)) = row.values.first()
                            && let Some(email) = sanitize_email(address)
                        {
                            account.groups.push(email);
                        }
                    }
                }

                // Obtain emails
                if let Some(query) = &self.mappings.query_email_aliases {
                    account.email_aliases.extend(
                        self.sql_store
                            .sql_query::<Rows>(query, vec![account.email.as_str().into()])
                            .await
                            .caused_by(trc::location!())?
                            .rows
                            .into_iter()
                            .flat_map(|v| {
                                v.values
                                    .into_iter()
                                    .filter_map(|v| sanitize_email(v.to_str().as_ref()))
                            }),
                    );
                }

                Ok(Recipient::Account(account))
            }
            Recipient::Group(group) => Ok(Recipient::Group(group)),
            Recipient::Invalid => Ok(Recipient::Invalid),
        }
    }
}

impl SqlMappings {
    pub fn row_to_account(&self, rows: NamedRows) -> Recipient {
        if rows.rows.is_empty() {
            return Recipient::Invalid;
        }

        let mut account = Account::default();
        let mut is_group = false;

        if let Some(row) = rows.rows.into_iter().next() {
            for (name, value) in rows.names.into_iter().zip(row.values) {
                if name.eq_ignore_ascii_case(&self.column_email) {
                    if let Value::Text(text) = value
                        && let Some(email) = sanitize_email(&text)
                    {
                        account.email = email;
                    }
                } else if name.eq_ignore_ascii_case(&self.column_secret) {
                    if let Value::Text(text) = value {
                        account.secret = Some(text.into_owned());
                    }
                } else if let Some(column_type) = &self.column_type
                    && name.eq_ignore_ascii_case(column_type)
                {
                    is_group = value.to_str().eq_ignore_ascii_case("group");
                } else if let Some(column_description) = &self.column_description
                    && name.eq_ignore_ascii_case(column_description)
                    && let Value::Text(text) = value
                {
                    account.description = Some(text.into_owned());
                }
            }
        }

        if !is_group {
            Recipient::Account(account)
        } else {
            Recipient::Group(crate::Group {
                email: account.email,
                email_aliases: account.email_aliases,
                description: account.description,
            })
        }
    }
}
