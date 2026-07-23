/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use types::id::Id;

use crate::schema::prelude::{
    Account, Credential, GroupAccount, PasswordCredential, SecondaryCredential, UserAccount,
};

impl Account {
    pub fn into_user(self) -> Option<UserAccount> {
        if let Account::User(user) = self {
            Some(user)
        } else {
            None
        }
    }

    pub fn into_group(self) -> Option<GroupAccount> {
        if let Account::Group(group) = self {
            Some(group)
        } else {
            None
        }
    }
}

impl UserAccount {
    pub fn set_password(&mut self, password: String) {
        if let Some(credential) = self.credentials.0.values_mut().find_map(|credential| {
            if let Credential::Password(credential) = credential {
                Some(credential)
            } else {
                None
            }
        }) {
            credential.secret = password;
        } else {
            let credential_id = self.next_credential_id().into();
            self.credentials
                .push(Credential::Password(PasswordCredential {
                    credential_id,
                    secret: password,
                    ..Default::default()
                }));
        }
    }

    pub fn password_credential(&self) -> Option<&PasswordCredential> {
        self.credentials.iter().find_map(|credential| {
            if let Credential::Password(credential) = credential {
                Some(credential)
            } else {
                None
            }
        })
    }

    pub fn password_credential_mut(&mut self) -> Option<&mut PasswordCredential> {
        self.credentials.values_mut().find_map(|credential| {
            if let Credential::Password(credential) = credential {
                Some(credential)
            } else {
                None
            }
        })
    }

    pub fn password(&self) -> Option<&str> {
        self.password_credential()
            .map(|credential| credential.secret.as_str())
    }

    pub fn into_password_credential(self) -> Option<PasswordCredential> {
        self.credentials.into_iter().find_map(|credential| {
            if let Credential::Password(credential) = credential {
                Some(credential)
            } else {
                None
            }
        })
    }

    pub fn into_password(self) -> Option<String> {
        self.into_password_credential()
            .map(|credential| credential.secret)
    }

    pub fn next_credential_id(&self) -> u64 {
        self.credentials
            .0
            .values()
            .map(|credential| match credential {
                Credential::Password(credential) => credential.credential_id.id() + 1,
                Credential::AppPassword(credential_properties)
                | Credential::ApiKey(credential_properties) => {
                    credential_properties.credential_id.id() + 1
                }
            })
            .max()
            .unwrap_or_default()
    }
}

impl Credential {
    pub fn credential_id(&self) -> Id {
        match self {
            Credential::Password(credential) => credential.credential_id,
            Credential::AppPassword(credential_properties) => credential_properties.credential_id,
            Credential::ApiKey(credential_properties) => credential_properties.credential_id,
        }
    }

    pub fn set_credential_id(&mut self, credential_id: Id) {
        match self {
            Credential::Password(credential) => credential.credential_id = credential_id,
            Credential::AppPassword(credential_properties) => {
                credential_properties.credential_id = credential_id
            }
            Credential::ApiKey(credential_properties) => {
                credential_properties.credential_id = credential_id
            }
        }
    }

    pub fn into_secondary_credential(self) -> Option<SecondaryCredential> {
        match self {
            Credential::AppPassword(credential_properties) => Some(credential_properties),
            Credential::ApiKey(credential_properties) => Some(credential_properties),
            Credential::Password(_) => None,
        }
    }

    pub fn as_secondary_credential(&self) -> Option<&SecondaryCredential> {
        match self {
            Credential::AppPassword(credential_properties) => Some(credential_properties),
            Credential::ApiKey(credential_properties) => Some(credential_properties),
            Credential::Password(_) => None,
        }
    }

    pub fn as_main_credential(&self) -> Option<&PasswordCredential> {
        match self {
            Credential::Password(credential) => Some(credential),
            Credential::AppPassword(_) | Credential::ApiKey(_) => None,
        }
    }
}
