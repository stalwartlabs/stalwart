/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod config;
mod error;
mod material;
mod rules;
mod verifier;

pub use config::{PemSource, Plaintext, TlsConfig, TlsMode};
pub use error::{Material, TlsError};

use config::{Sources, Stamps};
use parking_lot::Mutex;
use rules::Policy;
use rustls::{ClientConfig, client::Resumption, crypto::aws_lc_rs};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_rustls::TlsConnector;
use verifier::PeerVerifier;

pub const DEFAULT_REFRESH: Duration = Duration::from_secs(12 * 60 * 60);
const RELOAD_RETRY: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct TlsContext {
    shared: Arc<TlsShared>,
}

struct TlsShared {
    sources: Sources,
    refresh: Duration,
    state: Mutex<LoadState>,
}

#[derive(Default)]
struct LoadState {
    loaded: Option<Result<TlsConnector, TlsError>>,
    stamps: Stamps,
    next_check: Option<Instant>,
}

impl TlsContext {
    pub fn new(config: &TlsConfig, refresh: Duration) -> Self {
        Self::with_sources(Sources::resolve(config), refresh)
    }

    pub fn from_mode(mode: &TlsMode, refresh: Duration) -> Self {
        match mode {
            TlsMode::DefaultFiles => Self::with_sources(Sources::default_files(), refresh),
            TlsMode::Explicit(config) => Self::new(config, refresh),
        }
    }

    fn with_sources(sources: Sources, refresh: Duration) -> Self {
        Self {
            shared: Arc::new(TlsShared {
                sources,
                refresh,
                state: Mutex::new(LoadState::default()),
            }),
        }
    }

    pub fn validate(&self) -> Result<(), TlsError> {
        self.connector().map(drop)
    }

    pub(crate) fn refuses_plaintext(&self) -> bool {
        self.shared.sources.plaintext == Plaintext::Refused
    }

    pub(crate) fn connector(&self) -> Result<TlsConnector, TlsError> {
        let shared = &*self.shared;
        let mut state = shared.state.lock();
        let now = Instant::now();
        if let Some(Ok(connector)) = &state.loaded
            && (shared.refresh.is_zero() || state.next_check.is_some_and(|next| now < next))
        {
            return Ok(connector.clone());
        }
        let stamps = shared.sources.stamps();
        let refreshed = now + shared.refresh;
        let (result, stamps, next_check) = match state.loaded.take() {
            Some(previous) if stamps == state.stamps => (previous, stamps, refreshed),
            previous => match (load(&shared.sources), previous) {
                (Ok(connector), _) => (Ok(connector), stamps, refreshed),
                (Err(_), Some(Ok(connector))) => (
                    Ok(connector),
                    state.stamps,
                    now + RELOAD_RETRY.min(shared.refresh),
                ),
                (Err(err), _) => (Err(err), stamps, refreshed),
            },
        };
        state.stamps = stamps;
        state.next_check = Some(next_check);
        state.loaded = Some(result.clone());
        result
    }
}

fn load(sources: &Sources) -> Result<TlsConnector, TlsError> {
    if let Some(missing) = sources.unpaired {
        return Err(TlsError::Unpaired { missing });
    }
    let policy = Policy::parse(&sources.verify_peers)?;
    let roots = match &sources.ca {
        Some(source) => {
            material::certificates(&material::read(source, Material::Ca)?, Material::Ca)?
        }
        None => Vec::new(),
    };
    let identity = match (&sources.certificate, &sources.key) {
        (Some(certificate), Some(key)) => Some((
            material::certificates(
                &material::read(certificate, Material::Certificate)?,
                Material::Certificate,
            )?,
            material::private_key(
                &material::read(key, Material::Key)?,
                sources.password.as_deref(),
            )?,
        )),
        _ => None,
    };
    let provider = Arc::new(aws_lc_rs::default_provider());
    let verifier = PeerVerifier::new(roots, policy, provider.signature_verification_algorithms)?;
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    let mut config = match identity {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key)?,
        None => builder.with_no_client_auth(),
    };
    config.resumption = Resumption::disabled();
    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/tls/tests.rs"]
pub(crate) mod tests;
