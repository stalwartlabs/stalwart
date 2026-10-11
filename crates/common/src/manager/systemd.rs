/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Ready,
    Reloading,
    Stopping,
}

impl ServiceState {
    pub fn notify(self) {
        use sd_notify::{NotifyState, notify};

        let _ = match self {
            ServiceState::Ready => notify(&[NotifyState::Ready]),
            ServiceState::Stopping => notify(&[NotifyState::Stopping]),
            ServiceState::Reloading => NotifyState::monotonic_usec_now()
                .and_then(|now| notify(&[NotifyState::Reloading, now])),
        };
    }
}
