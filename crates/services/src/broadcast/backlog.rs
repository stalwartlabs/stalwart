/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{BroadcastBatch, MAX_BATCH_SIZE};
use common::ipc::{
    BroadcastEvent, CacheInvalidation, PushNotification, QueueNames, RegistryChange,
    ViewerStateChange,
};
use std::{collections::VecDeque, mem::size_of};
use store::{
    ahash::{AHashMap, AHashSet},
    write::TaskTypes,
};
use types::type_state::StateChange;
use utils::map::bitmap::Bitmap;

pub(crate) const MAX_PENDING_EVENTS: usize = 65_536;
pub(crate) const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;
const LOW_WATER_NUMERATOR: usize = 7;
const LOW_WATER_DENOMINATOR: usize = 8;
const INVALIDATE_ALL_THRESHOLD: usize = 1024;
const MAX_INVALIDATIONS_PER_EVENT: usize = 1024;
const MAX_CHUNK_BYTES: usize = 256 * 1024;

const EVENT_COST: usize = size_of::<BroadcastEvent>();
const INVALIDATION_COST: usize = size_of::<CacheInvalidation>() + size_of::<u64>();
const STATE_KEY_COST: usize = size_of::<(StateKey, Vec<TypeState>)>() + size_of::<u64>();
const TYPE_STATE_COST: usize = size_of::<TypeState>();
const PUSH_UPDATE_COST: usize = size_of::<u32>() + size_of::<u64>();

#[derive(Debug, Default)]
pub(crate) struct Backlog {
    ready: VecDeque<BroadcastEvent>,
    ready_bytes: usize,
    registry_changes: Vec<RegistryChange>,
    queue_status: Option<bool>,
    push_updates: AHashSet<u32>,
    invalidate_negative: bool,
    events: VecDeque<BroadcastEvent>,
    events_bytes: usize,
    state_changes: AHashMap<StateKey, Vec<TypeState>>,
    type_states: usize,
    invalidations: AHashSet<CacheInvalidation>,
    invalidate_all: bool,
    refresh_queues: QueueNames,
    refresh_tasks: TaskTypes,
    refresh_index: bool,
    in_flight: usize,
    in_flight_bytes: usize,
    degraded: bool,
    dropped: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum StateKey {
    Account(u32),
    Viewer { viewer_id: u32, account_id: u32 },
}

#[derive(Debug, Clone, Copy)]
struct TypeState {
    types: u64,
    change_id: u64,
}

impl Backlog {
    pub fn push(&mut self, event: BroadcastEvent) {
        match event {
            BroadcastEvent::PushNotification(PushNotification::StateChange(change)) => {
                self.push_state(
                    StateKey::Account(change.account_id),
                    *change.types,
                    change.change_id,
                );
            }
            BroadcastEvent::PushNotification(PushNotification::ViewerStateChange(change)) => {
                self.push_state(
                    StateKey::Viewer {
                        viewer_id: change.viewer_id,
                        account_id: change.change.account_id,
                    },
                    *change.change.types,
                    change.change.change_id,
                );
            }
            BroadcastEvent::PushNotification(PushNotification::EmailPush(push))
                if self.degraded =>
            {
                let change = push.to_state_change();
                self.push_state(
                    StateKey::Account(change.account_id),
                    *change.types,
                    change.change_id,
                );
            }
            BroadcastEvent::CacheInvalidate(items) => {
                for item in items {
                    self.push_invalidation(item);
                }
            }
            BroadcastEvent::CacheInvalidateAll => self.invalidate_all(),
            BroadcastEvent::CacheInvalidateNegative => {
                self.invalidate_negative |= !self.invalidate_all;
            }
            BroadcastEvent::RegistryChange(change) => self.push_registry_change(change),
            BroadcastEvent::MtaQueueStatus { is_running } => self.queue_status = Some(is_running),
            BroadcastEvent::PushServerUpdate(account_id) => {
                self.push_updates.insert(account_id);
            }
            BroadcastEvent::QueueRefresh(queues) => self.refresh_queues.merge(&queues),
            BroadcastEvent::TaskQueueRefresh(task_types) => self.refresh_tasks.union(task_types),
            BroadcastEvent::IndexQueueRefresh => self.refresh_index = true,
            event => {
                self.events_bytes += event_cost(&event);
                self.events.push_back(event);
            }
        }
        self.enforce_limits();
    }

    pub fn fill(&mut self, batch: &mut BroadcastBatch<Vec<BroadcastEvent>>) -> bool {
        if !batch.messages.is_empty() {
            return true;
        }
        if self.ready.is_empty() {
            self.snapshot();
        }
        let mut chunk_bytes = 0;
        while batch.messages.len() < MAX_BATCH_SIZE {
            let Some(event) = self.ready.front() else {
                break;
            };
            let cost = event_cost(event);
            if !batch.messages.is_empty() && chunk_bytes + cost > MAX_CHUNK_BYTES {
                break;
            }
            chunk_bytes += cost;
            self.ready_bytes -= cost;
            batch.messages.extend(self.ready.pop_front());
        }
        self.in_flight = batch.messages.len();
        self.in_flight_bytes = chunk_bytes;
        !batch.messages.is_empty()
    }

    pub fn release(&mut self, batch: &mut BroadcastBatch<Vec<BroadcastEvent>>) {
        batch.clear();
        self.in_flight = 0;
        self.in_flight_bytes = 0;
    }

    pub fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.in_flight
            + self.ready.len()
            + self.registry_changes.len()
            + usize::from(self.queue_status.is_some())
            + self.push_updates.len()
            + usize::from(self.invalidate_negative)
            + self.events.len()
            + self.type_states
            + self.invalidations.len()
            + usize::from(self.invalidate_all)
            + usize::from(!self.refresh_queues.is_empty())
            + usize::from(!self.refresh_tasks.is_empty())
            + usize::from(self.refresh_index)
    }

    pub fn bytes(&self) -> usize {
        self.in_flight_bytes
            + self.ready_bytes
            + self.registry_changes.len() * EVENT_COST
            + self.push_updates.len() * PUSH_UPDATE_COST
            + self.events_bytes
            + self.state_changes.len() * STATE_KEY_COST
            + self.type_states * TYPE_STATE_COST
            + self.invalidations.len() * INVALIDATION_COST
    }

    fn push_state(&mut self, key: StateKey, types: u64, change_id: u64) {
        if types == 0 {
            return;
        }
        let states = self.state_changes.entry(key).or_default();
        let before = states.len();
        merge_state(states, types, change_id);
        self.type_states = self.type_states + states.len() - before;
    }

    fn push_invalidation(&mut self, item: CacheInvalidation) {
        if self.invalidate_all && item.is_covered_by_invalidate_all() {
            return;
        }
        self.invalidations.insert(item);
        if !self.invalidate_all && self.invalidations.len() > INVALIDATE_ALL_THRESHOLD {
            self.invalidate_all();
        }
    }

    fn invalidate_all(&mut self) {
        self.invalidate_all = true;
        self.invalidate_negative = false;
        self.invalidations
            .retain(|item| !item.is_covered_by_invalidate_all());
    }

    fn push_registry_change(&mut self, change: RegistryChange) {
        let object = change.object();
        match self
            .registry_changes
            .iter_mut()
            .find(|pending| pending.object() == object)
        {
            Some(pending) if *pending != change => *pending = RegistryChange::Reload(object),
            Some(_) => {}
            None => self.registry_changes.push(change),
        }
    }

    fn snapshot(&mut self) {
        if std::mem::take(&mut self.invalidate_all) {
            self.push_ready(BroadcastEvent::CacheInvalidateAll);
        }
        while !self.invalidations.is_empty() {
            let items = if self.invalidations.len() <= MAX_INVALIDATIONS_PER_EVENT {
                self.invalidations.drain().collect::<Vec<_>>()
            } else {
                let items = self
                    .invalidations
                    .iter()
                    .take(MAX_INVALIDATIONS_PER_EVENT)
                    .copied()
                    .collect::<Vec<_>>();
                for item in &items {
                    self.invalidations.remove(item);
                }
                items
            };
            self.push_ready(BroadcastEvent::CacheInvalidate(items));
        }
        if std::mem::take(&mut self.invalidate_negative) {
            self.push_ready(BroadcastEvent::CacheInvalidateNegative);
        }
        for change in std::mem::take(&mut self.registry_changes) {
            self.push_ready(BroadcastEvent::RegistryChange(change));
        }
        if let Some(is_running) = self.queue_status.take() {
            self.push_ready(BroadcastEvent::MtaQueueStatus { is_running });
        }
        for account_id in std::mem::take(&mut self.push_updates) {
            self.push_ready(BroadcastEvent::PushServerUpdate(account_id));
        }
        self.ready_bytes += std::mem::take(&mut self.events_bytes);
        self.ready.append(&mut self.events);
        self.type_states = 0;
        for (key, states) in self.state_changes.drain() {
            for state in states {
                let change = StateChange {
                    account_id: key.account_id(),
                    change_id: state.change_id,
                    types: Bitmap::from(state.types),
                };
                let notification = match key {
                    StateKey::Account(_) => PushNotification::StateChange(change),
                    StateKey::Viewer { viewer_id, .. } => {
                        PushNotification::ViewerStateChange(ViewerStateChange { viewer_id, change })
                    }
                };
                self.ready_bytes += EVENT_COST;
                self.ready
                    .push_back(BroadcastEvent::PushNotification(notification));
            }
        }
        if !self.refresh_queues.is_empty() {
            let queues = std::mem::take(&mut self.refresh_queues);
            self.push_ready(BroadcastEvent::QueueRefresh(queues));
        }
        if !self.refresh_tasks.is_empty() {
            let task_types = std::mem::take(&mut self.refresh_tasks);
            self.push_ready(BroadcastEvent::TaskQueueRefresh(task_types));
        }
        if std::mem::take(&mut self.refresh_index) {
            self.push_ready(BroadcastEvent::IndexQueueRefresh);
        }
        self.enforce_limits();
    }

    fn push_ready(&mut self, event: BroadcastEvent) {
        self.ready_bytes += event_cost(&event);
        self.ready.push_back(event);
    }

    fn enforce_limits(&mut self) {
        if self.len() > MAX_PENDING_EVENTS || self.bytes() > MAX_PENDING_BYTES {
            self.relieve();
        }
    }

    #[cold]
    #[inline(never)]
    fn relieve(&mut self) {
        if !self.invalidate_all && !self.invalidations.is_empty() {
            self.invalidate_all();
        }
        if !self.degraded {
            self.degrade_email_pushes();
        }
        if self.len() <= MAX_PENDING_EVENTS && self.bytes() <= MAX_PENDING_BYTES {
            return;
        }

        let low_len = MAX_PENDING_EVENTS / LOW_WATER_DENOMINATOR * LOW_WATER_NUMERATOR;
        let low_bytes = MAX_PENDING_BYTES / LOW_WATER_DENOMINATOR * LOW_WATER_NUMERATOR;
        let mut dropped = 0u64;
        let is_over = |backlog: &Self| backlog.len() > low_len || backlog.bytes() > low_bytes;

        if is_over(self) {
            let ready_bytes = &mut self.ready_bytes;
            self.ready.retain(|event| {
                if matches!(event, BroadcastEvent::PushNotification(_)) {
                    *ready_bytes -= event_cost(event);
                    dropped += 1;
                    false
                } else {
                    true
                }
            });
        }
        if is_over(self) {
            let mut excess_len = self.len().saturating_sub(low_len);
            let mut excess_bytes = self.bytes().saturating_sub(low_bytes);
            let mut removed_states = 0;
            self.state_changes.retain(|_, states| {
                if excess_len == 0 && excess_bytes == 0 {
                    return true;
                }
                excess_len = excess_len.saturating_sub(states.len());
                excess_bytes =
                    excess_bytes.saturating_sub(STATE_KEY_COST + states.len() * TYPE_STATE_COST);
                removed_states += states.len();
                false
            });
            self.type_states -= removed_states;
            dropped += removed_states as u64;
        }
        while is_over(self) {
            let Some(event) = self.events.pop_front() else {
                break;
            };
            self.events_bytes -= event_cost(&event);
            dropped += 1;
        }
        if is_over(self) {
            dropped += self.invalidations.len() as u64;
            self.invalidations.clear();
        }
        if dropped > 0 {
            self.dropped += dropped;
            self.invalidate_all();
        }
    }

    fn degrade_email_pushes(&mut self) {
        self.degraded = true;
        let mut pushes = Vec::new();
        for (events, bytes) in [
            (&mut self.ready, &mut self.ready_bytes),
            (&mut self.events, &mut self.events_bytes),
        ] {
            events.retain(|event| match event {
                BroadcastEvent::PushNotification(PushNotification::EmailPush(push)) => {
                    pushes.push(push.to_state_change());
                    *bytes -= EVENT_COST;
                    false
                }
                _ => true,
            });
        }
        for change in pushes {
            self.push_state(
                StateKey::Account(change.account_id),
                *change.types,
                change.change_id,
            );
        }
    }
}

impl StateKey {
    fn account_id(&self) -> u32 {
        match self {
            StateKey::Account(account_id) | StateKey::Viewer { account_id, .. } => *account_id,
        }
    }
}

fn merge_state(states: &mut Vec<TypeState>, mut types: u64, change_id: u64) {
    for state in states.iter_mut() {
        let overlap = state.types & types;
        if overlap != 0 {
            if state.change_id >= change_id {
                types &= !overlap;
            } else {
                state.types &= !overlap;
            }
        }
    }
    states.retain(|state| state.types != 0);
    if types != 0 {
        match states.iter_mut().find(|state| state.change_id == change_id) {
            Some(state) => state.types |= types,
            None => states.push(TypeState { types, change_id }),
        }
    }
}

fn event_cost(event: &BroadcastEvent) -> usize {
    EVENT_COST
        + match event {
            BroadcastEvent::PushNotification(PushNotification::CalendarAlert(alert)) => {
                alert.uid.capacity() + alert.alert_id.capacity()
            }
            BroadcastEvent::CacheInvalidate(items) => {
                items.capacity() * size_of::<CacheInvalidation>()
            }
            _ => 0,
        }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/services/src/broadcast/backlog/tests.rs"]
mod tests;
