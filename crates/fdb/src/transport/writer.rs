/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    burst::BurstHold,
    config::Coalesce,
    peer::{MAX_RETAINED_BUFFER, Outbox, PeerShared},
    protocol::CONNECT_PACKET_LEN,
};
use std::{
    future::poll_fn,
    io::{self, IoSlice},
    sync::Arc,
    task::Poll,
};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    task::yield_now,
};

pub(crate) async fn run<W: AsyncWrite + Unpin>(
    peer: Arc<PeerShared>,
    mut half: W,
    hello: [u8; CONNECT_PACKET_LEN],
) -> io::Result<()> {
    let coalesce = peer.transport.config.coalesce;
    let mut out = Outbox {
        buf: hello.to_vec(),
        separate: Vec::new(),
    };
    let mut received = peer.frames_received();
    let mut taken = peer.append_queued(&mut out);
    let mut burst = BurstHold::default();
    loop {
        let writes = if out.separate.is_empty() {
            let mut pending = out.buf.as_slice();
            let mut writes = 0;
            while !pending.is_empty() {
                let written = half.write(pending).await?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                pending = pending.get(written..).unwrap_or_default();
                writes += 1;
            }
            writes
        } else {
            write_segments(&mut half, &out).await?
        };
        half.flush().await?;
        peer.record_writes(out.len(), writes);
        out.clear();
        if out.buf.capacity() > MAX_RETAINED_BUFFER {
            out.buf = Vec::new();
        }
        let queued = poll_fn(|cx| peer.poll_queued(cx)).await;
        let mut yielded = false;
        let take = match coalesce {
            Coalesce::Immediate => None,
            Coalesce::Requeue => {
                requeue_for_woken(&peer, queued, taken, received).await;
                None
            }
            Coalesce::Yield => {
                yield_now().await;
                None
            }
            Coalesce::Burst => {
                yielded = burst.admits_yield(queued.wrapping_sub(taken));
                if yielded {
                    yield_now().await;
                }
                if burst.gated(peer.reply_floor()) {
                    None
                } else {
                    Some(burst.prepare(&peer, taken, queued).await)
                }
            }
        };
        received = peer.frames_received();
        let previous = taken;
        taken = peer.take_queued(&mut out);
        if yielded {
            burst.record_yield(take.as_ref(), taken.wrapping_sub(queued));
        }
        if let Some(take) = take {
            burst.record(take, taken.wrapping_sub(previous), received);
        }
        #[cfg(all(test, stalwart_tests))]
        if coalesce == Coalesce::Burst {
            peer.record_burst(burst.stats());
        }
    }
}

async fn write_segments<W: AsyncWrite + Unpin>(half: &mut W, out: &Outbox) -> io::Result<u64> {
    let mut slices: Vec<IoSlice<'_>> = out.segments().map(IoSlice::new).collect();
    let mut pending = slices.as_mut_slice();
    let mut remaining = out.len();
    let mut writes = 0;
    while remaining > 0 {
        let written = half.write_vectored(pending).await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let written = written.min(remaining);
        remaining -= written;
        IoSlice::advance_slices(&mut pending, written);
        writes += 1;
    }
    Ok(writes)
}

const MAX_REQUEUES: usize = 4;
const REQUEUE_FRAME_CAP: u64 = 16;

async fn requeue_for_woken(peer: &PeerShared, mut queued: u64, taken: u64, received: u64) {
    for _ in 0..MAX_REQUEUES {
        let batch = queued.wrapping_sub(taken);
        if batch >= REQUEUE_FRAME_CAP {
            break;
        }
        let woken = peer.frames_received().wrapping_sub(received);
        if batch >= woken && peer.waiting_replies() < 2 {
            break;
        }
        requeue().await;
        let grown = peer.queued_frames();
        if grown == queued {
            break;
        }
        queued = grown;
    }
}

async fn requeue() {
    let mut requeued = false;
    poll_fn(|cx| {
        if requeued {
            return Poll::Ready(());
        }
        requeued = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/transport/writer/tests.rs"]
mod tests;
