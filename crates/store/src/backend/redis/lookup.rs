/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{RedisPool, RedisStore, into_error};
use crate::{Deserialize, write::now};
use redis::AsyncCommands;

impl RedisStore {
    pub async fn key_set(&self, key: &[u8], value: &[u8], expires: Option<u64>) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_set_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
            RedisPool::Cluster(pool) => {
                self.key_set_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
            RedisPool::Sentinel(pool) => {
                self.key_set_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
        }
    }

    pub async fn key_incr(&self, key: &[u8], value: i64, expires: Option<u64>) -> trc::Result<i64> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_incr_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
            RedisPool::Cluster(pool) => {
                self.key_incr_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
            RedisPool::Sentinel(pool) => {
                self.key_incr_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    key,
                    value,
                    expires,
                )
                .await
            }
        }
    }

    pub async fn try_lock(&self, key: &[u8], expires: u64) -> trc::Result<bool> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.try_lock_(pool.get().await.map_err(into_error)?.as_mut(), key, expires)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.try_lock_(pool.get().await.map_err(into_error)?.as_mut(), key, expires)
                    .await
            }
            RedisPool::Sentinel(pool) => {
                self.try_lock_(pool.get().await.map_err(into_error)?.as_mut(), key, expires)
                    .await
            }
        }
    }

    pub async fn renew_lock(&self, key: &[u8], expires: u64) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.renew_lock_(pool.get().await.map_err(into_error)?.as_mut(), key, expires)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.renew_lock_(pool.get().await.map_err(into_error)?.as_mut(), key, expires)
                    .await
            }
            RedisPool::Sentinel(pool) => {
                self.renew_lock_(pool.get().await.map_err(into_error)?.as_mut(), key, expires)
                    .await
            }
        }
    }

    pub async fn key_delete(&self, key: &[u8]) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_delete_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.key_delete_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Sentinel(pool) => {
                self.key_delete_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
        }
    }

    pub async fn chunks_get(&self, prefix: &[u8], count: u32) -> trc::Result<Option<Vec<u8>>> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.chunks_get_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    prefix,
                    count,
                )
                .await
            }
            RedisPool::Cluster(pool) => {
                self.chunks_get_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    prefix,
                    count,
                )
                .await
            }
            RedisPool::Sentinel(pool) => {
                self.chunks_get_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    prefix,
                    count,
                )
                .await
            }
        }
    }

    pub async fn chunks_set(
        &self,
        prefix: &[u8],
        data: &[u8],
        chunk_size: usize,
        expires: Option<u64>,
    ) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.chunks_set_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    prefix,
                    data,
                    chunk_size,
                    expires,
                )
                .await
            }
            RedisPool::Cluster(pool) => {
                self.chunks_set_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    prefix,
                    data,
                    chunk_size,
                    expires,
                )
                .await
            }
            RedisPool::Sentinel(pool) => {
                self.chunks_set_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    prefix,
                    data,
                    chunk_size,
                    expires,
                )
                .await
            }
        }
    }

    pub async fn chunks_delete(&self, prefix: &[u8], from: u32, to: u32) -> trc::Result<()> {
        if from >= to {
            return Ok(());
        }
        match &self.pool {
            RedisPool::Single(pool) => {
                self.chunks_delete_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    prefix,
                    from,
                    to,
                )
                .await
            }
            RedisPool::Cluster(pool) => {
                self.chunks_delete_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    prefix,
                    from,
                    to,
                )
                .await
            }
            RedisPool::Sentinel(pool) => {
                self.chunks_delete_(
                    pool.get().await.map_err(into_error)?.as_mut(),
                    prefix,
                    from,
                    to,
                )
                .await
            }
        }
    }

    async fn chunks_get_(
        &self,
        conn: &mut impl AsyncCommands,
        prefix: &[u8],
        count: u32,
    ) -> trc::Result<Option<Vec<u8>>> {
        let mut pipeline = redis::pipe();
        for index in 0..count {
            pipeline.cmd("GET").arg(chunk_key(prefix, index));
        }

        let chunks = pipeline
            .query_async::<Vec<Option<Vec<u8>>>>(conn)
            .await
            .map_err(into_error)?;

        let mut data = Vec::with_capacity(chunks.iter().flatten().map(Vec::len).sum());
        for chunk in chunks {
            match chunk {
                Some(chunk) => data.extend_from_slice(&chunk),
                None => return Ok(None),
            }
        }

        Ok(Some(data))
    }

    async fn chunks_set_(
        &self,
        conn: &mut impl AsyncCommands,
        prefix: &[u8],
        data: &[u8],
        chunk_size: usize,
        expires: Option<u64>,
    ) -> trc::Result<()> {
        let mut pipeline = redis::pipe();
        for (index, chunk) in data.chunks(chunk_size).enumerate() {
            let key = chunk_key(prefix, index as u32);
            match expires {
                Some(expires) => {
                    pipeline.cmd("SETEX").arg(key).arg(expires).arg(chunk);
                }
                None => {
                    pipeline.cmd("SET").arg(key).arg(chunk);
                }
            }
        }

        pipeline.query_async::<()>(conn).await.map_err(into_error)
    }

    async fn chunks_delete_(
        &self,
        conn: &mut impl AsyncCommands,
        prefix: &[u8],
        from: u32,
        to: u32,
    ) -> trc::Result<()> {
        let mut pipeline = redis::pipe();
        for index in from..to {
            pipeline.cmd("DEL").arg(chunk_key(prefix, index));
        }

        pipeline.query_async::<()>(conn).await.map_err(into_error)
    }

    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_delete_prefix_(pool.get().await.map_err(into_error)?.as_mut(), prefix)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.key_delete_prefix_(pool.get().await.map_err(into_error)?.as_mut(), prefix)
                    .await
            }
            RedisPool::Sentinel(pool) => {
                self.key_delete_prefix_(pool.get().await.map_err(into_error)?.as_mut(), prefix)
                    .await
            }
        }
    }

    pub async fn key_get<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        key: &[u8],
    ) -> trc::Result<Option<T>> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.key_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Sentinel(pool) => {
                self.key_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
        }
    }

    pub async fn counter_get(&self, key: &[u8]) -> trc::Result<i64> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.counter_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.counter_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Sentinel(pool) => {
                self.counter_get_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
        }
    }

    pub async fn key_exists(&self, key: &[u8]) -> trc::Result<bool> {
        match &self.pool {
            RedisPool::Single(pool) => {
                self.key_exists_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Cluster(pool) => {
                self.key_exists_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
            RedisPool::Sentinel(pool) => {
                self.key_exists_(pool.get().await.map_err(into_error)?.as_mut(), key)
                    .await
            }
        }
    }

    async fn key_get_<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        conn: &mut impl AsyncCommands,
        key: &[u8],
    ) -> trc::Result<Option<T>> {
        if let Some(value) = redis::cmd("GET")
            .arg(key)
            .query_async::<Option<Vec<u8>>>(conn)
            .await
            .map_err(into_error)?
        {
            T::deserialize_owned(value).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn counter_get_(&self, conn: &mut impl AsyncCommands, key: &[u8]) -> trc::Result<i64> {
        redis::cmd("GET")
            .arg(key)
            .query_async::<Option<i64>>(conn)
            .await
            .map(|x| x.unwrap_or(0))
            .map_err(into_error)
    }

    async fn key_exists_(&self, conn: &mut impl AsyncCommands, key: &[u8]) -> trc::Result<bool> {
        conn.exists(key).await.map_err(into_error)
    }

    async fn key_set_(
        &self,
        conn: &mut impl AsyncCommands,
        key: &[u8],
        value: &[u8],
        expires: Option<u64>,
    ) -> trc::Result<()> {
        if let Some(expires) = expires {
            conn.set_ex(key, value, expires).await.map_err(into_error)
        } else {
            conn.set(key, value).await.map_err(into_error)
        }
    }

    async fn key_incr_(
        &self,
        conn: &mut impl AsyncCommands,
        key: &[u8],
        value: i64,
        expires: Option<u64>,
    ) -> trc::Result<i64> {
        if let Some(expires) = expires {
            redis::pipe()
                .atomic()
                .incr(key, value)
                .expire(key, expires as i64)
                .ignore()
                .query_async::<Vec<i64>>(conn)
                .await
                .map_err(into_error)
                .map(|v| v.first().copied().unwrap_or(0))
        } else {
            conn.incr(key, value).await.map_err(into_error)
        }
    }

    async fn try_lock_(
        &self,
        conn: &mut impl AsyncCommands,
        key: &[u8],
        expires: u64,
    ) -> trc::Result<bool> {
        redis::cmd("SET")
            .arg(key)
            .arg(now() + expires)
            .arg("NX")
            .arg("EX")
            .arg(expires as i64)
            .query_async::<Option<String>>(conn)
            .await
            .map(|reply| reply.is_some())
            .map_err(into_error)
    }

    async fn renew_lock_(
        &self,
        conn: &mut impl AsyncCommands,
        key: &[u8],
        expires: u64,
    ) -> trc::Result<()> {
        redis::cmd("SET")
            .arg(key)
            .arg(now() + expires)
            .arg("EX")
            .arg(expires as i64)
            .query_async::<()>(conn)
            .await
            .map_err(into_error)
    }

    async fn key_delete_(&self, conn: &mut impl AsyncCommands, key: &[u8]) -> trc::Result<()> {
        conn.del(key).await.map_err(into_error)
    }

    async fn key_delete_prefix_(
        &self,
        conn: &mut impl AsyncCommands,
        prefix: &[u8],
    ) -> trc::Result<()> {
        let mut pattern = Vec::with_capacity(prefix.len() + 1);
        pattern.extend_from_slice(prefix);
        pattern.push(b'*');

        let mut cursor = 0;
        loop {
            let (new_cursor, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
                .cursor_arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(conn)
                .await
                .map_err(into_error)?;

            if !keys.is_empty() {
                conn.del::<_, ()>(&keys).await.map_err(into_error)?;
            }

            if new_cursor != 0 {
                cursor = new_cursor;
            } else {
                return Ok(());
            }
        }
    }
}

fn chunk_key(prefix: &[u8], index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 12);
    key.push(b'{');
    key.extend_from_slice(prefix);
    key.extend_from_slice(b"}:");
    key.extend_from_slice(index.to_string().as_bytes());
    key
}
