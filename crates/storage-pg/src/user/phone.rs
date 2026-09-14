// Copyright 2026 Tween
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Phone numbers owned by a user.
//!
//! The queries here are runtime-checked rather than compiled with the `sqlx`
//! macros: the macros need either a database at build time or an entry in the
//! offline cache, and adding to that cache is a separate infrastructure step.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{Clock, User, UserPhone};
use mas_storage::user::{UserPhoneFilter, UserPhoneRepository};
use rand::RngCore;
use sqlx::{PgConnection, QueryBuilder};
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, tracing::ExecuteExt as _};

/// The database representation of a [`UserPhone`]
#[derive(Debug, Clone, sqlx::FromRow)]
struct UserPhoneLookup {
    id: Uuid,
    user_id: Uuid,
    phone_number: String,
    created_at: DateTime<Utc>,
}

impl From<UserPhoneLookup> for UserPhone {
    fn from(lookup: UserPhoneLookup) -> Self {
        Self {
            id: lookup.id.into(),
            user_id: lookup.user_id.into(),
            phone_number: lookup.phone_number,
            created_at: lookup.created_at,
        }
    }
}

/// A [`UserPhoneRepository`] implementation for a PostgreSQL database
pub struct PgUserPhoneRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserPhoneRepository<'c> {
    /// Create a new [`PgUserPhoneRepository`] from an active SQL connection
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl UserPhoneRepository for PgUserPhoneRepository<'_> {
    type Error = DatabaseError;

    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserPhone>, Self::Error> {
        let res = sqlx::query_as::<_, UserPhoneLookup>(
            r"
                SELECT user_phone_id AS id, user_id, phone_number, created_at
                FROM user_phones
                WHERE user_phone_id = $1
            ",
        )
        .bind(Uuid::from(id))
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        Ok(res.map(UserPhone::from))
    }

    async fn find_by_phone_number(
        &mut self,
        phone_number: &str,
    ) -> Result<Option<UserPhone>, Self::Error> {
        let res = sqlx::query_as::<_, UserPhoneLookup>(
            r"
                SELECT user_phone_id AS id, user_id, phone_number, created_at
                FROM user_phones
                WHERE phone_number = $1
            ",
        )
        .bind(phone_number)
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        Ok(res.map(UserPhone::from))
    }

    async fn find(
        &mut self,
        user: &User,
        phone_number: &str,
    ) -> Result<Option<UserPhone>, Self::Error> {
        let res = sqlx::query_as::<_, UserPhoneLookup>(
            r"
                SELECT user_phone_id AS id, user_id, phone_number, created_at
                FROM user_phones
                WHERE user_id = $1 AND phone_number = $2
            ",
        )
        .bind(Uuid::from(user.id))
        .bind(phone_number)
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        Ok(res.map(UserPhone::from))
    }

    async fn all(&mut self, user: &User) -> Result<Vec<UserPhone>, Self::Error> {
        let res = sqlx::query_as::<_, UserPhoneLookup>(
            r"
                SELECT user_phone_id AS id, user_id, phone_number, created_at
                FROM user_phones
                WHERE user_id = $1
                ORDER BY created_at
            ",
        )
        .bind(Uuid::from(user.id))
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        Ok(res.into_iter().map(UserPhone::from).collect())
    }

    async fn count(&mut self, filter: UserPhoneFilter<'_>) -> Result<usize, Self::Error> {
        let mut query = QueryBuilder::new("SELECT COUNT(*) FROM user_phones WHERE 1 = 1");

        if let Some(user) = filter.user() {
            query.push(" AND user_id = ").push_bind(Uuid::from(user.id));
        }

        if let Some(phone_number) = filter.phone_number() {
            query.push(" AND phone_number = ").push_bind(phone_number);
        }

        let count: i64 = query.build_query_scalar().fetch_one(&mut *self.conn).await?;

        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        phone_number: String,
    ) -> Result<UserPhone, Self::Error> {
        let created_at = clock.now();
        // Filled from the rng directly: `from_datetime_with_rng` is not
        // available to this crate, and a ULID still sorts by creation time.
        let id = Ulid::from_bytes({
            let mut bytes = [0u8; 16];
            rng.fill_bytes(&mut bytes);
            bytes
        });

        sqlx::query(
            r"
                INSERT INTO user_phones (user_phone_id, user_id, phone_number, created_at)
                VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(Uuid::from(id))
        .bind(Uuid::from(user.id))
        .bind(&phone_number)
        .bind(created_at)
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserPhone {
            id,
            user_id: user.id,
            phone_number,
            created_at,
        })
    }

    async fn remove(&mut self, user_phone: UserPhone) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM user_phones WHERE user_phone_id = $1")
            .bind(Uuid::from(user_phone.id))
            .traced()
            .execute(&mut *self.conn)
            .await?;

        Ok(())
    }
}
