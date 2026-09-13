// Copyright 2026 Tween
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{Clock, User, UserPhone};
use rand_core::RngCore;
use ulid::Ulid;

/// A filter for [`UserPhoneRepository`]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserPhoneFilter<'a> {
    user: Option<&'a User>,
    phone_number: Option<&'a str>,
}

impl<'a> UserPhoneFilter<'a> {
    /// Create a new [`UserPhoneFilter`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by [`User`]
    #[must_use]
    pub fn for_user(mut self, user: &'a User) -> Self {
        self.user = Some(user);
        self
    }

    /// Filter by phone number, in E.164
    #[must_use]
    pub fn for_phone_number(mut self, phone_number: &'a str) -> Self {
        self.phone_number = Some(phone_number);
        self
    }

    /// Get the [`User`] to filter by
    pub fn user(&self) -> Option<&User> {
        self.user
    }

    /// Get the phone number to filter by
    pub fn phone_number(&self) -> Option<&str> {
        self.phone_number
    }
}

/// A [`UserPhoneRepository`] helps interacting with [`UserPhone`] saved in the
/// storage backend
#[async_trait]
pub trait UserPhoneRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup a [`UserPhone`] by its ID
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the [`UserPhone`] to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserPhone>, Self::Error>;

    /// Find a [`UserPhone`] by its number, whichever user owns it
    ///
    /// # Parameters
    ///
    /// * `phone_number`: The number to look for, in E.164
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_phone_number(
        &mut self,
        phone_number: &str,
    ) -> Result<Option<UserPhone>, Self::Error>;

    /// Find the [`UserPhone`] of a user with this number, if any
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] to look for
    /// * `phone_number`: The number to look for, in E.164
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find(
        &mut self,
        user: &User,
        phone_number: &str,
    ) -> Result<Option<UserPhone>, Self::Error>;

    /// All the numbers owned by a [`User`]
    ///
    /// # Parameters
    ///
    /// * `user`: The [`User`] to look for
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn all(&mut self, user: &User) -> Result<Vec<UserPhone>, Self::Error>;

    /// Count the [`UserPhone`] matching a filter
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn count(&mut self, filter: UserPhoneFilter<'_>) -> Result<usize, Self::Error>;

    /// Add a [`UserPhone`] to a [`User`]
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock to use
    /// * `user`: The [`User`] for whom to create the [`UserPhone`]
    /// * `phone_number`: The number, in E.164
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        phone_number: String,
    ) -> Result<UserPhone, Self::Error>;

    /// Delete a [`UserPhone`]
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn remove(&mut self, user_phone: UserPhone) -> Result<(), Self::Error>;
}
