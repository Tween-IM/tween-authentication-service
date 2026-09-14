// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use chrono::{DateTime, Utc};
use rand::Rng;
use rand_chacha::rand_core::CryptoRngCore;
use sha2::{Digest as _, Sha256};
use ulid::Ulid;

use crate::clock::Clock;

/// A boxed [`Clock`]
pub type BoxClock = Box<dyn Clock + Send>;
/// A boxed random number generator
pub type BoxRng = Box<dyn CryptoRngCore + Send>;

/// Extension trait on [`Ulid`] to build and inspect ULIDs using `chrono`
/// timestamps and an injected RNG.
pub trait UlidExt: Sized {
    /// Generate a [`Ulid`] for the given timestamp, sourcing its randomness
    /// from `rng`.
    ///
    /// This reproduces the exact bit layout of `ulid`'s own
    /// `Ulid::from_datetime_with_source` (48 timestamp bits, then 80 random
    /// bits drawn as a `u16` followed by a `u64`).
    fn from_datetime_with_rng<R: Rng + ?Sized>(datetime: DateTime<Utc>, rng: &mut R) -> Self;

    /// The creation timestamp encoded in this [`Ulid`], as a `chrono` datetime.
    fn datetime_utc(&self) -> DateTime<Utc>;
}

impl UlidExt for Ulid {
    fn from_datetime_with_rng<R: Rng + ?Sized>(datetime: DateTime<Utc>, rng: &mut R) -> Self {
        let timestamp_ms = u64::try_from(datetime.timestamp_millis()).unwrap_or(0);
        let timebits = timestamp_ms & ((1 << Ulid::TIME_BITS) - 1);

        let msb = timebits << 16 | u64::from(rng.r#gen::<u16>());
        let lsb = rng.r#gen::<u64>();
        Ulid::from(u128::from(msb) << 64 | u128::from(lsb))
    }

    fn datetime_utc(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(i64::try_from(self.timestamp_ms()).unwrap_or(i64::MAX))
            .unwrap_or_default()
    }
}

/// Derive the value stored for an account recovery code.
///
/// A recovery code is only six digits, so two sessions recovering at the same
/// time can easily draw the same one. Folding the recovery session's ULID into
/// the hash keeps every stored ticket unique to the session it belongs to, and
/// keeps the code itself out of the database in the clear.
#[must_use]
pub fn recovery_code_ticket(session_id: Ulid, code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recovery_ticket_is_scoped_to_its_session() {
        let session = Ulid::from_string("01J0RZ4N0P7E5A9F2C6B3D8H5K").unwrap();
        let other = Ulid::from_string("01J0RZ4N0P7E5A9F2C6B3D8H5M").unwrap();

        assert_eq!(
            recovery_code_ticket(session, "123456"),
            recovery_code_ticket(session, "123456")
        );
        assert_ne!(
            recovery_code_ticket(session, "123456"),
            recovery_code_ticket(other, "123456")
        );
        assert_ne!(
            recovery_code_ticket(session, "123456"),
            recovery_code_ticket(session, "123457")
        );
    }

    #[test]
    fn a_recovery_ticket_does_not_carry_the_code() {
        let session = Ulid::from_string("01J0RZ4N0P7E5A9F2C6B3D8H5K").unwrap();
        let ticket = recovery_code_ticket(session, "123456");

        assert!(!ticket.contains("123456"));
        assert_eq!(ticket.len(), 64);
        assert!(ticket.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
