// Copyright 2026 Tween.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Account recovery for the app.
//!
//! The web flow mails a link that lands on a page the fork does not have, so
//! this is the code-shaped variant: ask for a code against an e-mail address,
//! check it, then choose a new password. The code is stored as a recovery
//! ticket, hashed together with the session it belongs to, which means the
//! rest of the machinery ([`UserRecoveryRepository`]) is the same one the web
//! flow uses.

use std::str::FromStr as _;

use anyhow::Context as _;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use mas_axum_utils::InternalError;
use mas_data_model::{recovery_code_ticket, BoxClock, BoxRng, SiteConfig};
use mas_storage::{
    queue::{QueueJobRepositoryExt as _, SendRecoveryCodeEmailJob},
    user::{UserEmailRepository, UserPasswordRepository, UserRecoveryRepository, UserRepository},
    BoxRepository, RepositoryAccess,
};
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::{
    passwords::PasswordManager, BoundActivityTracker, Limiter, PreferredLanguage,
    RequesterFingerprint,
};

/// The user agent recorded on sessions started from the app, which has no
/// browser to report one.
const APP_USER_AGENT: &str = "TweenApp";

#[derive(Debug, Deserialize)]
pub struct RequestPayload {
    email: String,
}

#[derive(Debug, Serialize)]
pub struct RequestResponse {
    session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CodePayload {
    session_id: String,
    code: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPayload {
    session_id: String,
    code: String,
    new_password: String,
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    success: bool,
}

fn error(status: StatusCode, errcode: &str, error: &str) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({ "errcode": errcode, "error": error })),
    )
        .into_response()
}

/// Ask for a recovery code to be sent to an e-mail address.
///
/// The answer is the same whether or not the address has an account, so this
/// cannot be used to find out who has one.
#[tracing::instrument(name = "handlers.recovery.request", skip_all, fields(email = %payload.email))]
pub async fn request(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    State(limiter): State<Limiter>,
    State(site_config): State<SiteConfig>,
    PreferredLanguage(locale): PreferredLanguage,
    fingerprint: RequesterFingerprint,
    Json(payload): Json<RequestPayload>,
) -> Result<axum::response::Response, InternalError> {
    if !site_config.account_recovery_allowed {
        return Ok(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "M_UNKNOWN",
            "Account recovery is disabled",
        ));
    }

    let email = payload.email.trim().to_lowercase();
    if email.is_empty() || email.len() > 254 || lettre::Address::from_str(&email).is_err() {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "That does not look like an e-mail address",
        ));
    }

    if let Err(e) = limiter.check_account_recovery(fingerprint, &email) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "Recovery rate limited"
        );
        return Ok(error(
            StatusCode::TOO_MANY_REQUESTS,
            "M_LIMIT_EXCEEDED",
            "Too many attempts, please wait a while",
        ));
    }

    let session = repo
        .user_recovery()
        .add_session(
            &mut rng,
            &clock,
            email,
            APP_USER_AGENT.to_owned(),
            activity_tracker.ip(),
            locale.to_string(),
        )
        .await?;

    repo.queue_job()
        .schedule_job(&mut rng, &clock, SendRecoveryCodeEmailJob::new(&session))
        .await?;

    repo.save().await?;

    Ok((
        StatusCode::OK,
        Json(RequestResponse {
            session_id: session.id.to_string(),
        }),
    )
        .into_response())
}

/// Check a recovery code before the person is asked to pick a new password.
#[tracing::instrument(name = "handlers.recovery.verify", skip_all, fields(user_recovery_session.id = %payload.session_id))]
pub async fn verify(
    clock: BoxClock,
    mut repo: BoxRepository,
    State(limiter): State<Limiter>,
    State(site_config): State<SiteConfig>,
    fingerprint: RequesterFingerprint,
    Json(payload): Json<CodePayload>,
) -> Result<axum::response::Response, InternalError> {
    if !site_config.account_recovery_allowed {
        return Ok(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "M_UNKNOWN",
            "Account recovery is disabled",
        ));
    }

    let Some(session_id) = parse_session_id(&payload.session_id) else {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "Unknown recovery session",
        ));
    };

    let Some(session) = repo.user_recovery().lookup_session(session_id).await? else {
        return Ok(error(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "Unknown recovery session",
        ));
    };

    if let Err(e) = limiter.check_account_recovery(fingerprint, &session.email) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "Recovery rate limited"
        );
        return Ok(error(
            StatusCode::TOO_MANY_REQUESTS,
            "M_LIMIT_EXCEEDED",
            "Too many attempts, please wait a while",
        ));
    }

    match check_code(&mut repo, clock.now(), session_id, &payload.code).await? {
        CodeCheck::Valid => {
            Ok((StatusCode::OK, Json(SuccessResponse { success: true })).into_response())
        }
        CodeCheck::Expired => Ok(error(
            StatusCode::GONE,
            "M_CODE_EXPIRED",
            "That code has expired, ask for a new one",
        )),
        CodeCheck::Wrong => Ok(error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "That code is not right",
        )),
    }
}

/// Set a new password, using the code sent by e-mail.
#[tracing::instrument(name = "handlers.recovery.reset", skip_all, fields(user_recovery_session.id = %payload.session_id))]
pub async fn reset(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(limiter): State<Limiter>,
    State(password_manager): State<PasswordManager>,
    State(site_config): State<SiteConfig>,
    fingerprint: RequesterFingerprint,
    Json(payload): Json<ResetPayload>,
) -> Result<axum::response::Response, InternalError> {
    if !site_config.account_recovery_allowed || !password_manager.is_enabled() {
        return Ok(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "M_UNKNOWN",
            "Account recovery is disabled",
        ));
    }

    let Some(session_id) = parse_session_id(&payload.session_id) else {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "Unknown recovery session",
        ));
    };

    let Some(session) = repo.user_recovery().lookup_session(session_id).await? else {
        return Ok(error(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "Unknown recovery session",
        ));
    };

    if let Err(e) = limiter.check_account_recovery(fingerprint, &session.email) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "Recovery rate limited"
        );
        return Ok(error(
            StatusCode::TOO_MANY_REQUESTS,
            "M_LIMIT_EXCEEDED",
            "Too many attempts, please wait a while",
        ));
    }

    let valid = match password_manager.is_password_complex_enough(&payload.new_password) {
        Ok(valid) => valid,
        Err(e) => {
            tracing::error!(
                error = &e as &dyn std::error::Error,
                "Password manager disabled"
            );
            return Ok(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "M_UNKNOWN",
                "Account recovery is disabled",
            ));
        }
    };

    if !valid {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "Please choose a stronger password",
        ));
    }

    // The `?` result is bound before the match: its error type is not `Send`,
    // and a temporary left alive in the scrutinee would cross the arm's await.
    let checked = check_code(&mut repo, clock.now(), session_id, &payload.code).await?;

    let ticket = match checked {
        CodeCheck::Valid => repo
            .user_recovery()
            .find_ticket(&recovery_code_ticket(session_id, payload.code.trim()))
            .await?
            .context("Recovery ticket vanished between checks")
            .map_err(InternalError::from_anyhow)?,
        CodeCheck::Expired => {
            return Ok(error(
                StatusCode::GONE,
                "M_CODE_EXPIRED",
                "That code has expired, ask for a new one",
            ));
        }
        CodeCheck::Wrong => {
            return Ok(error(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "That code is not right",
            ));
        }
    };

    let user_email = repo
        .user_email()
        .lookup(ticket.user_email_id)
        .await?
        .context("Unknown e-mail address")
        .map_err(InternalError::from_anyhow)?;

    let user = repo
        .user()
        .lookup(user_email.user_id)
        .await?
        .context("Unknown user")
        .map_err(InternalError::from_anyhow)?;

    if !user.is_valid() {
        return Ok(error(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "This account is locked",
        ));
    }

    let (version, hash) = password_manager
        .hash(&mut rng, Zeroizing::new(payload.new_password))
        .await
        .map_err(InternalError::from_anyhow)?;

    repo.user_password()
        .add(&mut rng, &clock, &user, version, hash, None)
        .await?;

    repo.user_recovery()
        .consume_ticket(&clock, ticket, session)
        .await?;

    repo.save().await?;

    Ok((StatusCode::OK, Json(SuccessResponse { success: true })).into_response())
}

enum CodeCheck {
    Valid,
    Expired,
    Wrong,
}

/// Look the code up as a ticket belonging to `session_id`.
///
/// Scoping by session means a code cannot be replayed against another account
/// that happens to draw the same six digits.
async fn check_code(
    repo: &mut BoxRepository,
    now: DateTime<Utc>,
    session_id: Ulid,
    code: &str,
) -> Result<CodeCheck, InternalError> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(CodeCheck::Wrong);
    }

    let ticket = recovery_code_ticket(session_id, code);
    let Some(ticket) = repo.user_recovery().find_ticket(&ticket).await? else {
        return Ok(CodeCheck::Wrong);
    };

    if ticket.user_recovery_session_id != session_id {
        return Ok(CodeCheck::Wrong);
    }

    if !ticket.active(now) {
        return Ok(CodeCheck::Expired);
    }

    Ok(CodeCheck::Valid)
}

fn parse_session_id(raw: &str) -> Option<Ulid> {
    Ulid::from_string(raw.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::parse_session_id;

    #[test]
    fn a_recovery_session_id_must_be_a_ulid() {
        assert!(parse_session_id("01J0RZ4N0P7E5A9F2C6B3D8H5K").is_some());
        assert!(parse_session_id(" 01J0RZ4N0P7E5A9F2C6B3D8H5K ").is_some());
        assert!(parse_session_id("").is_none());
        assert!(parse_session_id("not-a-ulid").is_none());
        // Version 4 UUIDs, which a client may send by mistake, are ULID-sized
        // but not ULIDs.
        assert!(parse_session_id("9f1c2f38-46a1-4d3b-8f2e-3b1f0a52c0d9").is_none());
    }
}
