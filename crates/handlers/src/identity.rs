use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::Query;
use mas_data_model::{BoxClock, BoxRng, UlidExt as _};
use mas_tasks::convert::ConvertClient;
use rand::{Rng as _, distributions::Uniform};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use ulid::Ulid;

use crate::rate_limit::{Limiter, RequesterFingerprint};

#[derive(Deserialize)]
pub struct RequestToken {
    pub client_secret: String,
    pub country: String,
    pub phone_number: String,
    #[serde(default)]
    pub next_link: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub sid: String,
    pub submit_url: String,
}

#[derive(Deserialize)]
pub struct SubmitToken {
    pub sid: String,
    pub client_secret: String,
    pub token: String,
}

pub async fn request_token(
    State(pool): State<PgPool>,
    State(convert): State<ConvertClient>,
    State(limiter): State<Limiter>,
    clock: BoxClock,
    mut rng: BoxRng,
    fingerprint: RequesterFingerprint,
    Json(input): Json<RequestToken>,
) -> impl IntoResponse {
    if input.client_secret.is_empty()
        || input.client_secret.len() > 255
        || input.country.len() != 2
        || input.phone_number.trim().is_empty()
        || input.phone_number.len() > 32
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"errcode":"M_INVALID_PARAM","error":"Invalid phone verification parameters"}),
            ),
        );
    }
    // ULIDs and the code both come from the workspace rng, not the thread's,
    // so a request's randomness is injectable like everywhere else.
    let sid = Ulid::from_datetime_with_rng(clock.now(), &mut rng).to_string();
    let code = format!("{:06}", rng.sample(Uniform::<u32>::from(0..1_000_000)));
    let secret_hash = sha256(&input.client_secret);
    // Convert only accepts E.164 for WhatsApp and SMS, so a national number has
    // to be composed with the country the client sent.
    let Some(phone) = normalize_phone(&input.country, &input.phone_number) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"errcode":"M_INVALID_PARAM","error":"Invalid phone number"})),
        );
    };
    // Every accepted request sends a real message on our Convert account, so
    // the limits are checked before anything is stored or sent.
    if let Err(error) = limiter.check_phone_verification(fingerprint, &phone) {
        tracing::warn!(%error, "Phone verification rate limited");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(
                serde_json::json!({"errcode":"M_LIMIT_EXCEEDED","error":"Too many verification requests. Please try again later."}),
            ),
        );
    }
    let next_link = safe_next_link(input.next_link.as_deref());
    let inserted = sqlx::query("INSERT INTO matrix_msisdn_validations (sid, client_secret_hash, phone_number, token_hash, next_link, expires_at) VALUES ($1,$2,$3,$4,$5,now()+interval '5 minutes')")
        .bind(&sid).bind(secret_hash).bind(&phone).bind(sha256(&code)).bind(next_link).execute(&pool).await;
    if inserted.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({"errcode":"M_UNKNOWN","error":"Could not create validation session"}),
            ),
        );
    }
    let Ok(receipt) = convert
        .send_phone_otp(&phone, &code, &format!("matrix-msisdn-{sid}"))
        .await
    else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(
                serde_json::json!({"errcode":"M_UNKNOWN","error":"Could not deliver validation code"}),
            ),
        );
    };
    // Convert's message_id is acceptance, not delivery — recording it is what
    // lets a later delivery webhook find this session. Best effort: the message
    // is already sent, so a bookkeeping failure must not become a client retry
    // (which would send a second code).
    if let Some(message_id) = receipt.message_id.as_deref() {
        let _ = sqlx::query("UPDATE matrix_msisdn_validations SET convert_message_id=$2, delivery_status='accepted', delivery_updated_at=now() WHERE sid=$1")
            .bind(&sid).bind(message_id).execute(&pool).await;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!(TokenResponse {
            sid,
            submit_url: "/_matrix/identity/api/v2/validate/msisdn/submitToken".to_owned()
        })),
    )
}

pub async fn submit_token(
    State(pool): State<PgPool>,
    State(limiter): State<Limiter>,
    Json(input): Json<SubmitToken>,
) -> impl IntoResponse {
    if let Err(error) = limiter.check_phone_verification_attempt(&input.sid) {
        tracing::warn!(%error, "Phone verification attempt rate limited");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(
                serde_json::json!({"errcode":"M_LIMIT_EXCEEDED","error":"Too many attempts. Please request a new code."}),
            ),
        );
    }
    let result = sqlx::query("UPDATE matrix_msisdn_validations SET validated_at=now() WHERE sid=$1 AND client_secret_hash=$2 AND token_hash=$3 AND validated_at IS NULL AND expires_at>now()")
        .bind(input.sid).bind(sha256(&input.client_secret)).bind(sha256(&input.token)).execute(&pool).await;
    match result {
        Ok(r) if r.rows_affected() == 1 => {
            (StatusCode::OK, Json(serde_json::json!({"success":true})))
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"success":false})),
        ),
    }
}

pub async fn submit_token_get(
    State(pool): State<PgPool>,
    State(limiter): State<Limiter>,
    Query(input): Query<SubmitToken>,
) -> impl IntoResponse {
    if let Err(error) = limiter.check_phone_verification_attempt(&input.sid) {
        tracing::warn!(%error, "Phone verification attempt rate limited");
        return (StatusCode::TOO_MANY_REQUESTS, "Too many attempts").into_response();
    }
    let result = sqlx::query_scalar::<_, Option<String>>("UPDATE matrix_msisdn_validations SET validated_at=now() WHERE sid=$1 AND client_secret_hash=$2 AND token_hash=$3 AND validated_at IS NULL AND expires_at>now() RETURNING next_link")
        .bind(input.sid).bind(sha256(&input.client_secret)).bind(sha256(&input.token)).fetch_optional(&pool).await;
    match result {
        Ok(Some(Some(next_link))) => Redirect::to(&next_link).into_response(),
        Ok(Some(None)) => (StatusCode::OK, "Phone number validated").into_response(),
        _ => (StatusCode::BAD_REQUEST, "Validation failed").into_response(),
    }
}

fn sha256(value: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(value.as_bytes()).to_vec()
}

/// Only same-origin, relative `next_link` values are honoured.
///
/// `next_link` is client-supplied, so echoing an absolute URL back as a
/// redirect turns this endpoint into an open redirect: a phishing hop that
/// looks like it came from the homeserver. Anything that is not a plain
/// relative path is dropped, and the caller gets the normal success response
/// instead of a redirect.
#[must_use]
pub fn safe_next_link(next_link: Option<&str>) -> Option<String> {
    let link = next_link?.trim();
    if link.starts_with('/') && !link.starts_with("//") && !link.starts_with("/\\") {
        return Some(link.to_owned());
    }
    tracing::warn!(next_link = link, "Ignoring non-relative next_link");
    None
}

/// Dial codes for the markets we verify numbers in. Swap for libphonenumber
/// (`phonenumber` crate) if we ever need the full table.
fn dial_code(country: &str) -> Option<&'static str> {
    Some(match country.to_ascii_uppercase().as_str() {
        "NG" => "234",
        "GH" => "233",
        "KE" => "254",
        "ZA" => "27",
        "EG" => "20",
        "CI" => "225",
        "CM" => "237",
        "SN" => "221",
        "UG" => "256",
        "TZ" => "255",
        "RW" => "250",
        "US" | "CA" => "1",
        "GB" => "44",
        _ => return None,
    })
}

/// Normalise a submitted number to E.164, or `None` if it cannot be one.
///
/// A number that already carries its country code (`+234…`) is kept as-is;
/// otherwise the dial code for `country` is prepended. Punctuation is ignored.
#[must_use]
pub fn normalize_phone(country: &str, raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let has_plus = trimmed.starts_with('+');
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }

    let number = if has_plus {
        digits
    } else if let Some(rest) = digits.strip_prefix("00") {
        // The ITU international prefix means the number is already complete.
        rest.to_owned()
    } else {
        let code = dial_code(country)?;
        // Some clients send the country code without the plus.
        if digits.starts_with(code) {
            digits
        } else {
            // National numbers are usually written with a trunk prefix
            // ("0801…" in Nigeria, "07400…" in the UK). E.164 drops it.
            let national = digits.strip_prefix('0').unwrap_or(&digits);
            format!("{code}{national}")
        }
    };

    // E.164 is at most 15 digits; the shortest assigned numbers are 8.
    if !(8..=15).contains(&number.len()) {
        return None;
    }
    Some(format!("+{number}"))
}

#[cfg(test)]
mod tests {
    use super::{normalize_phone, safe_next_link, sha256};

    #[test]
    fn hashes_are_deterministic_and_not_plaintext() {
        assert_eq!(sha256("secret"), sha256("secret"));
        assert_ne!(sha256("secret"), b"secret");
    }

    #[test]
    fn national_numbers_get_their_country_code() {
        assert_eq!(
            normalize_phone("NG", "8012345678").as_deref(),
            Some("+2348012345678")
        );
        // The trunk prefix is dropped, or the carrier rejects the number.
        assert_eq!(
            normalize_phone("ng", "08012345678").as_deref(),
            Some("+2348012345678")
        );
        assert_eq!(
            normalize_phone("GB", "07400123456").as_deref(),
            Some("+447400123456")
        );
        assert_eq!(
            normalize_phone("GB", "7400123456").as_deref(),
            Some("+447400123456")
        );
    }

    #[test]
    fn international_numbers_are_left_alone() {
        assert_eq!(
            normalize_phone("NG", "+2348012345678").as_deref(),
            Some("+2348012345678")
        );
        assert_eq!(
            normalize_phone("NG", "002348012345678").as_deref(),
            Some("+2348012345678")
        );
        // Country code sent without the plus is not doubled up.
        assert_eq!(
            normalize_phone("NG", "2348012345678").as_deref(),
            Some("+2348012345678")
        );
        assert_eq!(
            normalize_phone("NG", "+234 801 234 5678").as_deref(),
            Some("+2348012345678")
        );
    }

    #[test]
    fn unusable_numbers_are_rejected() {
        assert_eq!(normalize_phone("NG", ""), None);
        assert_eq!(normalize_phone("NG", "abc"), None);
        assert_eq!(normalize_phone("NG", "123"), None);
        assert_eq!(normalize_phone("NG", "+1234567890123456"), None);
        // No dial code for this country and no international prefix.
        assert_eq!(normalize_phone("ZZ", "8012345678"), None);
    }

    #[test]
    fn only_relative_next_links_survive() {
        assert_eq!(safe_next_link(Some("/home")).as_deref(), Some("/home"));
        assert_eq!(
            safe_next_link(Some("  /settings  ")).as_deref(),
            Some("/settings")
        );
        assert_eq!(safe_next_link(None), None);
        // Absolute, protocol-relative and backslash tricks are all dropped.
        assert_eq!(safe_next_link(Some("https://evil.example/phish")), None);
        assert_eq!(safe_next_link(Some("//evil.example")), None);
        assert_eq!(safe_next_link(Some("/\\evil.example")), None);
        assert_eq!(safe_next_link(Some("javascript:alert(1)")), None);
    }
}

/// Attach a proved number to the account that proved it.
///
/// The code is verified before the account exists, so the number is claimed
/// after: the validation row is the proof, and this consumes it. One statement
/// so that two claims of the same number cannot both succeed — the unique
/// constraint on `user_phones` decides.
#[derive(Debug, Deserialize)]
pub struct Claim {
    sid: String,
    client_secret: String,
    user_id: String,
}

/// Claim the number validated in `sid` for `user_id`
pub async fn claim(State(pool): State<PgPool>, Json(input): Json<Claim>) -> impl IntoResponse {
    let claimed = sqlx::query_scalar::<_, String>(
        "INSERT INTO user_phones (user_phone_id, user_id, phone_number, created_at)
         SELECT gen_random_uuid(), $1::uuid, phone_number, now()
           FROM matrix_msisdn_validations
          WHERE sid = $2 AND client_secret_hash = $3
            AND validated_at IS NOT NULL AND expires_at > now()
         ON CONFLICT (phone_number) DO NOTHING
         RETURNING phone_number",
    )
    .bind(&input.user_id)
    .bind(&input.sid)
    .bind(sha256(&input.client_secret))
    .fetch_optional(&pool)
    .await;

    match claimed {
        Ok(Some(phone_number)) => (
            StatusCode::OK,
            Json(serde_json::json!({"success": true, "phone_number": phone_number})),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "The number was not verified, or another account already has it",
            })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(
                error = &error as &dyn std::error::Error,
                "claiming a phone number failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"success": false, "error": "Internal error"})),
            )
                .into_response()
        }
    }
}
