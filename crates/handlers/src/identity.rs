use axum::{Json, extract::{Query, State}, http::StatusCode, response::{IntoResponse, Redirect}};
use mas_tasks::convert::ConvertClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use ulid::Ulid;

#[derive(Deserialize)]
pub struct RequestToken {
    pub client_secret: String,
    pub country: String,
    pub phone_number: String,
    #[serde(default)]
    pub next_link: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse { pub sid: String, pub submit_url: String }

#[derive(Deserialize)]
pub struct SubmitToken { pub sid: String, pub client_secret: String, pub token: String }

pub async fn request_token(
    State(pool): State<PgPool>, State(convert): State<ConvertClient>, Json(input): Json<RequestToken>,
) -> impl IntoResponse {
    if input.client_secret.is_empty()
        || input.client_secret.len() > 255
        || input.country.len() != 2
        || input.phone_number.trim().is_empty()
        || input.phone_number.len() > 32
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errcode":"M_INVALID_PARAM","error":"Invalid phone verification parameters"})));
    }
    let sid = Ulid::new().to_string();
    let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    let secret_hash = sha256(&input.client_secret);
    // Convert only accepts E.164 for WhatsApp and SMS, so a national number has
    // to be composed with the country the client sent.
    let Some(phone) = normalize_phone(&input.country, &input.phone_number) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errcode":"M_INVALID_PARAM","error":"Invalid phone number"})));
    };
    let inserted = sqlx::query("INSERT INTO matrix_msisdn_validations (sid, client_secret_hash, phone_number, token_hash, next_link, expires_at) VALUES ($1,$2,$3,$4,$5,now()+interval '5 minutes')")
        .bind(&sid).bind(secret_hash).bind(&phone).bind(sha256(&code)).bind(input.next_link).execute(&pool).await;
    if inserted.is_err() { return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"errcode":"M_UNKNOWN","error":"Could not create validation session"}))); }
    let receipt = match convert.send_phone_otp(&phone, &code, &format!("matrix-msisdn-{sid}")).await {
        Ok(receipt) => receipt,
        Err(_) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"errcode":"M_UNKNOWN","error":"Could not deliver validation code"}))),
    };
    // Convert's message_id is acceptance, not delivery — recording it is what
    // lets a later delivery webhook find this session. Best effort: the message
    // is already sent, so a bookkeeping failure must not become a client retry
    // (which would send a second code).
    if let Some(message_id) = receipt.message_id.as_deref() {
        let _ = sqlx::query("UPDATE matrix_msisdn_validations SET convert_message_id=$2, delivery_status='accepted', delivery_updated_at=now() WHERE sid=$1")
            .bind(&sid).bind(message_id).execute(&pool).await;
    }
    (StatusCode::OK, Json(serde_json::json!(TokenResponse { sid, submit_url: "/_matrix/identity/api/v2/validate/msisdn/submitToken".to_owned() })))
}

pub async fn submit_token(State(pool): State<PgPool>, Json(input): Json<SubmitToken>) -> impl IntoResponse {
    let result = sqlx::query("UPDATE matrix_msisdn_validations SET validated_at=now() WHERE sid=$1 AND client_secret_hash=$2 AND token_hash=$3 AND validated_at IS NULL AND expires_at>now()")
        .bind(input.sid).bind(sha256(&input.client_secret)).bind(sha256(&input.token)).execute(&pool).await;
    match result { Ok(r) if r.rows_affected() == 1 => (StatusCode::OK, Json(serde_json::json!({"success":true}))), _ => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"success":false}))) }
}

pub async fn submit_token_get(State(pool): State<PgPool>, Query(input): Query<SubmitToken>) -> impl IntoResponse {
    let result = sqlx::query_scalar::<_, Option<String>>("UPDATE matrix_msisdn_validations SET validated_at=now() WHERE sid=$1 AND client_secret_hash=$2 AND token_hash=$3 AND validated_at IS NULL AND expires_at>now() RETURNING next_link")
        .bind(input.sid).bind(sha256(&input.client_secret)).bind(sha256(&input.token)).fetch_optional(&pool).await;
    match result {
        Ok(Some(Some(next_link))) => Redirect::to(&next_link).into_response(),
        Ok(Some(None)) => (StatusCode::OK, "Phone number validated").into_response(),
        _ => (StatusCode::BAD_REQUEST, "Validation failed").into_response(),
    }
}

fn sha256(value: &str) -> Vec<u8> { use sha2::{Digest, Sha256}; Sha256::digest(value.as_bytes()).to_vec() }

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
    use super::{normalize_phone, sha256};

    #[test]
    fn hashes_are_deterministic_and_not_plaintext() {
        assert_eq!(sha256("secret"), sha256("secret"));
        assert_ne!(sha256("secret"), b"secret");
    }

    #[test]
    fn national_numbers_get_their_country_code() {
        assert_eq!(normalize_phone("NG", "8012345678").as_deref(), Some("+2348012345678"));
        // The trunk prefix is dropped, or the carrier rejects the number.
        assert_eq!(normalize_phone("ng", "08012345678").as_deref(), Some("+2348012345678"));
        assert_eq!(normalize_phone("GB", "07400123456").as_deref(), Some("+447400123456"));
        assert_eq!(normalize_phone("GB", "7400123456").as_deref(), Some("+447400123456"));
    }

    #[test]
    fn international_numbers_are_left_alone() {
        assert_eq!(normalize_phone("NG", "+2348012345678").as_deref(), Some("+2348012345678"));
        assert_eq!(normalize_phone("NG", "002348012345678").as_deref(), Some("+2348012345678"));
        // Country code sent without the plus is not doubled up.
        assert_eq!(normalize_phone("NG", "2348012345678").as_deref(), Some("+2348012345678"));
        assert_eq!(normalize_phone("NG", "+234 801 234 5678").as_deref(), Some("+2348012345678"));
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
}
