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
    let phone = format!("+{}", input.phone_number.trim_start_matches('+'));
    let inserted = sqlx::query("INSERT INTO matrix_msisdn_validations (sid, client_secret_hash, phone_number, token_hash, next_link, expires_at) VALUES ($1,$2,$3,$4,$5,now()+interval '5 minutes')")
        .bind(&sid).bind(secret_hash).bind(&phone).bind(sha256(&code)).bind(input.next_link).execute(&pool).await;
    if inserted.is_err() { return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"errcode":"M_UNKNOWN","error":"Could not create validation session"}))); }
    if convert.send_phone_otp(&phone, &code, &format!("matrix-msisdn-{sid}")).await.is_err() {
        return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"errcode":"M_UNKNOWN","error":"Could not deliver validation code"})));
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

#[cfg(test)]
mod tests {
    use super::sha256;

    #[test]
    fn hashes_are_deterministic_and_not_plaintext() {
        assert_eq!(sha256("secret"), sha256("secret"));
        assert_ne!(sha256("secret"), b"secret");
    }
}
