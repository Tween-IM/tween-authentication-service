use std::time::Duration;

use mas_config::{ConvertChannel, ConvertConfig};
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

const MAX_ATTEMPTS: usize = 3;

/// Errors returned while delivering a phone verification message.
#[derive(Debug, Error)]
pub enum ConvertError {
    /// Convert is not configured.
    #[error("Convert is not configured")]
    NotConfigured,
    /// The request was rejected by Convert.
    #[error("Convert rejected the message ({status}): {body}")]
    Rejected { status: StatusCode, body: String },
    /// A network or serialization error occurred.
    #[error(transparent)]
    Request(#[from] reqwest::Error),
}

#[derive(Debug, Serialize)]
struct MessageRequest<'a> {
    to: &'a str,
    channel: &'static str,
    message: &'a str,
    test: bool,
}

#[derive(Debug, Deserialize)]
struct MessageResponse {
    success: bool,
    channel: Option<String>,
    message_id: Option<String>,
    error: Option<String>,
}

/// Acceptance information returned by Convert after submitting a message.
#[derive(Debug, Clone)]
pub struct DeliveryReceipt {
    /// Channel accepted by Convert.
    pub channel: String,
    /// Convert message identifier.
    pub message_id: Option<String>,
}

/// Small Convert API client used by the phone verification worker.
#[derive(Clone)]
pub struct ConvertClient {
    client: Client,
    base_url: String,
    api_key: Option<String>,
    channel: ConvertChannel,
    test: bool,
}

impl ConvertClient {
    /// Build a client from application configuration.
    #[must_use]
    pub fn new(config: &ConvertConfig) -> Self {
        Self {
            client: mas_http::reqwest_client(),
            base_url: config.base_url.trim_end_matches('/').to_owned(),
            api_key: config.api_key.clone(),
            channel: config.channel,
            test: config.test,
        }
    }

    /// Send a phone verification OTP through the configured Convert channel.
    pub async fn send_phone_otp(
        &self,
        phone_number: &str,
        code: &str,
        idempotency_key: &str,
    ) -> Result<DeliveryReceipt, ConvertError> {
        let api_key = self.api_key.as_deref().ok_or(ConvertError::NotConfigured)?;
        let channel = match self.channel {
            ConvertChannel::Smart => "smart",
            ConvertChannel::Whatsapp => "whatsapp",
            ConvertChannel::Sms => "sms",
        };
        let message = format!("Your Tween verification code is {code}. It expires in 5 minutes.");
        let body = MessageRequest {
            to: phone_number,
            channel,
            message: &message,
            test: self.test,
        };

        for attempt in 0..MAX_ATTEMPTS {
            let response = self
                .client
                .post(format!("{}/messages", self.base_url))
                .header(header::AUTHORIZATION, format!("Bearer {api_key}"))
                .header("Idempotency-Key", idempotency_key)
                .json(&body)
                .send()
                .await;

            match response {
                Ok(response) if response.status().is_success() => {
                    let payload = response.json::<MessageResponse>().await?;
                    if !payload.success {
                        return Err(ConvertError::Rejected {
                            status: StatusCode::OK,
                            body: payload.error.unwrap_or_else(|| "message rejected".to_owned()),
                        });
                    }
                    return Ok(DeliveryReceipt {
                        channel: payload.channel.unwrap_or_else(|| channel.to_owned()),
                        message_id: payload.message_id,
                    });
                }
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    if !status.is_server_error() || attempt + 1 == MAX_ATTEMPTS {
                        return Err(ConvertError::Rejected { status, body });
                    }
                }
                Err(error) if attempt + 1 == MAX_ATTEMPTS => return Err(error.into()),
                Err(_) => {}
            }

            tokio::time::sleep(Duration::from_millis(250 * 2_u64.pow(attempt as u32))).await;
        }

        unreachable!("the retry loop always returns")
    }

    /// Generate a stable key for one OTP delivery attempt.
    #[must_use]
pub fn idempotency_key(authentication_id: Ulid) -> String {
        format!("tween-phone-otp-{authentication_id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mas_config::ConvertConfig;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{header, method, path}};

    fn config(server: &MockServer) -> ConvertConfig {
        ConvertConfig { base_url: server.uri(), api_key: Some("rk_test".into()), ..Default::default() }
    }

    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[tokio::test]
    async fn sends_expected_request_and_parses_receipt() {
        install_crypto_provider();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .and(header("Authorization", "Bearer rk_test"))
            .and(header("Idempotency-Key", "key-1"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "success": true, "channel": "whatsapp", "status": "accepted", "message_id": "msg_1"
            })))
            .expect(1)
            .mount(&server).await;

        let receipt = ConvertClient::new(&config(&server)).send_phone_otp("+2348012345678", "123456", "key-1").await.unwrap();
        assert_eq!(receipt.channel, "whatsapp");
        assert_eq!(receipt.message_id.as_deref(), Some("msg_1"));
    }

    #[tokio::test]
    async fn retries_server_errors_with_the_same_idempotency_key() {
        install_crypto_provider();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .and(header("Idempotency-Key", "key-2"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&server).await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .and(header("Idempotency-Key", "key-2"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"success":true,"channel":"sms"})))
            .mount(&server).await;

        assert!(ConvertClient::new(&config(&server)).send_phone_otp("+2348012345678", "123456", "key-2").await.is_ok());
    }

    #[tokio::test]
    async fn does_not_retry_client_errors() {
        install_crypto_provider();
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/messages"))
            .respond_with(ResponseTemplate::new(400).set_body_string("invalid"))
            .expect(1).mount(&server).await;
        assert!(matches!(ConvertClient::new(&config(&server)).send_phone_otp("+1", "123456", "key-3").await, Err(ConvertError::Rejected { status: StatusCode::BAD_REQUEST, .. })));
    }
}
