use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error as _};
use url::Url;

use super::ConfigurationSection;

/// Convert delivery channel used for phone verification messages.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConvertChannel {
    /// Let Convert prefer `WhatsApp` and fall back to SMS.
    #[default]
    Smart,
    /// Deliver through `WhatsApp`.
    Whatsapp,
    /// Deliver through SMS.
    Sms,
}

/// Configuration for Convert transactional messaging.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConvertConfig {
    /// Convert API base URL.
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Organisation-scoped Convert API key.
    #[serde(default, skip_serializing)]
    pub api_key: Option<String>,
    /// Channel used for phone verification OTPs.
    #[serde(default)]
    pub channel: ConvertChannel,
    /// Validate requests without sending or charging.
    #[serde(default)]
    pub test: bool,
    /// Secret Convert signs webhook deliveries with (`X-Convert-Signature`).
    ///
    /// Without it the webhook endpoint stays disabled, and delivery state is
    /// never recorded — an accepted message would only ever read as accepted.
    #[serde(default, skip_serializing)]
    pub webhook_secret: Option<String>,
}

fn default_base_url() -> String {
    "https://convert.ruut.chat/api/v1".to_owned()
}

impl Default for ConvertConfig {
    fn default() -> Self {
        Self {
            base_url: default_base_url(),
            api_key: None,
            channel: ConvertChannel::default(),
            test: false,
            webhook_secret: None,
        }
    }
}

impl ConvertConfig {
    /// Whether this section has only its defaults.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.api_key.is_none()
            && self.base_url == default_base_url()
            && matches!(self.channel, ConvertChannel::Smart)
            && !self.test
            && self.webhook_secret.is_none()
    }

    /// Whether Convert delivery is configured.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.api_key
            .as_deref()
            .is_some_and(|key| !key.trim().is_empty())
    }

    /// Whether webhook deliveries can be verified.
    #[must_use]
    pub fn webhooks_enabled(&self) -> bool {
        self.webhook_secret
            .as_deref()
            .is_some_and(|secret| !secret.trim().is_empty())
    }
}

impl ConfigurationSection for ConvertConfig {
    const PATH: Option<&'static str> = Some("convert");

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        if Url::parse(&self.base_url).is_err() {
            let metadata = figment.find_metadata(Self::PATH.unwrap());
            let mut error = figment::error::Error::custom("base_url must be a valid URL");
            error.metadata = metadata.cloned();
            error.path = vec!["convert".to_owned(), "base_url".to_owned()];
            return Err(error.into());
        }
        Ok(())
    }
}
