use axum::{body::Bytes, extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse};
use mas_tasks::convert::ConvertClient;
use serde_json::Value;
use sqlx::PgPool;

const SIGNATURE_HEADER: &str = "x-convert-signature";

/// Delivery state for a Convert event, as stored against a validation session.
///
/// Ordering is Convert's, not ours: `opened`/`clicked` arrive after `delivered`
/// and must not walk the status backwards.
fn delivery_status(event: &str) -> Option<&'static str> {
    Some(match event {
        "message.sent" => "sent",
        "message.delivered" => "delivered",
        "message.failed" => "failed",
        "message.bounced" => "bounced",
        "message.unsubscribed" => "unsubscribed",
        "message.opened" => "opened",
        "message.clicked" => "clicked",
        // Campaign and contact events carry no message of ours.
        _ => return None,
    })
}

/// Find the first `message_id` anywhere in the payload.
///
/// Defensive on purpose: the brief lists the event names but not the payload
/// shape, so we do not pin ourselves to a nesting Convert may change.
fn find_message_id(value: &Value) -> Option<&str> {
    match value {
        Value::Object(map) => map
            .get("message_id")
            .and_then(Value::as_str)
            .or_else(|| map.values().find_map(find_message_id)),
        Value::Array(items) => items.iter().find_map(find_message_id),
        _ => None,
    }
}

/// Verify and record a Convert webhook delivery.
///
/// Convert retries anything that is not a 2xx up to five times, so we answer
/// 2xx once the signature checks out even if the event is one we ignore.
pub async fn webhook(
    State(pool): State<PgPool>,
    State(convert): State<ConvertClient>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !convert.webhooks_enabled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Convert webhooks are not configured");
    }

    let signature = headers.get(SIGNATURE_HEADER).and_then(|value| value.to_str().ok());
    if !convert.verify_webhook(signature, &body) {
        return (StatusCode::UNAUTHORIZED, "Invalid signature");
    }

    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "Malformed payload");
    };

    let event = payload
        .get("event")
        .or_else(|| payload.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let message_id = find_message_id(&payload);

    // Always keep the event: it is the only record of what Convert told us.
    let recorded = sqlx::query("INSERT INTO convert_webhook_events (event, message_id, payload) VALUES ($1,$2,$3)")
        .bind(event).bind(message_id).bind(&payload).execute(&pool).await;
    if recorded.is_err() {
        // Ask Convert to try again rather than silently dropping the event.
        return (StatusCode::INTERNAL_SERVER_ERROR, "Could not record event");
    }

    if let (Some(status), Some(message_id)) = (delivery_status(event), message_id) {
        let _ = sqlx::query("UPDATE matrix_msisdn_validations SET delivery_status=$2, delivery_updated_at=now() WHERE convert_message_id=$1")
            .bind(message_id).bind(status).execute(&pool).await;
    }

    (StatusCode::OK, "ok")
}

#[cfg(test)]
mod tests {
    use super::{delivery_status, find_message_id};
    use serde_json::json;

    #[test]
    fn delivery_events_map_to_a_status() {
        assert_eq!(delivery_status("message.delivered"), Some("delivered"));
        assert_eq!(delivery_status("message.bounced"), Some("bounced"));
        assert_eq!(delivery_status("message.unsubscribed"), Some("unsubscribed"));
        assert_eq!(delivery_status("campaign.completed"), None);
        assert_eq!(delivery_status("contact.created"), None);
        assert_eq!(delivery_status("something.new"), None);
    }

    #[test]
    fn message_id_is_found_wherever_convert_puts_it() {
        assert_eq!(find_message_id(&json!({"message_id": "msg_1"})), Some("msg_1"));
        assert_eq!(
            find_message_id(&json!({"data": {"message": {"message_id": "msg_2"}}})),
            Some("msg_2")
        );
        assert_eq!(
            find_message_id(&json!({"data": {"events": [{"message_id": "msg_3"}]}})),
            Some("msg_3")
        );
        assert_eq!(find_message_id(&json!({"data": {"status": "delivered"}})), None);
    }
}
