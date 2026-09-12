-- Convert accepts a message (201 + message_id); delivery is reported later over
-- webhooks. Track that state against the validation session that sent it.
ALTER TABLE matrix_msisdn_validations
    ADD COLUMN convert_message_id TEXT,
    ADD COLUMN delivery_status TEXT,
    ADD COLUMN delivery_updated_at TIMESTAMPTZ;

CREATE INDEX matrix_msisdn_validations_message_idx
    ON matrix_msisdn_validations (convert_message_id);

-- Audit of every signature-verified webhook, including events we cannot tie to
-- a validation session (campaign/contact events, or a message we did not send).
CREATE TABLE convert_webhook_events (
    id BIGSERIAL PRIMARY KEY,
    event TEXT NOT NULL,
    message_id TEXT,
    payload JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX convert_webhook_events_message_idx
    ON convert_webhook_events (message_id);
