CREATE TABLE matrix_msisdn_validations (
    sid TEXT PRIMARY KEY,
    client_secret_hash BYTEA NOT NULL,
    phone_number TEXT NOT NULL,
    token_hash BYTEA NOT NULL,
    next_link TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    validated_at TIMESTAMPTZ
);

CREATE INDEX matrix_msisdn_validations_phone_idx ON matrix_msisdn_validations (phone_number);
