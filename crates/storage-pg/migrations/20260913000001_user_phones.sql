-- Copyright 2026 Tween
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Phone numbers a user owns.
--
-- `matrix_msisdn_validations` proves a number for one request and then expires;
-- nothing ever carried that proof to an account, which is why a phone number was
-- never an identifier and could not receive a one-time code. This is where the
-- number lives once it is claimed, mirroring `user_emails` — with the unique
-- constraint that table is still missing.
CREATE TABLE "user_phones" (
  "user_phone_id" UUID PRIMARY KEY,

  "user_id" UUID NOT NULL
    CONSTRAINT "user_phones_user_id_fkey"
    REFERENCES "users" ("user_id")
    ON DELETE CASCADE,

  -- E.164, as the identity endpoints normalise it.
  "phone_number" TEXT NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

  -- One account per number.
  CONSTRAINT "user_phones_phone_number_unique" UNIQUE ("phone_number")
);

-- "Which numbers does this user have?", and the reverse by the unique index.
CREATE INDEX "user_phones_user_idx" ON "user_phones" ("user_id");
