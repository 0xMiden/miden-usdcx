-- Version 1: the store's tables.

-- The discovery checkpoint.
CREATE TABLE attester_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    faucet_account_id BLOB NOT NULL,
    anchor_block INTEGER NOT NULL CHECK (anchor_block BETWEEN 0 AND 4294967295),
    anchor_commitment BLOB NOT NULL,
    scan_start INTEGER NOT NULL CHECK (scan_start BETWEEN 0 AND 4294967295),
    next_block INTEGER NOT NULL CHECK (next_block BETWEEN 0 AND 4294967295),
    authenticated_parent BLOB
) STRICT;

-- Every burn found so far, with its withdrawal-limit reservation and hold.
CREATE TABLE burns (
    note_id BLOB PRIMARY KEY,
    nullifier BLOB NOT NULL UNIQUE,
    note BLOB NOT NULL,
    creation_block INTEGER NOT NULL CHECK (creation_block BETWEEN 0 AND 4294967295),
    consumption_block INTEGER
        CHECK (consumption_block > creation_block AND consumption_block <= 4294967295),
    burn_tx_id BLOB,
    status TEXT NOT NULL CHECK (status IN ('CANDIDATE', 'DISCOVERED', 'REFUSED')),
    hold_reason TEXT CHECK (hold_reason IN ('prepare_rejected')),
    reservation_amount INTEGER CHECK (reservation_amount >= 0),
    admitted_at_ms INTEGER CHECK (admitted_at_ms >= 0),
    CHECK ((status = 'CANDIDATE') = (consumption_block IS NULL)),
    CHECK ((consumption_block IS NULL) = (burn_tx_id IS NULL)),
    CHECK ((reservation_amount IS NULL) = (admitted_at_ms IS NULL))
) STRICT;

-- Each burn's saved, signed withdrawal request and Circle's latest answer to it.
CREATE TABLE submissions (
    note_id BLOB PRIMARY KEY,
    endpoint TEXT NOT NULL,
    body BLOB NOT NULL,
    transfer_spec_hash BLOB NOT NULL,
    use_circle_forwarding INTEGER NOT NULL CHECK (use_circle_forwarding IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN (
        'SUBMITTING', 'SUBMITTED', 'FINALIZED', 'EXPIRED', 'FAILED', 'HELD'
    )),
    withdrawal_id TEXT,
    hold_reason TEXT CHECK (hold_reason IN ('http_rejected')),
    last_http_status INTEGER,
    last_response BLOB,
    last_error TEXT
) STRICT;

-- Every burn's submission history. The submissions table keeps each burn's current request; this
-- table only grows, and keeps what happened to every request the burn had.
CREATE TABLE submission_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id BLOB NOT NULL REFERENCES burns (note_id),
    recorded_at INTEGER NOT NULL, -- unix seconds
    kind TEXT NOT NULL,
    status TEXT,
    withdrawal_id TEXT,
    body BLOB, -- the exact signed bytes, on an authorization
    transfer_spec_hash BLOB,
    http_status INTEGER,
    response BLOB,
    error TEXT,
    endpoint TEXT,
    hold_reason TEXT,
    -- What the row records about the burn itself. A reservation is the amount and admission time a
    -- new or renewed request holds against the limit.
    reservation_amount INTEGER CHECK (reservation_amount >= 0),
    admitted_at_ms INTEGER
        CHECK (admitted_at_ms >= 0 AND (admitted_at_ms IS NULL) = (reservation_amount IS NULL)),
    burn_status TEXT,
    burn_hold_reason TEXT
) STRICT;

CREATE INDEX submission_events_by_note ON submission_events (note_id, seq);
CREATE INDEX submission_events_reservations ON submission_events (note_id, seq DESC)
    WHERE reservation_amount IS NOT NULL;
