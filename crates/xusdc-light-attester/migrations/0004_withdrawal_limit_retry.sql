ALTER TABLE burns ADD COLUMN withdrawal_limit_retry_at INTEGER
    CHECK (withdrawal_limit_retry_at IS NULL OR withdrawal_limit_retry_at >= 0);

CREATE INDEX burns_waiting_for_limit
    ON burns (creation_block, note_id)
    WHERE withdrawal_limit_retry_at IS NOT NULL;
