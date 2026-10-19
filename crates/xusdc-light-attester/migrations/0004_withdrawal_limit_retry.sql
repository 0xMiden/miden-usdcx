ALTER TABLE burns ADD COLUMN withdrawal_limit_retry_at INTEGER
    CHECK (withdrawal_limit_retry_at IS NULL OR withdrawal_limit_retry_at >= 0);
