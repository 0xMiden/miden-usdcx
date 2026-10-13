-- Version 2: scanning starts at the trusted anchor, so the store keeps one checkpoint.

-- The checkpoint is the header of the last authenticated block. The block to authenticate next
-- follows from it, and there is no separate block where scanning starts.
ALTER TABLE attester_state DROP COLUMN scan_start;
ALTER TABLE attester_state DROP COLUMN next_block;
ALTER TABLE attester_state RENAME COLUMN authenticated_parent TO checkpoint;
