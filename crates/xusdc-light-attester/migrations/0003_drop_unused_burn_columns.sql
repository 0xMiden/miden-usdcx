-- Version 3: a burn row no longer records twice whether its note was consumed, and no longer keeps
-- the ID of the consuming transaction, which nothing read.

-- Both columns are named in the table's CHECK constraints, so SQLite cannot drop them: the table is
-- rebuilt. The history table refers to burns by name. Its foreign key is checked when the
-- migration commits, by which time every burn is back under that name.
PRAGMA defer_foreign_keys = ON;

CREATE TABLE burns_rows AS
SELECT note_id, nullifier, note, creation_block, consumption_block, hold_reason FROM burns;

DROP TABLE burns;

-- Every burn found so far, with its hold. A note the faucet has not consumed yet has no
-- consumption block.
CREATE TABLE burns (
    note_id BLOB PRIMARY KEY,
    nullifier BLOB NOT NULL UNIQUE,
    note BLOB NOT NULL,
    creation_block INTEGER NOT NULL CHECK (creation_block BETWEEN 0 AND 4294967295),
    consumption_block INTEGER
        CHECK (consumption_block > creation_block AND consumption_block <= 4294967295),
    hold_reason INTEGER CHECK (hold_reason IN (1, 2))
) STRICT;

INSERT INTO burns (note_id, nullifier, note, creation_block, consumption_block, hold_reason)
SELECT note_id, nullifier, note, creation_block, consumption_block, hold_reason FROM burns_rows;

DROP TABLE burns_rows;
