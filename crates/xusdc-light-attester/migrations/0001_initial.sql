-- Version 1: the discovery checkpoint and every burn found so far.

CREATE TABLE attester_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    faucet_account_id BLOB NOT NULL,
    anchor_block INTEGER NOT NULL CHECK (anchor_block BETWEEN 0 AND 4294967295),
    anchor_commitment BLOB NOT NULL,
    scan_start INTEGER NOT NULL CHECK (scan_start BETWEEN 0 AND 4294967295),
    next_block INTEGER NOT NULL CHECK (next_block BETWEEN 0 AND 4294967295),
    authenticated_parent BLOB
) STRICT;

CREATE TABLE burns (
    note_id BLOB PRIMARY KEY,
    nullifier BLOB NOT NULL UNIQUE,
    note BLOB NOT NULL,
    creation_block INTEGER NOT NULL CHECK (creation_block BETWEEN 0 AND 4294967295),
    consumption_block INTEGER
        CHECK (consumption_block > creation_block AND consumption_block <= 4294967295),
    burn_tx_id BLOB,
    status TEXT NOT NULL CHECK (status IN ('CANDIDATE', 'DISCOVERED', 'REFUSED')),
    CHECK ((status = 'CANDIDATE') = (consumption_block IS NULL)),
    CHECK ((consumption_block IS NULL) = (burn_tx_id IS NULL))
) STRICT;
