-- Each destination starts with the complete history and advances only after successful exports.
CREATE TABLE withdrawal_export_cursors (
    destination TEXT PRIMARY KEY CHECK (length(destination) > 0),
    after_seq INTEGER NOT NULL CHECK (after_seq >= 0)
) STRICT;
