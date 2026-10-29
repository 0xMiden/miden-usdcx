-- Operator-directed suspension preserves the burn and its saved submission.
ALTER TABLE burns ADD COLUMN exclusion_reason TEXT CHECK (
    exclusion_reason IS NULL OR length(CAST(exclusion_reason AS BLOB)) BETWEEN 1 AND 256
);
