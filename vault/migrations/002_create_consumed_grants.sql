CREATE TABLE IF NOT EXISTS consumed_grants (
    grant_id TEXT PRIMARY KEY,
    consumed_at TIMESTAMP DEFAULT now()
);
