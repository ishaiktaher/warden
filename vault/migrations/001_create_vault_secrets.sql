CREATE TABLE IF NOT EXISTS vault_secrets (
    ref TEXT PRIMARY KEY,
    encrypted_value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);
