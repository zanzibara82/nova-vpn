ALTER TABLE idempotency_keys
    ALTER COLUMN response_body TYPE jsonb USING convert_from(response_body, 'UTF8')::jsonb;
