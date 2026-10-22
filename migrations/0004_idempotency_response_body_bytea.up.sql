-- jsonb нормализует порядок ключей и пробелы: повтор Idempotency-Key отдал бы
-- клиенту другие байты, чем первый ответ (§5.2 требует вернуть первый результат).
-- bytea хранит тело как есть; convert_to вместо ::text::bytea, чтобы escape-формат
-- bytea не съедал бэкслеши в JSON-строках.
ALTER TABLE idempotency_keys
    ALTER COLUMN response_body TYPE bytea USING convert_to(response_body::text, 'UTF8');
