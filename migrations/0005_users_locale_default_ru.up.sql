-- Решение 2026-10-22: язык интерфейса продукта — русский, locale по умолчанию — 'ru'.
-- 0001 выгружена с DEFAULT 'en'; историю не переписываем — дефолт меняет эта пара.
ALTER TABLE users
    ALTER COLUMN locale SET DEFAULT 'ru';
