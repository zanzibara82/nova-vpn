-- name: BusyAddresses :many
-- Занято = «назначено сейчас» ИЛИ «освобождено, но окно переиспользования (§7.2)
-- ещё не истекло». Окно считается по часам сервера, а не по переданному now():
-- Go-выборка и DB-защита должны судить об одном и том же моменте.
SELECT address FROM tunnel_addresses
WHERE server_id = $1
  AND (allocated_to IS NOT NULL
       OR (reusable_at IS NOT NULL AND reusable_at > now()));

-- name: ClaimAddress :one
-- INSERT..ON CONFLICT DO UPDATE с условием: если адрес успели занять между выборкой
-- в Go и этим запросом, строка не возвращается, и аллокатор отказывается, а не
-- перетирает чужое назначение. Это второй слой защиты поверх LockServerRow.
-- Условие — ровно дополнение BusyAddresses: адрес свободен, только если он никому
-- не назначен И окно переиспользования (§7.2) закрыто. Раздельные «ИЛИ» здесь
-- означали бы, что освобождённый адрес можно взять мгновенно, а проверка Go-выборки
-- обходилась бы на каждом конкурентном заходе.
INSERT INTO tunnel_addresses (server_id, address, allocated_to)
VALUES ($1, $2, $3)
ON CONFLICT (server_id, address) DO UPDATE
    SET allocated_to = EXCLUDED.allocated_to,
        released_at  = NULL,
        reusable_at  = NULL
  WHERE tunnel_addresses.allocated_to IS NULL
    AND (tunnel_addresses.reusable_at IS NULL
         OR tunnel_addresses.reusable_at <= now())
RETURNING address;

-- name: ReleaseAddressByProfile :exec
UPDATE tunnel_addresses
   SET allocated_to = NULL, released_at = now(),
       reusable_at  = now() + interval '5 minutes'
 WHERE allocated_to = $1;

-- name: ReleaseAddressesByProfiles :exec
UPDATE tunnel_addresses
   SET allocated_to = NULL, released_at = now(),
       reusable_at  = now() + interval '5 minutes'
 WHERE allocated_to = ANY($1::uuid[]);

-- name: AddressOfProfile :one
SELECT address FROM tunnel_addresses WHERE allocated_to = $1;
