# Плановый вывод узла из работы (drain)

Назначение: снять с узла всех пиеров, не ломая пользователям профили и не теряя
строку сервера. Порядок важен: остановка службы до снятия пиеров обрывает туннели
тех, кто ещё подключён.

Заголовок `Authorization` администратора читается из файла `0600` вне репозитория
(`-H @файл`), поэтому токен не попадает ни в argv, ни в журнал, ни в историю shell.

## 1. Перевод сервера в draining

```bash
curl -sS -X POST -H @~/novavpn-admin-auth.header -H 'Content-Type: application/json' \
  -d '{"status":"draining"}' \
  "https://api.novavpn.example/api/v1/admin/servers/$SERVER_ID/maintenance"
```

Ожидание: `200` и тело с новым статусом и поднятой `config_version`. Узел снимает
пиеров на следующем опросе: не позже 27,5 с (интервал опроса 25 с плюс jitter,
замеренный стендом задачи 13).

## 2. Проверка

```bash
ssh root@HOST 'wg show wg0 peers'
curl -sS -H @~/novavpn-admin-auth.header \
  "https://api.novavpn.example/api/v1/admin/servers/$SERVER_ID"
```

Ожидание: вывод `wg show wg0 peers` пуст (ни одного блока `peer`), а в ответе API
`health.status`/`status` показывает `draining`.

## 3. Пользователям

Выдать профили на другом сервере: `POST /api/v1/devices/{id}/profiles` с новым
`server_id` (выдача профиля — это новый сервер, а не перезапись старого). Старый
профиль отзывается владельцем: `DELETE /api/v1/devices/{id}/profiles/{server_id}`.

## 4. Остановка службы — только после снятия пиеров

```bash
ssh root@HOST systemctl stop novavpn-node-agent
```

Сервер из API не удалять, пока у профилей есть адреса:
`DELETE /api/v1/admin/servers/{id}` отказывает, если профили живы, и это отказ
защиты данных, а не поломка.

## 5. Возврат в работу

```bash
curl -sS -X POST -H @~/novavpn-admin-auth.header -H 'Content-Type: application/json' \
  -d '{"status":"online"}' \
  "https://api.novavpn.example/api/v1/admin/servers/$SERVER_ID/maintenance"
```

Ожидание: `200` с тем же набором полей, и тот же набор пиеров возвращается на
следующем опросе (та же граница 27,5 с) — `wg show wg0 peers` снова непустой, трафик
идёт.
