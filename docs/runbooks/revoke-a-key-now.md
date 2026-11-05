# Немедленный отзыв ключа устройства

Сценарий: устройство пользователя потеряно, продано или скомпрометировано, доступ
надо снять сейчас. Критерий: пиер исчез с узла не позже 30 с. На стенде задачи 13
замерено 10 с (повторы того же стенда — 13 с), граница остаётся 30 с.

## 1. Владелец устройства отзываем сам

```bash
curl -sS -X DELETE -H @~/user-auth.header \
  "https://api.novavpn.example/api/v1/devices/$DEVICE_ID"
```

или только профиль на одном сервере:

```bash
curl -sS -X DELETE -H @~/user-auth.header \
  "https://api.novavpn.example/api/v1/devices/$DEVICE_ID/profiles/$SERVER_ID"
```

Ожидание: `204`. Удаление устройства снимает все его профили, удаление профиля —
только один.

## 2. Проверка

```bash
ssh root@HOST "wg show wg0 peers"
curl -sS -H @~/novavpn-admin-auth.header \
  "https://api.novavpn.example/api/v1/admin/servers/$SERVER_ID"
```

Ожидание: строки `peer <BASE64>` с отозванным ключом в выводе `wg show` нет; в
событиях `connections` у API поток `handshake_observed` для этого ключа
прекращается — после последнего handshake новых записей не появляется; трафик с
устройства не идёт.

## 3. Если владелец недоступен

Точечного отзыва чужого устройства у администратора нет — это ограничение §13
спецификации, и обещать его было бы ложью. Единственная немедленная мера в контракте
A-2 — перевести сервер в `draining`:

```bash
curl -sS -X POST -H @~/novavpn-admin-auth.header -H 'Content-Type: application/json' \
  -d '{"status":"draining"}' \
  "https://api.novavpn.example/api/v1/admin/servers/$SERVER_ID/maintenance"
```

Ожидание: `200` с поднятой `config_version`, и узел снимает **всех** пиеров сервера
на следующем опросе (не позже 27,5 с). Это заденет и здоровых пользователей — поэтому
дальше шаг 5.

## 4. После закрытия инцидента

Сервер возвращают в `online` (`node-drain.md`, шаг 5). Владельцу потерянного
устройства выдают новый профиль: старый отозван безвозвратно, а новый ключ получают
через `POST /api/v1/devices/{id}/keys/rotate`. Итог — строка в журнал операций
инцидента (`incident.md`, шаг 5).
