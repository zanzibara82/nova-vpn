-- Индексы под два запроса горячего пути узла (задача 10 и задача 9).
--
-- Ключи из отчёта узла приходят пачкой: ObservedDevicesByPublicKeys ищет устройство
-- по public_key, а уникальность в 0001 — по (user_id, public_key), поэтому без
-- отдельного индекса идёт последовательное чтение всей таблицы устройств.
CREATE INDEX devices_public_key ON devices (public_key);
-- EXISTS внутри того же запроса не фильтрует по статусу профиля, поэтому частичный
-- profiles_one_active_per_device_server ему не подходит: нужен полный (device_id, server_id).
CREATE INDEX profiles_device_server ON vpn_profiles (device_id, server_id);
-- DesiredCandidates читает профили одного сервера в порядке адреса: ведущая пара
-- (server_id, address_v4) отдаёт их уже отсортированными, без отдельной сортировки.
CREATE INDEX profiles_server_address ON vpn_profiles (server_id, address_v4);
-- Цепочка ротации идёт вниз по rotation_of (RotationDescendantIDs), а ON DELETE
-- SET NULL проверяет ту же колонку на каждого удаляемого потомка: без индекса это
-- перебор всей таблицы устройств на каждый узел цепочки.
CREATE INDEX devices_rotation_of ON devices (rotation_of) WHERE rotation_of IS NOT NULL;
-- Та же причина у профилей: rotate_from — внешний ключ ON DELETE SET NULL, и
-- удаление каждого профиля без индекса перебирает всю таблицу.
CREATE INDEX profiles_rotate_from ON vpn_profiles (rotate_from) WHERE rotate_from IS NOT NULL;
