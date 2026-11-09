# S2: unbound как резолвер узла в harness

Дата замера: 2026-11-02 и 2026-11-03 (живой прогон стенда и две точечные пробы).
Статус: спайк выполнен, ответы зафиксированы в ADR-005 спецификации цикла A.
Вопрос спайка: можно ли держать резолвер внутри контейнера узла так, чтобы клиент
в туннеле получал через него имена, запросы из управляющей сети отвергались,
содержимое запросов не попадало в журнал, и при этом сам резолвер не требовал
сетевых привилегий.

Все строки вывода ниже — фактические строки прогонов. Журналы:
`.superpowers/sdd/2026-10-27-novavpn-cycle-a3-node-runtime/task-12-run3.log`
(полный зелёный прогон `make e2e`), `task-12-spike-dnsraw.log` (замеры на живом
стенде), `task-12-spike-nslookup.log` и `task-12-spike-forwarder.log` (одиночные
пробы того же конфига вне стенда).

## Условия, в которых измерялось

| Параметр | Значение |
|---|---|
| Резолвер | unbound `Version 1.20.0`, образ узла на `alpine:3.20` |
| Конфиг | `infrastructure/docker/e2e/unbound.conf`, проверка `unbound-checkconf: no errors in /etc/unbound/unbound.conf` |
| Форвардер | dnsmasq в контейнере `probe`, адрес `172.31.98.3` |
| Топология | harness `172.31.99.0/24` (node1 `.2`, client1 `.3`), uplink `172.31.98.0/24` (node1 `.2`, probe `.3`), туннель `10.99.7.0/24` (узел `.1`, клиент `.2`) |
| Процесс узла | `PID 1 novavpn /usr/local/bin/novavpn-node-agent run`, `PID 19 unbound unbound -c /etc/unbound/unbound.conf` |
| Клиент | BusyBox `v1.36.1`, `tcpdump version 4.99.4`, `DiG 9.18.49` |

## Ответ 1: unbound не просит `NET_ADMIN`, но просит сбросить привилегии

Сетевых capabilities резолверу не нужно: в контейнере с `CapAdd=[]`,
`privileged=false` тот же образ и тот же конфиг стартовал и отвечал на 53/udp
(`task-12-spike-nslookup.log`). В полном стенде `NET_ADMIN` и `NET_RAW` на узле
есть — они нужны агенту и `ping`-проверкам, а не unbound:
`CapAdd=[NET_ADMIN NET_RAW] privileged=false`, и unbound — отдельный процесс
с PID 19 от пользователя `unbound`.

Одиночный замер с `--cap-drop ALL` показал, что именно всё-таки требуется
(`task-12-spike-dnsraw.log`):

```
[1793605147] unbound[1:0] warning: unable to initgroups unbound: Operation not permitted
[1793605147] unbound[1:0] fatal error: unable to set group id of unbound: Operation not permitted
exited exit=1
```

Значит unbound нужны штатные `SETUID`/`SETGID` из набора Docker по умолчанию: он
обязан сменить пользователя после привязки сокета. Это свойство процесса, а не
требование к правам узла, и оно не влияет на развёртывание: образ узла и так
получает `NET_ADMIN`, а `unbound` запускается внутри него.

## Ответ 2: запрос из сети без туннеля отвергается access-control, а не маршрутом

Ключевые строки конфига:

```
    access-control: 10.99.7.0/24 allow
    access-control: 0.0.0.0/0 refuse
    do-ip6: no
```

`unbound` слушает не адрес туннеля, а всё: в контейнере узла —
`udp 0 0 0.0.0.0:53`. Ограничение делает список ACL, а не привязка интерфейса, и
`interface:` в конфиге не задан. Поэтому ADR-005 уточняется: конфигурировать
привязку к `10.99.7.1` нельзя — на момент старта unbound интерфейса `wg0` ещё нет,
и привязка к туннельному адресу сделала бы резолвер зависимым от порядка старта.

Отвержение с живого стенда, запрос из client1 к узлу по адресу harness-сети
(`task-12-spike-dnsraw.log`, строки после `### dig к резолверу из сети без туннеля`):

```
; <<>> DiG 9.18.49 <<>> +tries=1 +time=3 +noedns @172.31.99.2 probe.e2e.test
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 47633
;; flags: qr rd ad; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available
dig_rc=0
```

Тот же вывод `nslookup` из образа клиента против того же конфига, снятый отдельно
(`task-12-spike-nslookup.log`):

```
Server:		172.31.99.2
Address:	172.31.99.2#53

** server can't find probe.e2e.test: REFUSED

nslookup_rc=1
```

Здесь важны два факта, и второй — причина, по которой фаза `dns` в скрипте
свершает ответ, а не код возврата.

- Код выхода `dig` при REFUSED равен `0`, поэтому «резолвер отверг» нельзя
  доказывать кодом: молчание файрвола и верный отказ были бы неразличимы.
  Решение принято по разобранному `status:`.
- `nslookup` на этом стенде непригоден как доказательство резолвинга: он шлёт ещё
  и AAAA, и даже при верно отданной A-записи уходит с кодом 1:

```
Non-authoritative answer:
Name:	probe.e2e.test
Address: 172.31.98.3
;; Got SERVFAIL reply from 10.99.7.1
** server can't find probe.e2e.test: SERVFAIL

nslookup_rc=1
```

## Ответ 3: клиента в туннеле резолвер обслуживает

Запрос того же резолвера по туннельному адресу с того же клиента
(`task-12-spike-dnsraw.log`):

```
; <<>> DiG 9.18.49 <<>> +tries=1 +time=3 +noedns @10.99.7.1 probe.e2e.test
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10684
;; ANSWER SECTION:
probe.e2e.test.		0	IN	A	172.31.98.3
;; SERVER: 10.99.7.1#53(10.99.7.1) (UDP)
dig_rc=0
```

Путь запроса — туннель, а не управляющая сеть: `resolv.conf` клиента содержит
ровно `nameserver 10.99.7.1`, а маршрут до него разрешается в `wg0`:

```
10.99.7.1 dev wg0 table 51820 src 10.99.7.2 uid 0
```

## Ответ 4: ни строк запросов в журнале, ни файла журнала

В конфиге `log-queries: no` и `log-replies: no`, `logfile` не задан, поэтому
писать некуда и нечего. Замеры на живом стенде: строк `query:`/`reply:` в выводе
контейнера узла — `0`, всего строк в выводе контейнера узла — `0`,
`ls: /var/log/unbound.log: No such file or directory`. Проверка файла журнала в
фазу не включена: `grep` по заведомо отсутствующему файлу выглядел бы как
проверка, ничего не доказывающая.

## Ответ 5: в стенде форвард, а не рекурсия, и это ограничение стенда

Конфиг узла отправляет всё, что не закрыто локальной зоной, на один адрес:

```
    local-zone: "e2e.test." transparent
    forward-addr: 172.31.98.3
```

`local-zone: ... transparent` нужен именно потому, что зона стенда не должна
получать авторитетных ответов из конфига: запрос проходит к итератору, а итератор
идёт к форвардеру. Без этой строки имя из `e2e.test` не резолвилось бы никак.

Замер форвардера отдельно от узла (`task-12-spike-forwarder.log`, dnsmasq из
`probe`-образа в сети `172.31.98.0/24`, конфиг
`infrastructure/docker/e2e/dnsmasq.conf`):

```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48783
probe.e2e.test.		0	IN	A	172.31.98.3
--- dig AAAA к форвардеру ---
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 6646
```

Отсюда механизм AAAA-провала: dnsmasq стенда знает только A-записи двух имён, на
AAAA он отвечает REFUSED, а unbound, не получив данных от вышестоящего сервера,
возвращает клиенту SERVFAIL. Это поведение конкретной сборки стенда, а не свойство
unbound: форвардер выбран потому, что у стенда нет доступа в интернет — сети
созданы изолированно, `no-resolv` в конфиге dnsmasq обязателен, иначе проверка
«запрос ушёл через туннель» перестала бы что-либо доказывать. Настоящий узел
будет резолвить рекурсивно от корня (без `forward-addr`, с корневой зоной), и
тогда AAAA-ответы придут откуда-то из сети. Поэтому:

- доказанным считается поведение форвардера (клиент в туннеле получает ответ,
  клиент вне туннеля получает REFUSED, журнал пуст);
- поведение рекурсивного резолвера на реальном VPS остаётся не проверенным и
  относится к задаче 19, а не к этому спайку.

## Чего эксперимент не показал (не переносить в продукт как доказанное)

- Перехват на стороне узла не измерен: в образе узла нет `tcpdump`
  (`timeout: can't execute 'tcpdump': No such file or directory`, `cap_rc=127`).
  Доказательство «нет утечки» снимается на `eth0` клиента, а путь до резолвера
  подтверждается маршрутом (`dev wg0 table 51820`), а не пакетом на узле.
- IPv6 на клиенте проверен состоянием (нет глобального адреса, нет маршрута по
  умолчанию, нет пути наружу), а не поведением резолвера при включённом IPv6.
- unbound не проверялся под нагрузкой и без `NET_RAW` в составе узла: в стенде эти
  права отданы контейнеру целиком, и разделить их по процессам конфиг не требует.
- Производительность, кэш и TTL в стенде не измерялись: записи отдаются с TTL 0,
  потому что их отдаёт dnsmasq с `address=`.

## Как повторить

```sh
# 1. полный прогон (включает dns-фазу): стенд поднимается и снимается сам
make e2e

# 2. точечная проба access-control без стенда: тот же образ узла и тот же конфиг
docker network create --driver bridge --subnet 172.31.99.0/24 novavpn-spike-net
docker run -d --name novavpn-spike-unbound --network novavpn-spike-net \
  --ip 172.31.99.2 --entrypoint unbound novavpn-e2e-node1:local \
  -c /etc/unbound/unbound.conf -d
docker run --rm --network novavpn-spike-net --ip 172.31.99.3 \
  --entrypoint sh novavpn-e2e-client1:local \
  -c 'nslookup probe.e2e.test 172.31.99.2; echo nslookup_rc=$?'
docker rm -f novavpn-spike-unbound
docker network rm novavpn-spike-net

# 3. проба форвардера: образ probe сам по себе в сети uplink
docker network create --driver bridge --subnet 172.31.98.0/24 novavpn-spike-up
docker run -d --name novavpn-spike-dnsmasq --network novavpn-spike-up \
  --ip 172.31.98.3 novavpn-e2e-probe:local
docker run --rm --network novavpn-spike-up --ip 172.31.98.9 --entrypoint sh \
  novavpn-e2e-client1:local \
  -c 'dig +tries=1 +time=3 +noedns @172.31.98.3 probe.e2e.test'
docker rm -f novavpn-spike-dnsmasq
docker network rm novavpn-spike-up
```

После точечных проб сети `novavpn-spike-*` обязаны быть удалены: `make e2e`
отказывается поднимать стенд, если любая сеть Docker пересекается с
`172.31.98.0/24` или `172.31.99.0/24`.
