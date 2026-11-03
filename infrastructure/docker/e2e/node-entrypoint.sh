#!/bin/sh
# Узловая точка входа стенда: короткая подготовка под root, затем настоящий агент
# без root (UID/GID 65532). NAT и DNS поднимаются только для run; init/enroll/status
# получают лишь доступный каталог состояния.
set -eu
umask 077

STATE_DIR=${NOVAVPN_NODE_STATE_DIR:-/var/lib/novavpn-node}
AGENT=/usr/local/bin/novavpn-node-agent
# Путь ожидаемого pid-файла unbound. Конфиг демона задаёт /run/unbound.pid сам;
# переменная нужна проверкам, чтобы не трогать /run хоста, и конфиг не меняет.
UNBOUND_PID_FILE_WAIT=${UNBOUND_PID_FILE_WAIT:-/run/unbound.pid}

prepare_state() {
	mkdir -p "$STATE_DIR"
	# Только сам каталог: рекурсивный chown произвольного дерева здесь не нужен.
	chown 65532:65532 "$STATE_DIR"
	chmod 0700 "$STATE_DIR"
}

start_nat() {
	# Отсутствие своей таблицы при первом старте — ожидаемое состояние, а не ошибка.
	# Но ошибка чтения списка таблиц — это не отсутствие: её нельзя принять за
	# первый старт, поэтому список читается с сохранением кода, а наличие своей
	# таблицы определяется только по успешно прочитанному списку.
	local tables
	tables=$(nft list tables ip 2>&1) || {
		printf 'узел: не удалось прочитать список таблиц nftables\n' >&2
		exit 1
	}
	if printf '%s\n' "$tables" | grep -qx 'table ip novavpn'; then
		nft delete table ip novavpn || {
			printf 'узел: не удалось удалить прежнюю таблицу NAT\n' >&2
			exit 1
		}
	fi
	nft -f /etc/novavpn/nat.nft || {
		printf 'узел: не удалось применить правила NAT\n' >&2
		exit 1
	}
	nft list table ip novavpn >/dev/null || {
		printf 'узел: таблица NAT не появилась после применения\n' >&2
		exit 1
	}
}

start_dns() {
	unbound-checkconf /etc/unbound/unbound.conf >/dev/null || {
		printf 'узел: конфигурация unbound неверна\n' >&2
		exit 1
	}
	rm -f "$UNBOUND_PID_FILE_WAIT"
	unbound -c /etc/unbound/unbound.conf || {
		printf 'узел: unbound не запустился\n' >&2
		exit 1
	}
	i=0
	while [ ! -s "$UNBOUND_PID_FILE_WAIT" ]; do
		i=$((i + 1))
		if [ "$i" -gt 50 ]; then
			printf 'узел: unbound не создал pid-файл, запуск не подтверждён\n' >&2
			exit 1
		fi
		sleep 0.1
	done
}

case "${1:-run}" in
run)
	prepare_state
	start_nat
	start_dns
	exec su-exec novavpn:novavpn "$AGENT" run
	;;
init | enroll | status)
	prepare_state
	exec su-exec novavpn:novavpn "$AGENT" "$@"
	;;
*)
	exec su-exec novavpn:novavpn "$AGENT" "$@"
	;;
esac