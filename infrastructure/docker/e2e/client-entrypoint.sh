#!/bin/sh
# Клиентская точка входа стенда. Здесь же создаётся приватный ключ (только внутри
# тома /state) и проверяется текст конфига, полученного от API: неожиданные секции
# и поля обязаны остановить запуск до настройки интерфейса.
set -eu
umask 077

STATE=${CLIENT_STATE_DIR:-/state}

die() {
	printf 'клиент: %s\n' "$*" >&2
	exit 1
}

# validate_config принимает только канонический ответ API стенда: две секции в
# порядке [Interface], [Peer], закрытые наборы ключей и точные значения стенда.
# Разбор идёт awk, без eval и без вызова в shell.
validate_config() {
	[ -f "$1" ] || die "конфиг не найден: $1"
	awk '
	function bad(msg) { print "клиент: " msg > "/dev/stderr"; ok = 0; exit }
	function need(key) {
		if (!(key in req)) {
			print "клиент: нет обязательного поля " substr(key, 2) > "/dev/stderr"
			ok = 0
			exit 1
		}
	}
	BEGIN { ok = 1; sect = ""; interfaces = 0; peers = 0 }
	/^[[:space:]]*$/ { next }
	/^\[/ {
		if ($0 == "[Interface]" && interfaces == 0 && peers == 0) {
			sect = "i"; interfaces = 1; next
		}
		if ($0 == "[Peer]" && interfaces == 1 && peers == 0) {
			sect = "p"; peers = 1; next
		}
		bad("недопустимая секция: " $0)
	}
	{
		p = index($0, " = ")
		if (p == 0) bad("строка не в форме «ключ = значение»: " $0)
		key = substr($0, 1, p - 1)
		val = substr($0, p + 3)
		if (key !~ /^[A-Za-z]+$/) bad("недопустимый ключ: " key)
		if (sect == "i") {
			if (key == "Address") {
				if (val != "10.99.7.2/32") bad("неверный Address: " val)
			} else if (key == "DNS") {
				if (val != "10.99.7.1") bad("неверный DNS: " val)
			} else if (key == "MTU") {
				if (val !~ /^[0-9]+$/ || val + 0 < 1280 || val + 0 > 1420) bad("неверный MTU: " val)
			} else {
				bad("недопустимый ключ [Interface]: " key)
			}
		} else if (sect == "p") {
			if (key == "PublicKey") {
				if (val !~ /^[A-Za-z0-9+\/]{43}=$/) bad("неверный PublicKey")
			} else if (key == "AllowedIPs") {
				if (val != "0.0.0.0/0") bad("неверный AllowedIPs: " val)
			} else if (key == "Endpoint") {
				if (val != "172.31.99.2:51820") bad("неверный Endpoint: " val)
			} else if (key == "PersistentKeepalive") {
				if (val !~ /^[0-9]+$/ || val + 0 < 5 || val + 0 > 120) bad("неверный PersistentKeepalive: " val)
			} else {
				bad("недопустимый ключ [Peer]: " key)
			}
		} else {
			bad("ключ вне секции: " key)
		}
		if (seen[sect key]++) bad("повтор ключа: " key)
		req[sect key] = 1
	}
	END {
		if (!ok) exit 1
		if (interfaces == 0 || peers == 0) {
			print "клиент: нужны секции [Interface] и [Peer]" > "/dev/stderr"
			exit 1
		}
		need("iAddress"); need("iMTU")
		need("pPublicKey"); need("pAllowedIPs"); need("pEndpoint"); need("pPersistentKeepalive")
		exit 0
	}
	' "$1"
}

# genkey не затирает существующий ключ и отказывает повреждённому: перевыпуск
# молча означал бы новое устройство вместо диагностики старого.
genkey() {
	mkdir -p "$STATE"
	chmod 700 "$STATE"
	path=$STATE/client.key
	if [ -e "$path" ]; then
		[ -f "$path" ] && [ ! -L "$path" ] || die "файл ключа не является обычным файлом"
		grep -Eq '^[A-Za-z0-9+/]{43}=$' "$path" || die "существующий ключ повреждён; перевыпуск не выполняется"
		wg pubkey < "$path" >/dev/null 2>&1 || die "существующий ключ повреждён; перевыпуск не выполняется"
	else
		(umask 077; wg genkey > "$path")
	fi
	chmod 600 "$path"
	# Ключ читается только этим процессом; наружу уходит публичная часть.
	wg pubkey < "$path"
}

# saveconfig принимает текст API со стандартного входа и кладёт его в том только
# после проверки формы: неожиданные поля не должны дождаться настройки интерфейса.
saveconfig() {
	mkdir -p "$STATE"
	chmod 700 "$STATE"
	tmp=$STATE/client.conf.new
	trap 'rm -f "$tmp"' EXIT
	cat > "$tmp"
	validate_config "$tmp"
	chmod 600 "$tmp"
	mv "$tmp" "$STATE/client.conf"
	trap - EXIT
}

run_client() {
	conf=$STATE/client.conf
	key=$STATE/client.key
	wgconf=$STATE/wg0.conf
	[ -f "$conf" ] || die "нет $conf"
	validate_config "$conf"
	[ -f "$key" ] || die "нет $key"
	[ ! -L "$key" ] || die "файл ключа не должен быть ссылкой"
	grep -Eq '^[A-Za-z0-9+/]{43}=$' "$key" || die "файл ключа повреждён"

	# Адрес закреплён валидатором, MTU — число 1280–1420; иное значение до сюда
	# не доходит.
	addr=$(sed -n 's/^Address = //p' "$conf")
	mtu=$(sed -n 's/^MTU = //p' "$conf")

	# wg setconf понимает только ключи WireGuard: Address и MTU — параметры
	# интерфейса и передаются отдельными командами. Приватный ключ вставляется
	# чтением файла, а не аргументом внешней команды.
	{
		printf '[Interface]\n'
		printf 'PrivateKey = '
		cat "$key"
		printf '\n'
		sed -n '/^\[Peer\]$/,$p' "$conf"
	} > "$wgconf"
	chmod 600 "$wgconf"
	# resolvconf в alpine нет: резолвер задаётся явно, адрес резолвера закрыт
	# валидатором.
	resolv=${CLIENT_RESOLV_CONF:-/etc/resolv.conf}
	printf 'nameserver 10.99.7.1\n' > "$resolv"
	chmod 644 "$resolv"

	# Порядок повторяет wg-quick для AllowedIPs=0.0.0.0/0, но без sysctl:
	# /proc/sys в контейнере только для чтения, а net.ipv4.conf.all.src_valid_mark
	# выставляет Docker при старте контейнера (sysctls в compose).
	ip link add wg0 type wireguard
	wg setconf wg0 "$wgconf"
	ip -4 address add "$addr" dev wg0
	ip link set mtu "$mtu" up dev wg0
	wg set wg0 fwmark 51820
	ip -4 route add 0.0.0.0/0 dev wg0 table 51820
	ip -4 rule add not fwmark 51820 table 51820
	ip -4 rule add table main suppress_prefixlength 0
	exec sleep infinity
}

if [ "${CLIENT_ENTRYPOINT_LIB:-0}" = "1" ]; then
	return 0 2>/dev/null || true
fi

case "${1:-run}" in
genkey) genkey ;;
saveconfig) saveconfig ;;
run) run_client ;;
*) exec "$@" ;;
esac