// Package connections собирает и разбирает клиентский конфиг WireGuard. Это
// единственный слой, который видит текст конфига целиком, и он намеренно не знает
// ни про HTTP, ни про БД: инъекционные тесты обязаны проверять модель угроз без
// поднятого стека.
//
// Приватного ключа в этом пакете нет ни в каком виде: в Config нет поля PrivateKey,
// а разбор отказывается от строки PrivateKey. То, чего не может быть в структуре,
// не может и утечь в ответе (спецификация §3, правило 1).
package connections

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/novavpn/novavpn/internal/db"
)

// Границы значений. MTU: 1280 — минимум WireGuard, 1420 — максимум, который узел
// сам себе выставил в схеме (0002); всё, что выше, не пройдёт по фрагментации.
// Keepalive: 5..120 — нижняя граница отсекает «каждый пакет», верхняя держится
// ниже 2-минутного таймаута отслеживания NAT.
const (
	MinMTU          = 1280
	MaxMTU          = 1420
	MinKeepalive    = 5
	MaxKeepalive    = 120
	tunnelPrefixLen = 32
)

// Форма публичного ключа — тот же CHECK devices_key_shape из 0001. Каноничность
// base64 проверяет единственная запись ключа (devices.Register и RotateKey), а
// здесь только форма: connections не импортирует devices, потому что оба модуля
// имеют право ходить исключительно в db — импорт модуля от модуля дал бы цикл
// через две задачи.
var (
	pubkeyShape = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	hostShape   = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
)

// forbidden — ключи, которые встречаются в языке конфигов WireGuard, но не входят
// в контракт цикла A. Причина отказа у каждого своя и обязана быть в сообщении:
// «неизвестный ключ» для PrivateKey было бы обманом — это известный ключ, который
// нам не прислан намеренно.
var forbidden = map[string]string{
	"PrivateKey":   "приватный ключ не покидает устройство клиента",
	"PresharedKey": "PSK меняет криптографиру пира и не входит в контракт A",
	"Table":        "Table правит таблицу маршрутизации ядра, а её нам выставляет узел",
	"FwMark":       "FwMark меняет поведение файрвола и не входит в контракт A",
	"SaveConfig":   "SaveConfig пишет файл на устройстве, это решение клиента, а не API",
	"LogConf":      "LogConf включает логирование конфига, где лежит приватный ключ",
}

// Разрешённые ключи по секциям. Порядок секций фиксирован, состав ключей закрыт:
// всё остальное — неизвестный ключ, и отказ на нём предпочтительнее «пропустить».
var (
	interfaceKeys = map[string]bool{"Address": true, "DNS": true, "MTU": true}
	peerKeys      = map[string]bool{"PublicKey": true, "AllowedIPs": true,
		"Endpoint": true, "PersistentKeepalive": true}
)

// defaultAllowedIPs — глобальный туннель по спецификации §7 («исключи утечки DNS
// за пределы туннеля»): весь трафик идёт через узел.
var defaultAllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}

// Config — клиентский конфиг без приватного ключа. Значения полей проверяются на
// границе и сериализатора, и парсера (check), поэтому «разобрано» и «собрано нами»
// означают одно и то же множество документов.
type Config struct {
	Address       netip.Prefix
	DNS           []netip.Addr
	MTU           int
	Keepalive     int
	PeerPublicKey string
	PeerHost      string
	PeerPort      int
	AllowedIPs    []netip.Prefix
}

// NodeTunnelAddress — адрес узла внутри туннеля: база пула + 1. Он же DNS-рекурсор
// для клиента (unbound на узле), поэтому и Render, и аллокация адресов (задача 4)
// считают его одними руками: расхождение было бы «DNS клиента смотрит не туда».
func NodeTunnelAddress(pool netip.Prefix) netip.Addr {
	return pool.Addr().Next()
}

// is4 — IPv4 в обоих представлениях netip: MustParseAddr("10.0.0.1") даёт
// 4-in-6, где Is4() лжёт, а Unmap() возвращает истинный IPv4.
func is4(a netip.Addr) bool { return a.Unmap().Is4() }

func Render(srv db.VpnServer, address netip.Addr) (string, error) {
	c := Config{
		Address:       netip.PrefixFrom(address, tunnelPrefixLen),
		DNS:           []netip.Addr{NodeTunnelAddress(srv.AddressPoolV4)},
		MTU:           int(srv.Mtu),
		Keepalive:     int(srv.KeepaliveSec),
		PeerPublicKey: srv.PublicKey,
		PeerHost:      srv.AdvertisedHost,
		PeerPort:      int(srv.ListenPort),
		AllowedIPs:    defaultAllowedIPs,
	}
	return c.SerializeNoPrivateKey()
}

// SerializeNoPrivateKey — каноническая сборка: порядок ключей зафиксирован,
// разделитель «ключ = значение» один на весь текст, в конце — перевод строки.
// Именно эта форма идёт наружу, и именно она проверяется на round-trip.
func (c Config) SerializeNoPrivateKey() (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", c.Address)
	fmt.Fprintf(&b, "DNS = %s\n", joinList(addrStrings(c.DNS)))
	fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.PeerPublicKey)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", joinList(prefixStrings(c.AllowedIPs)))
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", c.PeerHost, c.PeerPort)
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Keepalive)
	return b.String(), nil
}

// check — единственное место, где известно, какие значения вообще имеют право
// попасть в конфиг. И сериализатор, и парсер проходят через неё: проверка только
// на одном конце оставила бы «враждебное значение прошло сборку, а потом его
// отверг разбор», то есть дыру ровно там, где API сам собирает текст.
func (c Config) check() error {
	if !c.Address.IsValid() || c.Address.Bits() != tunnelPrefixLen || !is4(c.Address.Addr()) {
		return fmt.Errorf("connections: адрес туннеля обязан быть IPv4 с маской /%d, а не %q",
			tunnelPrefixLen, c.Address)
	}
	if len(c.DNS) == 0 {
		return errors.New("connections: DNS не задан")
	}
	for _, d := range c.DNS {
		if !d.IsValid() || !is4(d) {
			return fmt.Errorf("connections: DNS-адрес %q не IPv4", d)
		}
	}
	if c.MTU < MinMTU || c.MTU > MaxMTU {
		return fmt.Errorf("connections: MTU %d вне диапазона %d..%d", c.MTU, MinMTU, MaxMTU)
	}
	if c.Keepalive < MinKeepalive || c.Keepalive > MaxKeepalive {
		return fmt.Errorf("connections: PersistentKeepalive %d вне диапазона %d..%d",
			c.Keepalive, MinKeepalive, MaxKeepalive)
	}
	if !pubkeyShape.MatchString(c.PeerPublicKey) {
		return fmt.Errorf("connections: публичный ключ узла неверной формы (%d символов)",
			len(c.PeerPublicKey))
	}
	if !hostShape.MatchString(c.PeerHost) {
		// Значение в сообщение не выносим: host приходит из строки оператора, и
		// печать его в журнале — это способ унести управление в сам журнал.
		return errors.New("connections: host узла не проходит форму имени хоста")
	}
	if c.PeerPort < 1 || c.PeerPort > 65535 {
		return fmt.Errorf("connections: порт узла %d вне диапазона 1..65535", c.PeerPort)
	}
	if len(c.AllowedIPs) == 0 {
		return errors.New("connections: AllowedIPs не заданы")
	}
	for _, p := range c.AllowedIPs {
		if !p.IsValid() {
			return fmt.Errorf("connections: AllowedIPs содержит некорректную сеть %q", p)
		}
		// ADR-007: ::/0 без IPv6-адреса в [Interface] — не «нейтральное значение», а
		// тихий blackhole: маршрут есть, а идти по нему некому.
		if !is4(p.Addr()) {
			return fmt.Errorf("connections: AllowedIPs содержит IPv6-сеть %q, а IPv6 в туннеле нет", p)
		}
	}
	return nil
}

// Parse читает канонический текст конфига. Разбор нарочито закрытый: две секции в
// этом порядке, перечисленные ключи без повторов и без значений с управляющими
// символами. Всё, что выходит за рамки, — ошибка, а не «пропущенное поле».
func Parse(text string) (Config, error) {
	var c Config
	// \r проверяется разом по всему тексту: после split по \n он остался бы хвостом
	// значения и уехал бы в Config, минуя проверку построчного разбора.
	if strings.ContainsRune(text, '\r') {
		return Config{}, errors.New(`connections: конфиг содержит символ возврата каретки`)
	}
	section := ""
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch line {
			case "[Interface]":
				if section != "" {
					return Config{}, fmt.Errorf("connections: строка %d: [Interface] повторяется или идёт не первым", i+1)
				}
				section = "Interface"
			case "[Peer]":
				if section != "Interface" {
					return Config{}, fmt.Errorf("connections: строка %d: [Peer] раньше [Interface]", i+1)
				}
				section = "Peer"
			default:
				return Config{}, fmt.Errorf("connections: строка %d: неизвестная секция %q", i+1, line)
			}
			continue
		}
		if section == "" {
			return Config{}, fmt.Errorf("connections: строка %d: ключ %q вне секции", i+1, line)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("connections: строка %d: нет разделителя %q", i+1, "=")
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if value == "" {
			return Config{}, fmt.Errorf("connections: строка %d: у ключа %q пустое значение", i+1, key)
		}
		// Управляющие символы в значении — это способ перенести в конфиг вторую
		// секцию или команду; пробел (0x20) законен в списках через запятую.
		if strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 }) {
			return Config{}, fmt.Errorf("connections: строка %d: значение ключа %q содержит управляющий символ", i+1, key)
		}
		sectionID := section + "." + key
		if seen[sectionID] {
			return Config{}, fmt.Errorf("connections: строка %d: повторный ключ %q", i+1, key)
		}
		seen[sectionID] = true
		if reason, bad := forbidden[key]; bad {
			return Config{}, fmt.Errorf("connections: строка %d: ключ %q запрещён — %s", i+1, key, reason)
		}
		allowed := interfaceKeys
		if section == "Peer" {
			allowed = peerKeys
		}
		if !allowed[key] {
			return Config{}, fmt.Errorf("connections: строка %d: ключ %q не входит в секцию [%s]", i+1, key, section)
		}
		if err := assign(&c, key, value, i+1); err != nil {
			return Config{}, err
		}
	}
	if section != "Peer" {
		return Config{}, errors.New("connections: в конфиге нет секции [Peer]")
	}
	if err := c.check(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func assign(c *Config, key, value string, line int) error {
	bad := func(what string) error {
		return fmt.Errorf("connections: строка %d: %s", line, what)
	}
	switch key {
	case "Address":
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return bad(fmt.Sprintf("Address %q разобран не был", value))
		}
		if p.String() != value {
			return bad(fmt.Sprintf("Address %q записан неканонически, канон — %s", value, p))
		}
		c.Address = p
	case "DNS":
		addrs, err := parseList(value)
		if err != nil {
			return bad("DNS разобран не был")
		}
		c.DNS = make([]netip.Addr, 0, len(addrs))
		for _, item := range addrs {
			a, err := netip.ParseAddr(item)
			if err != nil {
				return bad(fmt.Sprintf("DNS-запись %q не является адресом", item))
			}
			if a.String() != item {
				return bad(fmt.Sprintf("DNS-запись %q записана неканонически, канон — %s", item, a))
			}
			c.DNS = append(c.DNS, a)
		}
	case "MTU":
		n, err := parseBoundedInt(value)
		if err != nil {
			return bad("MTU не является числом с канонической записью")
		}
		c.MTU = n
	case "PublicKey":
		c.PeerPublicKey = value
	case "AllowedIPs":
		items, err := parseList(value)
		if err != nil {
			return bad("AllowedIPs разобраны не были")
		}
		c.AllowedIPs = make([]netip.Prefix, 0, len(items))
		for _, item := range items {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return bad(fmt.Sprintf("AllowedIPs содержит %q, а не сеть", item))
			}
			if p.String() != item {
				return bad(fmt.Sprintf("AllowedIPs содержит неканоническую запись %q, канон — %s", item, p))
			}
			c.AllowedIPs = append(c.AllowedIPs, p)
		}
	case "Endpoint":
		// Последний «:», а не первый: значение host по паттерну двоеточия не содержит,
		// и сдвиг на последний оставляет ошибочный формат видимым, а не тихо порезанным.
		i := strings.LastIndex(value, ":")
		if i < 0 {
			return bad("Endpoint без порта")
		}
		host, portText := value[:i], value[i+1:]
		if !hostShape.MatchString(host) {
			return bad("Endpoint содержит host недопустимой формы")
		}
		port, err := parseBoundedInt(portText)
		if err != nil {
			return bad("Endpoint содержит порт нечислом")
		}
		c.PeerHost, c.PeerPort = host, port
	case "PersistentKeepalive":
		n, err := parseBoundedInt(value)
		if err != nil {
			return bad("PersistentKeepalive не является числом с канонической записью")
		}
		c.Keepalive = n
	default:
		return bad(fmt.Sprintf("ключ %q не присваивается", key))
	}
	return nil
}

// parseBoundedInt требует канонической десятичной записи: «025» — это не 25, а
// способ договориться с парсером так, чтобы в конфиге было написано одно, а
// прочитано другое.
func parseBoundedInt(value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if strconv.Itoa(n) != value {
		return 0, fmt.Errorf("connections: %q не каноническое число", value)
	}
	return n, nil
}

func parseList(value string) ([]string, error) {
	items := strings.Split(value, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, errors.New("connections: список с пустым элементом")
		}
		out = append(out, item)
	}
	return out, nil
}

func joinList(items []string) string { return strings.Join(items, ", ") }

func addrStrings(in []netip.Addr) []string {
	out := make([]string, len(in))
	for i, a := range in {
		out[i] = a.String()
	}
	return out
}

func prefixStrings(in []netip.Prefix) []string {
	out := make([]string, len(in))
	for i, p := range in {
		out[i] = p.String()
	}
	return out
}
