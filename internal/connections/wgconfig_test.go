package connections

import (
	"net/netip"
	"strings"
	"testing"
)

func serverRow() Config {
	return Config{
		Address: netip.MustParsePrefix("10.99.7.42/32"),
		DNS:     []netip.Addr{netip.MustParseAddr("10.99.7.1")},
		MTU:     1420, Keepalive: 25,
		PeerPublicKey: "bm92YXZwbi1wbGFuLWZpeHR1cmUta2V5LTAwMDAwMDA=",
		PeerHost:      "de1.novavpn.local", PeerPort: 51820,
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}
}

func TestParseRoundTripIsStable(t *testing.T) {
	in := serverRow()
	text, err := in.SerializeNoPrivateKey()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	back, err := Parse(text)
	if err != nil {
		t.Fatalf("parse: %v (%s)", err, text)
	}
	again, err := back.SerializeNoPrivateKey()
	if err != nil {
		t.Fatalf("reserialize: %v", err)
	}
	if again != text {
		t.Fatalf("round-trip разъехался:\n--- первое\n%s\n--- второе\n%s", text, again)
	}
	if strings.Contains(text, "PrivateKey") {
		t.Fatalf("в тексте клиента появился приватный ключ: %s", text)
	}
}

func TestParseKeepsAddressAndAllowedIPs(t *testing.T) {
	text, err := serverRow().SerializeNoPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if c.Address.String() != "10.99.7.42/32" {
		t.Errorf("Address = %v, want 10.99.7.42/32", c.Address)
	}
	if len(c.AllowedIPs) != 1 || c.AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Errorf("AllowedIPs = %v", c.AllowedIPs)
	}
	if c.PeerPort != 51820 || c.PeerHost != "de1.novavpn.local" {
		t.Errorf("endpoint = %s:%d", c.PeerHost, c.PeerPort)
	}
}

func TestParseRejectsPrivateKeyLine(t *testing.T) {
	// Клиентский приватный ключ не проходит через API ни в какую сторону, и разбор
	// это закрепляет: конфиг с такой строкой — не наш конфиг.
	text, err := serverRow().SerializeNoPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(text, "[Interface]\n", "[Interface]\nPrivateKey = SKM= \n", 1)
	if _, err := Parse(bad); err == nil {
		t.Fatal("конфиг с PrivateKey принят")
	}
}

// Таблица гостевых значений, каждое из которых должно быть отвергнуто. Это проверка
// модели угроз (спецификация §2, строка «скомпрометированный ответ API»): серверные
// строки не имеют права попасть ни в shell, ни в чужую секцию конфига.
var hostile = []struct {
	name   string
	mutate func(*Config)
}{
	{"CRLF в host", func(c *Config) { c.PeerHost = "ok.example.com\r\nPrivateKey = SKA=" }},
	{"shell-метасимволы в host", func(c *Config) { c.PeerHost = "a;rm -rf /" }},
	{"обратные кавычки", func(c *Config) { c.PeerHost = "$(whoami).example.com" }},
	{"вложенная секция в host", func(c *Config) { c.PeerHost = "x.example.com\n[Peer]" }},
	{"неканонический pubkey", func(c *Config) { c.PeerPublicKey = "AAA=" }},
	{"unicode-обфускация host", func(c *Config) { c.PeerHost = "арьтм.-com" }},
	{"порт вне диапазона", func(c *Config) { c.PeerPort = 70000 }},
	{"порт нулевой", func(c *Config) { c.PeerPort = 0 }},
	{"маска не /32", func(c *Config) { c.Address = netip.MustParsePrefix("10.99.7.0/24") }},
	{"IPv6 allow-all без адреса", func(c *Config) {
		c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("::/0")}
	}},
	{"MTU за пределами", func(c *Config) { c.MTU = 9000 }},
	{"пустой endpoint host", func(c *Config) { c.PeerHost = "" }},
}

func TestSerializeRefusesHostileValues(t *testing.T) {
	for _, h := range hostile {
		t.Run(h.name, func(t *testing.T) {
			c := serverRow()
			h.mutate(&c)
			// Сериализатор обязан отказаться, а не записать: «собери и проверь потом»
			// здесь означало бы, что отказ ловит только парсер.
			text, err := c.SerializeNoPrivateKey()
			if err == nil {
				if _, perr := Parse(text); perr == nil {
					t.Fatalf("враждебное значение принято: %s", text)
				}
			}
		})
	}
}

func TestParseSeparatesForbiddenFromUnknownKey(t *testing.T) {
	// Разница между «ключ неизвестен» и «ключ запрещён» — не косметика: первое
	// означает непривычный нам конфиг, второе — что API прислал приватный ключ или
	// параметр, меняющий поведение ядра. Без отдельной ветки запрещённые ключи
	// отсекались бы общим «неизвестный ключ», и таблица forbidden стала бы мёртвым
	// кодом, который никто не проверяет.
	text, err := serverRow().SerializeNoPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	banned := strings.Replace(text, "[Interface]\n", "[Interface]\nPresharedKey = SKM= \n", 1)
	if _, err := Parse(banned); err == nil {
		t.Fatal("PresharedKey принят")
	} else if !strings.Contains(err.Error(), "запрещ") {
		t.Errorf("сообщение об отказе = %q, want указание на запрещённый ключ", err)
	}

	unknown := strings.Replace(text, "[Interface]\n", "[Interface]\nListenPort = 51820\n", 1)
	if _, err := Parse(unknown); err == nil {
		t.Fatal("ListenPort принят")
	} else if strings.Contains(err.Error(), "запрещ") {
		t.Errorf("неизвестный ключ назван запрещённым: %q", err)
	}
}
