package wg

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestReadCounter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    int64
		wantErr bool
	}{
		{name: "zero", content: "0\n"},
		{name: "positive", content: "123456\n", want: 123456},
		{name: "whitespace", content: " \t42\r\n", want: 42},
		{name: "max-int64", content: "9223372036854775807\n", want: 9223372036854775807},
		{name: "empty", wantErr: true},
		{name: "only-whitespace", content: " \t\n", wantErr: true},
		{name: "invalid", content: "not-a-counter", wantErr: true},
		{name: "fraction", content: "1.5", wantErr: true},
		{name: "multiple-values", content: "1\n2", wantErr: true},
		{name: "negative", content: "-1", wantErr: true},
		{name: "min-int64", content: "-9223372036854775808", wantErr: true},
		{name: "overflow", content: "9223372036854775808", wantErr: true},
		{name: "uint64-max", content: "18446744073709551615", wantErr: true},
		{name: "underflow", content: "-9223372036854775809", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rx_bytes")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := readCounter(path)
			if tc.wantErr {
				if err == nil {
					t.Fatal("неверный счётчик принят как измерение")
				}
				if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "счётчик") {
					t.Fatal("ошибка должна содержать путь и русский контекст счётчика")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("счётчик: получено %d, ошибка %v; ожидалось %d", got, err, tc.want)
			}
		})
	}
}

func TestReadCounterReadErrors(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{filepath.Join(dir, "missing"), dir} {
		_, err := readCounter(path)
		if err == nil {
			t.Fatal("ошибка чтения не должна превращаться в нулевое измерение")
		}
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) || pathErr.Path != path {
			t.Fatal("исходная ошибка чтения должна сохраняться")
		}
		if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "счётчик") {
			t.Fatal("ошибка чтения должна содержать путь и русский контекст счётчика")
		}
	}
}

func TestReadCounterDistinguishesParseErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    error
	}{
		{name: "syntax", content: "not-a-counter", want: strconv.ErrSyntax},
		{name: "range", content: "9223372036854775808", want: strconv.ErrRange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rx_bytes")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := readCounter(path)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ошибка разбора должна различаться: получено %v, ожидалась %v", err, tc.want)
			}
			var numErr *strconv.NumError
			if !errors.As(err, &numErr) {
				t.Fatal("исходная ошибка strconv должна сохраняться в цепочке")
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatal("ошибка разбора должна содержать путь")
			}
		})
	}
}

func TestFromIPNets(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   net.IP
		bits int
		size int
		want string
	}{
		{"ipv4-4-host", net.IP{10, 99, 0, 7}, 32, 32, "10.99.0.7/32"},
		{"ipv4-16-host", net.IPv4(10, 99, 0, 7), 32, 32, "10.99.0.7/32"},
		{"ipv4-4-network", net.IP{10, 99, 0, 7}, 24, 32, "10.99.0.0/24"},
		{"ipv4-16-network", net.IPv4(10, 99, 0, 7), 24, 32, "10.99.0.0/24"},
		{"ipv4-4-default", net.IP{10, 99, 0, 7}, 0, 32, "0.0.0.0/0"},
		{"ipv4-16-default", net.IPv4(10, 99, 0, 7), 0, 32, "0.0.0.0/0"},
		{"ipv6-host", net.ParseIP("2001:db8::7"), 128, 128, "2001:db8::7/128"},
		{"ipv6-network", net.ParseIP("2001:db8::7"), 64, 128, "2001:db8::/64"},
		{"ipv6-default", net.ParseIP("2001:db8::7"), 0, 128, "::/0"},
		{"mapped-ipv6-prefix", net.IPv4(10, 99, 0, 7), 120, 128, "::ffff:10.99.0.0/120"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []net.IPNet{{IP: tc.ip, Mask: net.CIDRMask(tc.bits, tc.size)}}
			before := []net.IPNet{{IP: slices.Clone(input[0].IP), Mask: slices.Clone(input[0].Mask)}}
			got := fromIPNets(input)
			want := []netip.Prefix{netip.MustParsePrefix(tc.want)}
			if !slices.Equal(got, want) {
				t.Fatalf("префиксы: получено %v, ожидалось %v", got, want)
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("преобразование изменило исходный адрес или маску")
			}
		})
	}
}

func TestFromIPNetsSkipsUnsupported(t *testing.T) {
	valid := net.IPNet{IP: net.IPv4(10, 99, 0, 7), Mask: net.CIDRMask(32, 32)}
	for _, invalid := range []net.IPNet{
		{},
		{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)},
		{IP: net.IP{10, 99, 0, 7}},
		{IP: net.IP{10, 99, 0, 7}, Mask: net.IPMask{255, 0, 255, 0}},
		{IP: net.IP{10, 99, 0, 7}, Mask: net.IPMask{255}},
		{IP: net.IP{10, 99, 0, 7}, Mask: net.CIDRMask(64, 128)},
		{IP: net.ParseIP("2001:db8::7"), Mask: net.CIDRMask(24, 32)},
	} {
		got := fromIPNets([]net.IPNet{valid, invalid, valid})
		prefix := netip.MustParsePrefix("10.99.0.7/32")
		if !slices.Equal(got, []netip.Prefix{prefix, prefix}) {
			t.Fatalf("неподдерживаемые данные не пропущены либо изменён порядок: %v", got)
		}
	}
	if got := fromIPNets(nil); len(got) != 0 {
		t.Fatalf("для пустого входа ожидался пустой результат: %v", got)
	}
}

func TestFromIPNetsRoundTrip(t *testing.T) {
	input := []netip.Prefix{
		netip.MustParsePrefix("10.99.0.7/32"),
		netip.MustParsePrefix("10.99.0.7/24"),
		netip.MustParsePrefix("10.99.0.7/0"),
		netip.MustParsePrefix("2001:db8::7/128"),
		netip.MustParsePrefix("2001:db8::7/64"),
		netip.MustParsePrefix("2001:db8::7/0"),
		netip.MustParsePrefix("::ffff:10.99.0.7/120"),
	}
	before := slices.Clone(input)
	want := []netip.Prefix{
		netip.MustParsePrefix("10.99.0.7/32"),
		netip.MustParsePrefix("10.99.0.0/24"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("2001:db8::7/128"),
		netip.MustParsePrefix("2001:db8::/64"),
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("::ffff:10.99.0.0/120"),
	}
	if got := fromIPNets(toIPNets(input)); !slices.Equal(got, want) {
		t.Fatalf("обратное преобразование: получено %v, ожидалось %v", got, want)
	}
	if !slices.Equal(input, before) {
		t.Fatal("обратное преобразование изменило исходные префиксы")
	}
}
