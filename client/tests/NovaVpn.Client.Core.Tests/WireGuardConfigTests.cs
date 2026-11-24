using System.Text;
using NovaVpn.Client.Core.Config;
using NovaVpn.Client.Core.Devices;

namespace NovaVpn.Client.Core.Tests;

public sealed class WireGuardConfigTests
{
    private static readonly DeviceKeyPair Pair = DeviceKeyPair.Generate();

    private static string ServerText(string publicKey = "") =>
        "[Interface]\n" +
        "Address = 10.66.0.2/32\n" +
        "DNS = 10.66.0.1\n" +
        "MTU = 1420\n" +
        "\n" +
        "[Peer]\n" +
        $"PublicKey = {(publicKey.Length == 0 ? DeviceKeyPair.Generate().PublicKeyBase64 : publicKey)}\n" +
        "AllowedIPs = 0.0.0.0/0, ::/0\n" +
        "Endpoint = 203.0.113.1:51820\n" +
        "PersistentKeepalive = 25\n";

    [Fact]
    public void Inserts_private_key_after_interface_and_preserves_tail()
    {
        var text = ServerText();

        var composed = WireGuardConfig.Compose(text, Pair.PrivateKeyBase64, Pair.PublicKeyBase64);

        Assert.StartsWith("[Interface]\nPrivateKey = " + Pair.PrivateKeyBase64 + "\nAddress = 10.66.0.2/32\n",
            composed);
        var serverTail = text["[Interface]\n".Length..];
        Assert.Contains(serverTail, composed);
        Assert.EndsWith("PersistentKeepalive = 25\n", composed);
        Assert.DoesNotContain("\r", composed);
        Assert.DoesNotContain("\uFEFF", composed, StringComparison.Ordinal);
        Assert.Equal(Encoding.UTF8.GetByteCount(composed),
            new UTF8Encoding(false).GetByteCount(composed));
    }

    [Fact]
    public void Rejects_wrong_public_key()
    {
        var ex = Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(ServerText(), Pair.PrivateKeyBase64,
                DeviceKeyPair.Generate().PublicKeyBase64));
        Assert.Contains("публичн", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_invalid_private_key()
    {
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(ServerText(), "not-base64", Pair.PublicKeyBase64));
    }

    [Theory]
    [InlineData("\r\n")]
    public void Rejects_crlf(string newline)
    {
        var text = ServerText().Replace("\n", newline);
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(text, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_nul_and_bom()
    {
        Assert.Throws<ConfigException>(() => WireGuardConfig.Compose(
            ServerText().Replace("MTU = 1420", "MTU = 142\0"), Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
        Assert.Throws<ConfigException>(() => WireGuardConfig.Compose(
            "\uFEFF" + ServerText(), Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_missing_final_lf()
    {
        var text = ServerText().TrimEnd('\n');
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(text, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_duplicate_sections_and_existing_private_key()
    {
        var duplicate = ServerText().Replace("[Peer]", "[Interface]\n[Peer]");
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(duplicate, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));

        var withKey = ServerText().Replace("[Interface]\n",
            "[Interface]\nPrivateKey = " + Pair.PrivateKeyBase64 + "\n");
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(withKey, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_unknown_section_and_malformed_line()
    {
        Assert.Throws<ConfigException>(() => WireGuardConfig.Compose(
            ServerText().Replace("[Peer]", "[Peer]\n[Extra]"), Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
        Assert.Throws<ConfigException>(() => WireGuardConfig.Compose(
            ServerText().Replace("MTU = 1420", "MTU=1420"), Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_missing_peer()
    {
        var text = ServerText().Split("[Peer]")[0];
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(text, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }
}
