using System.Text;
using NovaVpn.Client.Core.Config;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class ConfigExporterTests
{
    [Theory]
    [InlineData("Berlin 1", "NovaVPN-Berlin1.conf")]
    [InlineData("ams-01_nl", "NovaVPN-ams-01_nl.conf")]
    [InlineData("../../etc/passwd", "NovaVPN-....etcpasswd.conf")]
    [InlineData("Москва", "NovaVPN-server.conf")]
    [InlineData("", "NovaVPN-server.conf")]
    public void Default_name_is_sanitized(string server, string expected)
    {
        Assert.Equal(expected, ConfigExporter.DefaultFileName(server));
    }

    [Fact]
    public void Write_uses_utf8_without_bom_and_overwrites()
    {
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "NovaVPN-x.conf");
        File.WriteAllText(path, "old");

        ConfigExporter.Write(path, "[Interface]\nPrivateKey = x\n");

        var bytes = File.ReadAllBytes(path);
        Assert.False(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF);
        Assert.Equal("[Interface]\nPrivateKey = x\n", Encoding.UTF8.GetString(bytes));
    }
}
