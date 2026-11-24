using NovaVpn.Client.Core.Diagnostics;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class ClientLogTests
{
    [Fact]
    public void Rotates_and_keeps_three_files()
    {
        using var dir = new TempDir();
        var log = new ClientLog(dir.Path, maxBytes: 200);
        for (var i = 0; i < 40; i++) log.Write($"event {i} {new string('x', 30)}");

        var files = Directory.GetFiles(dir.Path, "client-*.log*").OrderBy(p => p).ToList();
        Assert.Equal(3, files.Count);
        Assert.All(files, f => Assert.True(new FileInfo(f).Length <= 260));
    }

    [Fact]
    public void Lines_do_not_accept_arbitrary_fields()
    {
        using var dir = new TempDir();
        var log = new ClientLog(dir.Path);
        log.Write("GET /api/v1/me 401 req=9a1b2c3d4e5f6071 12ms");

        var text = File.ReadAllText(Directory.GetFiles(dir.Path).Single());
        Assert.Contains("GET /api/v1/me", text);
        Assert.DoesNotContain("Bearer ", text);
    }
}
