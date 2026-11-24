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
        using (var dir = new TempDir())
        {
            var log = new ClientLog(dir.Path);
            log.Write("a\r\nb");

            var lines = File.ReadAllLines(Directory.GetFiles(dir.Path).Single());
            Assert.Single(lines);
            Assert.DoesNotContain('\r', lines[0]);
            Assert.Contains("a", lines[0]);
            Assert.Contains("b", lines[0]);
            Assert.DoesNotContain("Bearer ", lines[0]);
        }

        using (var dir = new TempDir())
        {
            var log = new ClientLog(dir.Path);
            log.Write("x\nInjected: y");

            var lines = File.ReadAllLines(Directory.GetFiles(dir.Path).Single());
            Assert.Single(lines);
            Assert.DoesNotContain(lines,
                l => l.StartsWith("Injected:", StringComparison.Ordinal));
        }
    }
}
