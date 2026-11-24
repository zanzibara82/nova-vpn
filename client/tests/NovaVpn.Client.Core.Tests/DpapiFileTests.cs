using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class DpapiFileTests
{
    [Fact]
    public void Roundtrip_is_not_plaintext_on_disk()
    {
        using var dir = new TempDir();
        var file = new DpapiFile(Path.Combine(dir.Path, "session.dat"), "NovaVPN/session/v1");
        var plain = System.Text.Encoding.UTF8.GetBytes("secret-marker-123");

        file.Write(plain);

        Assert.True(file.Exists);
        Assert.DoesNotContain("secret-marker-123",
            System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(file.Path)));
        Assert.Equal(plain, file.Read());
    }

    [Fact]
    public void Corrupt_block_is_reported_and_file_is_kept()
    {
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "session.dat");
        File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4, 5 });
        var file = new DpapiFile(path, "NovaVPN/session/v1");

        Assert.Throws<StorageCorruptedException>(() => file.Read());
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Missing_file_reads_as_null()
    {
        using var dir = new TempDir();
        var file = new DpapiFile(Path.Combine(dir.Path, "session.dat"), "NovaVPN/session/v1");
        Assert.Null(file.Read());
    }
}
