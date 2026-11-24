using NovaVpn.Client.Core.Devices;
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class DpapiFileTests
{
    [Fact]
    public void Session_file_is_not_readable_with_device_entropy_and_vice_versa()
    {
        using var dir = new TempDir();
        var session = new SessionStore(dir.Path);
        session.Save(new StoredSession(1, new Uri("https://api.example/"), "a@b.c", "r1",
            DateTimeOffset.Parse("2026-12-24T10:00:00Z")));
        var devices = new DeviceIdentityStore(dir.Path);
        devices.Put("account-key", new DeviceIdentity(new Uri("https://api.example/"), "a@b.c",
            Guid.Parse("22222222-2222-4222-8222-222222222222"),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "private", "pc",
            DateTimeOffset.Parse("2026-11-24T10:00:00Z")));

        var sessionAsDevice = new DpapiFile(Path.Combine(dir.Path, "session.dat"),
            "NovaVPN/devices/v1");
        var devicesAsSession = new DpapiFile(Path.Combine(dir.Path, "devices.dat"),
            "NovaVPN/session/v1");

        Assert.Throws<StorageCorruptedException>(() => sessionAsDevice.Read());
        Assert.Throws<StorageCorruptedException>(() => devicesAsSession.Read());
        Assert.True(session.Exists);
        Assert.True(File.Exists(Path.Combine(dir.Path, "devices.dat")));
    }

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
