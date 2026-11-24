using NovaVpn.Client.Core.Devices;
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class DeviceIdentityStoreTests
{
    private static readonly Uri Base = new("https://api.example/");

    [Fact]
    public void Roundtrip_is_bound_to_api_and_email()
    {
        using var dir = new TempDir();
        var store = new DeviceIdentityStore(dir.Path);
        var key = DeviceIdentityStore.AccountKey(Base, "a@b.c");
        var id = new DeviceIdentity(Base, "a@b.c", Guid.NewGuid(),
            "pub", "priv", "pc", DateTimeOffset.Parse("2026-11-24T10:00:00Z"));

        store.Put(key, id);

        var loaded = new DeviceIdentityStore(dir.Path).Get(key);
        Assert.Equal(id, loaded);
        Assert.NotEqual(key, DeviceIdentityStore.AccountKey(new Uri("https://other.example/"), "a@b.c"));
        Assert.NotEqual(key, DeviceIdentityStore.AccountKey(Base, "x@b.c"));
    }

    [Fact]
    public void Remove_deletes_only_that_record()
    {
        using var dir = new TempDir();
        var store = new DeviceIdentityStore(dir.Path);
        var k1 = DeviceIdentityStore.AccountKey(Base, "a@b.c");
        var k2 = DeviceIdentityStore.AccountKey(Base, "c@d.e");
        store.Put(k1, new DeviceIdentity(Base, "a@b.c", null, "p1", "s1", "pc", DateTimeOffset.UtcNow));
        store.Put(k2, new DeviceIdentity(Base, "c@d.e", null, "p2", "s2", "pc", DateTimeOffset.UtcNow));

        store.Remove(k1);

        Assert.Null(store.Get(k1));
        Assert.NotNull(store.Get(k2));
    }
}
