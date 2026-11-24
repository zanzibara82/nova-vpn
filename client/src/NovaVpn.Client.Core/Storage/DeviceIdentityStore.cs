using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Devices;

namespace NovaVpn.Client.Core.Storage;

public sealed class DeviceIdentityStore
{
    private const int CurrentSchema = 1;
    private readonly DpapiFile _file;
    private readonly object _gate = new();

    public DeviceIdentityStore(string rootDir)
        : this(new DpapiFile(Path.Combine(rootDir, "devices.dat"), "NovaVPN/devices/v1")) { }

    internal DeviceIdentityStore(DpapiFile file) => _file = file;

    public static string AccountKey(Uri baseUrl, string email)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(
            baseUrl.GetLeftPart(UriPartial.Authority) + "\n" + email.Trim()));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public DeviceIdentity? Get(string key) => Read().GetValueOrDefault(key);

    public void Put(string key, DeviceIdentity identity)
    {
        lock (_gate)
        {
            var all = Read();
            all[key] = identity;
            Write(all);
        }
    }

    public void Remove(string key)
    {
        lock (_gate)
        {
            var all = Read();
            if (!all.Remove(key)) return;
            if (all.Count == 0) _file.Delete();
            else Write(all);
        }
    }

    private Dictionary<string, DeviceIdentity> Read()
    {
        var plain = _file.Read();
        if (plain is null) return new(StringComparer.Ordinal);
        try
        {
            var doc = JsonSerializer.Deserialize<DeviceFile>(plain, JsonDefaults.Options);
            if (doc is null || doc.Schema != CurrentSchema)
                throw new StorageCorruptedException(_file.Path, new InvalidDataException("schema"));
            return new Dictionary<string, DeviceIdentity>(doc.Records, StringComparer.Ordinal);
        }
        catch (JsonException ex)
        {
            throw new StorageCorruptedException(_file.Path, ex);
        }
    }

    private void Write(Dictionary<string, DeviceIdentity> records) =>
        _file.Write(JsonSerializer.SerializeToUtf8Bytes(
            new DeviceFile(CurrentSchema, records), JsonDefaults.Options));

    private sealed record DeviceFile(int Schema, Dictionary<string, DeviceIdentity> Records);
}
