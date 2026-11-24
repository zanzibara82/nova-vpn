using System.Text.Json;
using NovaVpn.Client.Core.Api;

namespace NovaVpn.Client.Core.Storage;

public sealed record StoredSession(
    int Schema,
    Uri ApiBaseUrl,
    string Email,
    string RefreshToken,
    DateTimeOffset RefreshExpiresAt);

public sealed class SessionStore
{
    private const int CurrentSchema = 1;
    private readonly DpapiFile _file;

    public SessionStore(string rootDir)
        : this(new DpapiFile(System.IO.Path.Combine(rootDir, "session.dat"), "NovaVPN/session/v1")) { }

    internal SessionStore(DpapiFile file) => _file = file;

    public bool Exists => _file.Exists;
    public string Path => _file.Path;

    public StoredSession? Load()
    {
        var plain = _file.Read();
        if (plain is null) return null;
        StoredSession? stored;
        try
        {
            stored = JsonSerializer.Deserialize<StoredSession>(plain, JsonDefaults.Options);
        }
        catch (JsonException ex)
        {
            throw new StorageCorruptedException(_file.Path, ex);
        }
        if (stored is null || stored.Schema != CurrentSchema)
            throw new StorageCorruptedException(_file.Path,
                new InvalidDataException("Неизвестная схема session.dat"));
        return stored;
    }

    public void Save(StoredSession session)
    {
        if (session.Schema != CurrentSchema)
            throw new ArgumentException("Схема записи должна быть 1.", nameof(session));
        _file.Write(JsonSerializer.SerializeToUtf8Bytes(session, JsonDefaults.Options));
    }

    public void Clear() => _file.Delete();
}
