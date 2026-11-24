using System.Text.Json;
using NovaVpn.Client.Core.Api;

namespace NovaVpn.Client.Core.Storage;

public sealed record ClientSettings(
    int Schema,
    Uri? ApiBaseUrl,
    int WindowWidth,
    int WindowHeight,
    Guid? SelectedDeviceId)
{
    public static ClientSettings Default => new(1, null, 900, 700, null);
}

public sealed class SettingsStore
{
    private const int CurrentSchema = 1;
    private readonly string _path;

    public SettingsStore(string rootDir) => _path = Path.Combine(rootDir, "settings.json");

    public ClientSettings Load()
    {
        if (!File.Exists(_path)) return ClientSettings.Default;
        try
        {
            var s = JsonSerializer.Deserialize<ClientSettings>(File.ReadAllBytes(_path), JsonDefaults.Options);
            return s is { Schema: CurrentSchema } ? s : ClientSettings.Default;
        }
        catch (JsonException)
        {
            return ClientSettings.Default;
        }
    }

    public void Save(ClientSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var tmp = _path + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllBytes(tmp, JsonSerializer.SerializeToUtf8Bytes(settings, JsonDefaults.Options));
        if (File.Exists(_path)) File.Replace(tmp, _path, null);
        else File.Move(tmp, _path);
    }
}
