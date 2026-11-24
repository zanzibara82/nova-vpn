using System.Security.Cryptography;
using System.Text;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Storage;

namespace NovaVpn.Client.Core.Devices;

public sealed class DeviceService
{
    private readonly ApiClient _api;
    private readonly SessionService _session;
    private readonly DeviceIdentityStore _store;
    private readonly string _hostName;
    private bool _autoCreateSuppressed;

    public DeviceService(ApiClient api, SessionService session, DeviceIdentityStore store, string? hostName = null)
    {
        _api = api;
        _session = session;
        _store = store;
        _hostName = string.IsNullOrWhiteSpace(hostName) ? Environment.MachineName : hostName;
    }

    public DeviceIdentity? CurrentIdentity =>
        _session is { BaseUrl: var b, Email: { } e } ? _store.Get(DeviceIdentityStore.AccountKey(b, e)) : null;

    public static string IdempotencyKeyFor(string publicKey) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("device-create\n" + publicKey)))
            .ToLowerInvariant();

    public async Task<DeviceView> EnsureRegisteredAsync(CancellationToken ct)
    {
        if (_autoCreateSuppressed)
            throw new ApiException("bad_args", 0, "Устройство не создано: выберите «Создать устройство».");
        var (baseUrl, email) = Location();
        var accountKey = DeviceIdentityStore.AccountKey(baseUrl, email);
        var identity = _store.Get(accountKey);
        var devices = await ListWireAsync(ct);

        if (identity is not null)
        {
            var live = devices.FirstOrDefault(d => d.PublicKey == identity.PublicKey && d.RevokedAt is null);
            if (live is not null)
            {
                if (identity.DeviceId != live.Id) _store.Put(accountKey, identity with { DeviceId = live.Id });
                return live;
            }
            if (devices.Any(d => d.PublicKey == identity.PublicKey))
                identity = NewIdentity(baseUrl, email); // сохранённый ключ отозван: занять его нельзя
        }

        identity ??= NewIdentity(baseUrl, email);
        return await RegisterAsync(identity, accountKey, retryDuplicate: true, ct);
    }

    public async Task<DeviceView> CreateAsync(string name, CancellationToken ct)
    {
        var (baseUrl, email) = Location();
        var accountKey = DeviceIdentityStore.AccountKey(baseUrl, email);
        var current = _store.Get(accountKey);
        if (current?.DeviceId is Guid oldId)
            await DeleteAsync(oldId, ct);
        _autoCreateSuppressed = false;
        var identity = NewIdentity(baseUrl, email, name);
        return await RegisterAsync(identity, accountKey, retryDuplicate: false, ct);
    }

    public async Task DeleteAsync(Guid deviceId, CancellationToken ct)
    {
        var (baseUrl, email) = Location();
        var accountKey = DeviceIdentityStore.AccountKey(baseUrl, email);
        try
        {
            await _session.AuthorizedAsync<object?>(
                async (t, c) =>
                {
                    await _api.DeleteDeviceAsync(t, deviceId, c);
                    return null;
                }, ct);
        }
        catch (ApiException ex) when (ex.StatusCode == 404)
        {
            // Для «забыть устройство» отсутствие на сервере — уже достигнутый результат.
        }
        var current = _store.Get(accountKey);
        if (current?.DeviceId is null || current.DeviceId == deviceId) _store.Remove(accountKey);
        _autoCreateSuppressed = true;
    }

    public Task SuppressAutoCreateAsync()
    {
        _autoCreateSuppressed = true;
        return Task.CompletedTask;
    }

    private async Task<DeviceView> RegisterAsync(DeviceIdentity identity, string accountKey,
        bool retryDuplicate, CancellationToken ct)
    {
        _store.Put(accountKey, identity); // до запроса: повтор после сети идёт с той же парой
        var body = new DeviceCreate(identity.PublicKey, "windows", identity.Name);
        var idem = IdempotencyKeyFor(identity.PublicKey);
        try
        {
            var device = await _session.AuthorizedAsync(
                (t, c) => _api.CreateDeviceAsync(t, body, idem, c), ct);
            _store.Put(accountKey, identity with { DeviceId = device.Id });
            return device;
        }
        catch (ApiException ex) when (ex.Code == "duplicate_device" && retryDuplicate)
        {
            var devices = await ListWireAsync(ct);
            var live = devices.FirstOrDefault(d => d.PublicKey == identity.PublicKey && d.RevokedAt is null);
            if (live is not null)
            {
                _store.Put(accountKey, identity with { DeviceId = live.Id });
                return live;
            }
            var fresh = NewIdentity(identity.ApiBaseUrl, identity.Email, identity.Name);
            return await RegisterAsync(fresh, accountKey, retryDuplicate: false, ct);
        }
    }

    private Task<IReadOnlyList<DeviceView>> ListWireAsync(CancellationToken ct) =>
        _session.AuthorizedAsync((t, c) => _api.ListDevicesAsync(t, c), ct);

    private (Uri BaseUrl, string Email) Location()
    {
        if (_session.Current is null || _session.Email is null)
            throw new ApiException("unauthenticated", 401, "Сессия не открыта.");
        return (_session.BaseUrl, _session.Email);
    }

    private DeviceIdentity NewIdentity(Uri baseUrl, string email, string? name = null)
    {
        var pair = DeviceKeyPair.Generate();
        return new DeviceIdentity(baseUrl, email, null, pair.PublicKeyBase64, pair.PrivateKeyBase64,
            NormalizeName(name ?? _hostName), DateTimeOffset.UtcNow);
    }

    private static string NormalizeName(string name)
    {
        var trimmed = name.Trim();
        if (trimmed.Length == 0) return "Windows";
        return trimmed.Length <= 64 ? trimmed : trimmed[..64];
    }
}
