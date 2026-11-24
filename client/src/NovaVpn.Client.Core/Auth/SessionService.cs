using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Storage;

namespace NovaVpn.Client.Core.Auth;

public sealed record SessionSnapshot(
    Uri BaseUrl,
    string Email,
    string AccessToken,
    DateTimeOffset AccessExpiresAt);

public sealed class SessionService
{
    private readonly ApiClient _api;
    private readonly Uri _baseUrl;
    private readonly SessionStore _store;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private string? _access;
    private string? _refresh;
    private SessionSnapshot? _current;

    public SessionService(ApiClient api, Uri baseUrl, SessionStore store, TimeProvider? time = null)
    {
        _api = api;
        _baseUrl = baseUrl;
        _store = store;
        _time = time ?? TimeProvider.System;
    }

    public SessionSnapshot? Current => _current;
    public Uri BaseUrl => _baseUrl;
    public string? Email => _current?.Email;
    public string? StartupError { get; private set; }
    public event Action? Changed;

    public async Task<SessionSnapshot> LoginAsync(string email, string password, CancellationToken ct)
    {
        ValidateCredentials(email, password);
        return Apply(await _api.LoginAsync(email.Trim(), password, ct), email.Trim());
    }

    public async Task<SessionSnapshot> RegisterAsync(string email, string password, CancellationToken ct)
    {
        ValidateCredentials(email, password);
        return Apply(await _api.RegisterAsync(email.Trim(), password, ct), email.Trim());
    }

    public async Task<MeView> GetMeAsync(CancellationToken ct) =>
        await AuthorizedAsync((t, c) => _api.GetMeAsync(t, c), ct);

    public async Task<bool> TryRestoreAsync(CancellationToken ct)
    {
        StartupError = null;
        StoredSession? stored;
        try
        {
            stored = _store.Load();
        }
        catch (StorageCorruptedException)
        {
            StartupError = "Хранилище повреждено или принадлежит другому пользователю. Войдите заново.";
            return false;
        }
        if (stored is null || stored.ApiBaseUrl != _baseUrl) return false;
        if (stored.RefreshExpiresAt <= _time.GetUtcNow())
        {
            _store.Clear();
            return false;
        }
        _refresh = stored.RefreshToken;
        try
        {
            Apply(await _api.RefreshAsync(stored.RefreshToken, ct), stored.Email);
            return true;
        }
        catch (ApiException ex) when (ex.Code is "refresh_token_invalid" or "account_locked")
        {
            ClearLocal();
            return false;
        }
    }

    public async Task<T> AuthorizedAsync<T>(
        Func<string, CancellationToken, Task<T>> call, CancellationToken ct)
    {
        var used = _access ?? throw new ApiException("unauthenticated", 401, "Сессия не открыта.");
        try
        {
            return await call(used, ct);
        }
        catch (ApiException ex) when (ex.StatusCode == 401)
        {
            var fresh = await RefreshOnceAsync(used, ct);
            return await call(fresh, ct);
        }
    }

    public async Task LogoutAsync(CancellationToken ct)
    {
        var refresh = _refresh;
        try
        {
            if (refresh is not null) await _api.LogoutAsync(refresh, ct);
        }
        catch (ApiException) { }
        finally
        {
            ClearLocal();
        }
    }

    public void ClearLocal()
    {
        _store.Clear();
        _access = null;
        _refresh = null;
        _current = null;
        Changed?.Invoke();
    }

    private async Task<string> RefreshOnceAsync(string usedAccess, CancellationToken ct)
    {
        await _refreshGate.WaitAsync(ct);
        try
        {
            if (_access is not null && _access != usedAccess) return _access;
            if (_refresh is null)
            {
                ClearLocal();
                throw new ApiException("refresh_token_invalid", 401, "Сессия недействительна.");
            }
            Session session;
            try
            {
                session = await _api.RefreshAsync(_refresh, ct);
            }
            catch (ApiException ex) when (ex.Code is "refresh_token_invalid" or "account_locked")
            {
                ClearLocal();
                throw;
            }
            Apply(session, _current?.Email);
            return session.AccessToken;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private SessionSnapshot Apply(Session session, string? email = null)
    {
        var owner = email ?? _current?.Email ?? "";
        // Новый refresh фиксируется на диске до того, как им разрешено пользоваться в памяти.
        _store.Save(new StoredSession(1, _baseUrl, owner, session.RefreshToken,
            session.RefreshExpiresAt));
        _access = session.AccessToken;
        _refresh = session.RefreshToken;
        _current = new SessionSnapshot(_baseUrl, owner, session.AccessToken,
            session.AccessExpiresAt);
        Changed?.Invoke();
        return _current;
    }

    private static void ValidateCredentials(string email, string password)
    {
        var trimmed = (email ?? "").Trim();
        if (trimmed.Length is 0 or > 254)
            throw new ApiException("bad_args", 0, "Проверьте email.");
        if ((password ?? "").Length is < 10 or > 1024)
            throw new ApiException("bad_args", 0, "Пароль должен быть от 10 до 1024 символов.");
    }
}
