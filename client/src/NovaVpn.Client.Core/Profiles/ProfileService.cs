using System.Collections.Concurrent;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;

namespace NovaVpn.Client.Core.Profiles;

public sealed class ProfileService
{
    private readonly ApiClient _api;
    private readonly SessionService _session;
    private readonly ConcurrentDictionary<string, string> _issueKeys = new(StringComparer.Ordinal);

    public ProfileService(ApiClient api, SessionService session)
    {
        _api = api;
        _session = session;
    }

    public Task<IReadOnlyList<ServerView>> ListServersAsync(CancellationToken ct) =>
        _session.AuthorizedAsync((t, c) => _api.ListServersAsync(t, c), ct);

    public Task<IReadOnlyList<ProfileView>> ListAsync(Guid deviceId, CancellationToken ct) =>
        _session.AuthorizedAsync((t, c) => _api.ListProfilesAsync(t, deviceId, c), ct);

    public async Task<ProfileView> IssueAsync(Guid deviceId, Guid serverId, CancellationToken ct)
    {
        var intent = $"{deviceId:N}:{serverId:N}";
        var key = _issueKeys.GetOrAdd(intent, _ => Guid.NewGuid().ToString("N"));
        try
        {
            var profile = await _session.AuthorizedAsync(
                (t, c) => _api.IssueProfileAsync(t, deviceId, serverId, key, c), ct);
            _issueKeys.TryRemove(intent, out _);
            return profile;
        }
        catch (ApiException ex) when (!IsTransient(ex))
        {
            _issueKeys.TryRemove(intent, out _);
            throw;
        }
    }

    public async Task RevokeAsync(Guid deviceId, Guid serverId, CancellationToken ct)
    {
        try
        {
            // ApiClient.RevokeProfileAsync возвращает необобщённый Task, поэтому
            // AuthorizedAsync<T> оборачивает вызов в значение, чтобы вывести T.
            await _session.AuthorizedAsync(async (t, c) =>
            {
                await _api.RevokeProfileAsync(t, deviceId, serverId, c);
                return true;
            }, ct);
        }
        catch (ApiException ex) when (ex.Code == "conflict" && ex.DetailString("status") is { } status)
        {
            throw new ApiException("conflict", ex.StatusCode,
                $"Профиль уже в состоянии «{status}».", ex.Details, ex.RequestId, ex.RetryAfter);
        }
    }

    public Task<string> FetchConfigAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        _session.AuthorizedAsync((t, c) => _api.GetConfigTextAsync(t, deviceId, serverId, c), ct);

    private static bool IsTransient(ApiException ex) =>
        ex.Code is ClientErrorCodes.Network or ClientErrorCodes.Timeout or "idempotency_key_in_progress"
        || ex.StatusCode >= 500;
}
