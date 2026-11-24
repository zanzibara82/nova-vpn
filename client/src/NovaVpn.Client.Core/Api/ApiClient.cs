using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace NovaVpn.Client.Core.Api;

public interface IApiObserver
{
    void OnRequestCompleted(ApiCall call);
}

public sealed record ApiCall(string Method, string Path, int Status, string? RequestId, TimeSpan Duration);

public static class ApiExceptionFactory
{
    public static string CodeForStatus(int status) => status switch
    {
        401 => "unauthenticated",
        403 => "forbidden",
        404 => "not_found",
        409 => "conflict",
        429 => "rate_limited",
        _ => "internal",
    };
}

public sealed class ApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly IApiObserver? _observer;

    public ApiClient(Uri baseUrl, HttpMessageHandler? handler = null,
        TimeSpan? timeout = null, IApiObserver? observer = null)
    {
        var h = handler ?? CreateHandler();
        _http = new HttpClient(h, disposeHandler: handler is null)
        {
            BaseAddress = baseUrl,
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
        };
        _observer = observer;
    }

    internal static HttpClientHandler CreateHandler() => new() { AllowAutoRedirect = false };

    public Task<Session> RegisterAsync(string email, string password, CancellationToken ct) =>
        SendAsync<Session>(HttpMethod.Post, "api/v1/auth/register",
            new { email, password }, null, null, ct);

    public Task<Session> LoginAsync(string email, string password, CancellationToken ct) =>
        SendAsync<Session>(HttpMethod.Post, "api/v1/auth/login",
            new { email, password }, null, null, ct);

    public Task<Session> RefreshAsync(string refreshToken, CancellationToken ct) =>
        SendAsync<Session>(HttpMethod.Post, "api/v1/auth/refresh",
            new { refresh_token = refreshToken }, null, null, ct);

    public Task LogoutAsync(string refreshToken, CancellationToken ct) =>
        SendAsync<object>(HttpMethod.Post, "api/v1/auth/logout",
            new { refresh_token = refreshToken }, null, null, ct, noContent: true);

    public Task<MeView> GetMeAsync(string accessToken, CancellationToken ct) =>
        SendAsync<MeView>(HttpMethod.Get, "api/v1/me", null, accessToken, null, ct);

    public async Task<IReadOnlyList<DeviceView>> ListDevicesAsync(string accessToken, CancellationToken ct)
    {
        var list = await SendAsync<DeviceListWire>(HttpMethod.Get, "api/v1/devices", null, accessToken, null, ct);
        return list.Devices;
    }

    public Task<DeviceView> CreateDeviceAsync(string accessToken, DeviceCreate body,
        string idempotencyKey, CancellationToken ct) =>
        SendAsync<DeviceView>(HttpMethod.Post, "api/v1/devices", body, accessToken, idempotencyKey, ct);

    public Task DeleteDeviceAsync(string accessToken, Guid deviceId, CancellationToken ct) =>
        SendAsync<object>(HttpMethod.Delete, $"api/v1/devices/{deviceId}", null, accessToken, null, ct, noContent: true);

    public async Task<IReadOnlyList<ServerView>> ListServersAsync(string accessToken, CancellationToken ct)
    {
        var list = await SendAsync<ServerListWire>(HttpMethod.Get, "api/v1/servers", null, accessToken, null, ct);
        return list.Servers;
    }

    public async Task<IReadOnlyList<ProfileView>> ListProfilesAsync(string accessToken,
        Guid deviceId, CancellationToken ct)
    {
        var list = await SendAsync<ProfileListWire>(HttpMethod.Get,
            $"api/v1/devices/{deviceId}/profiles", null, accessToken, null, ct);
        return list.Profiles;
    }

    public Task<ProfileView> IssueProfileAsync(string accessToken, Guid deviceId, Guid serverId,
        string idempotencyKey, CancellationToken ct) =>
        SendAsync<ProfileView>(HttpMethod.Post, $"api/v1/devices/{deviceId}/profiles",
            new { server_id = serverId }, accessToken, idempotencyKey, ct);

    public Task RevokeProfileAsync(string accessToken, Guid deviceId, Guid serverId, CancellationToken ct) =>
        SendAsync<object>(HttpMethod.Delete, $"api/v1/devices/{deviceId}/profiles/{serverId}",
            null, accessToken, null, ct, noContent: true);

    public async Task<string> GetConfigTextAsync(string accessToken, Guid deviceId, Guid serverId,
        CancellationToken ct) =>
        await SendAsync<string>(HttpMethod.Get,
            $"api/v1/devices/{deviceId}/profiles/{serverId}/config", null, accessToken, null, ct);

    public void Dispose() => _http.Dispose();

    /// <summary>
    /// Тело JSON с точным media type <c>application/json</c>: <see cref="JsonContent"/>
    /// дописывает <c>; charset=utf-8</c>, а API сверяет заголовок посимвольно
    /// (<c>internal/httpx/json.go</c>) и на параметр charset отвечает 400 invalid_request.
    /// Живой E2E это и поймал: без сброса charset отвергались все POST'ы с телом.
    /// </summary>
    internal static JsonContent JsonBody(object payload)
    {
        var content = JsonContent.Create(payload, options: JsonDefaults.Options);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private async Task<T> SendAsync<T>(HttpMethod method, string path, object? body,
        string? accessToken, string? idempotencyKey, CancellationToken ct, bool noContent = false)
    {
        using var req = new HttpRequestMessage(method, path);
        if (accessToken is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (idempotencyKey is not null)
            req.Headers.TryAddWithoutValidation("Idempotency-Key", idempotencyKey);
        if (body is not null)
            req.Content = JsonBody(body);

        var started = Stopwatch.StartNew();
        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ApiException(ClientErrorCodes.Timeout, 0, "Истекло время ожидания ответа API.");
        }
        catch (HttpRequestException)
        {
            throw new ApiException(ClientErrorCodes.Network, 0, "Нет связи с API.");
        }

        using (resp)
        {
            var status = (int)resp.StatusCode;
            if (status is >= 300 and < 400)
            {
                _observer?.OnRequestCompleted(new ApiCall(method.Method, path, status, null, started.Elapsed));
                throw new ApiException(ClientErrorCodes.Network, status,
                    "API перенаправляет запросы; переадресация запрещена.");
            }
            if (status is >= 200 and < 300)
            {
                var requestId = RequestId(resp, null);
                _observer?.OnRequestCompleted(new ApiCall(method.Method, path, status, requestId, started.Elapsed));
                if (noContent || status == 204) return default!;
                var text = await resp.Content.ReadAsStringAsync(ct);
                if (typeof(T) == typeof(string)) return (T)(object)text;
                return JsonSerializer.Deserialize<T>(text, JsonDefaults.Options)
                    ?? throw new ApiException("internal", status, "Пустой ответ API.", requestId: requestId);
            }

            var raw = await resp.Content.ReadAsStringAsync(ct);
            var ex = ParseError(resp, raw, status);
            _observer?.OnRequestCompleted(new ApiCall(method.Method, path, status, ex.RequestId, started.Elapsed));
            throw ex;
        }
    }

    private static ApiException ParseError(HttpResponseMessage resp, string raw, int status)
    {
        string? code = null, message = null, requestId = null;
        JsonElement? details = null;
        try
        {
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.TryGetProperty("error", out var err))
            {
                if (err.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String) code = c.GetString();
                if (err.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String) message = m.GetString();
                if (err.TryGetProperty("request_id", out var r) && r.ValueKind == JsonValueKind.String) requestId = r.GetString();
                if (err.TryGetProperty("details", out var d)) details = d.Clone();
            }
        }
        catch (JsonException) { }

        var retryAfter = resp.Headers.RetryAfter?.Delta;
        return new ApiException(
            code ?? ApiExceptionFactory.CodeForStatus(status),
            status,
            message ?? status switch
            {
                401 => "Сессия недействительна.",
                403 => "Действие запрещено.",
                404 => "Не найдено.",
                409 => "Конфликт состояния.",
                429 => "Слишком часто.",
                _ => "Внутренняя ошибка.",
            },
            details,
            RequestId(resp, requestId),
            retryAfter);
    }

    private static string? RequestId(HttpResponseMessage resp, string? bodyValue) =>
        bodyValue ?? (resp.Headers.TryGetValues("X-Request-Id", out var v) ? v.FirstOrDefault() : null);

    private sealed record DeviceListWire(IReadOnlyList<DeviceView> Devices);
    private sealed record ServerListWire(IReadOnlyList<ServerView> Servers);
    private sealed record ProfileListWire(IReadOnlyList<ProfileView> Profiles);
}
