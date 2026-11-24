using System.Net;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class SessionServiceTests
{
    private static readonly Uri Base = new("https://api.example/");
    private static readonly string MeJson =
        """{"user":{"id":"11111111-1111-4111-8111-111111111111","email":"a@b.c","display_name":null,"status":"active","locale":"ru","created_at":"2026-11-24T10:00:00Z"},"plan":null,"devices":{"live":0,"limit":0}}""";

    private static Session Session(string access, string refresh) => new(
        access, refresh, "Bearer",
        DateTimeOffset.Parse("2026-11-24T10:05:00Z"),
        DateTimeOffset.Parse("2026-12-24T10:00:00Z"));

    private static string ApiJson(Session s) => JsonSerializer.Serialize(new
    {
        access_token = s.AccessToken,
        refresh_token = s.RefreshToken,
        token_type = s.TokenType,
        access_expires_at = s.AccessExpiresAt,
        refresh_expires_at = s.RefreshExpiresAt,
    });

    [Fact]
    public async Task Authorized_call_refreshes_once_and_retries()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a1", "r1"))),
            "/api/v1/auth/refresh" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a2", "r2"))),
            "/api/v1/me" when req.Headers.Authorization!.Parameter == "a1" => MeUnauthorized(),
            "/api/v1/me" => SuccessMe(),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);
        await svc.LoginAsync("a@b.c", "0123456789", default);

        var me = await svc.AuthorizedAsync((t, c) => api.GetMeAsync(t, c), default);

        Assert.Equal("a@b.c", me.User.Email);
        Assert.Equal(1, handler.Requests.Count(r => r.Path == "/api/v1/auth/refresh"));
        Assert.Equal("r2", store.Load()!.RefreshToken);
        Assert.Equal(2, handler.Requests.Count(r => r.Path == "/api/v1/me"));
    }

    [Fact]
    public async Task Parallel_401_wait_for_one_refresh()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        var refreshCalls = 0;
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a1", "r1"))),
            "/api/v1/auth/refresh" => Interlocked.Increment(ref refreshCalls) == 1
                ? StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a2", "r2")))
                : Interlocked.Increment(ref refreshCalls) == 2
                    ? StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a3", "r3")))
                    : StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a4", "r4"))),
            "/api/v1/me" when req.Headers.Authorization!.Parameter == "a1" => MeUnauthorized(),
            "/api/v1/me" => SuccessMe(),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);
        await svc.LoginAsync("a@b.c", "0123456789", default);

        var results = await Task.WhenAll(Enumerable.Range(0, 3)
            .Select(_ => svc.AuthorizedAsync((t, c) => api.GetMeAsync(t, c), default)));

        Assert.All(results, m => Assert.Equal("a@b.c", m.User.Email));
        Assert.Equal(1, refreshCalls);
        Assert.Equal(1, handler.Requests.Count(r => r.Path == "/api/v1/auth/refresh"));
    }

    [Fact]
    public async Task Failed_refresh_clears_local_session()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a1", "r1"))),
            "/api/v1/me" => MeUnauthorized(),
            "/api/v1/auth/refresh" => StubHandler.Json(HttpStatusCode.Unauthorized,
                """{"error":{"code":"refresh_token_invalid","message":"Сессия недействительна","request_id":"0000000000000001"}}"""),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);
        await svc.LoginAsync("a@b.c", "0123456789", default);

        var ex = await Assert.ThrowsAsync<ApiException>(() =>
            svc.AuthorizedAsync((t, c) => api.GetMeAsync(t, c), default));

        Assert.Equal("refresh_token_invalid", ex.Code);
        Assert.Null(svc.Current);
        Assert.False(store.Exists);
    }

    [Fact]
    public async Task Logout_clears_locally_even_when_api_is_unreachable()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a1", "r1"))),
            "/api/v1/auth/logout" => throw new HttpRequestException("offline"),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);
        await svc.LoginAsync("a@b.c", "0123456789", default);

        await svc.LogoutAsync(default);

        Assert.Null(svc.Current);
        Assert.False(store.Exists);
    }

    [Fact]
    public async Task Corrupt_store_reports_message_and_keeps_file()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        File.WriteAllBytes(System.IO.Path.Combine(dir.Path, "session.dat"), new byte[] { 9, 9, 9 });
        using var api = new ApiClient(Base, new StubHandler(_ => StubHandler.Json(HttpStatusCode.OK, "{}")));
        var svc = new SessionService(api, Base, store);

        var restored = await svc.TryRestoreAsync(default);

        Assert.False(restored);
        Assert.Contains("Хранилище повреждено", svc.StartupError);
        Assert.True(store.Exists);
    }

    [Fact]
    public async Task Restore_refreshes_and_returns_signed_in_state()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        store.Save(new StoredSession(1, Base, "a@b.c", "r1",
            DateTimeOffset.Parse("2026-12-24T10:00:00Z")));
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/refresh" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a2", "r2"))),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);

        Assert.True(await svc.TryRestoreAsync(default));
        Assert.Equal("a@b.c", svc.Current!.Email);
        Assert.Equal("r2", store.Load()!.RefreshToken);
    }

    private static HttpResponseMessage MeUnauthorized() => StubHandler.Json(HttpStatusCode.Unauthorized,
        """{"error":{"code":"unauthenticated","message":"Требуется вход","request_id":"0000000000000002"}}""");

    private static HttpResponseMessage SuccessMe() => StubHandler.Json(HttpStatusCode.OK, MeJson);
}
