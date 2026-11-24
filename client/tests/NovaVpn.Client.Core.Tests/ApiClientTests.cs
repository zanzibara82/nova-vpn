using System.Net;
using System.Text;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class ApiClientTests
{
    private static ApiClient Client(StubHandler handler) =>
        new(new Uri("https://api.example/"), handler);

    [Fact]
    public async Task Login_maps_error_envelope()
    {
        var handler = new StubHandler(_ => StubHandler.Json(HttpStatusCode.Unauthorized,
            """{"error":{"code":"invalid_credentials","message":"Неверный email или пароль","request_id":"9a1b2c3d4e5f6071"}}"""));
        using var api = Client(handler);

        var ex = await Assert.ThrowsAsync<ApiException>(() => api.LoginAsync("a@b.c", "0123456789", default));

        Assert.Equal("invalid_credentials", ex.Code);
        Assert.Equal(401, ex.StatusCode);
        Assert.Equal("9a1b2c3d4e5f6071", ex.RequestId);
        Assert.Equal("Неверный email или пароль", ex.Message);
    }

    [Fact]
    public async Task Register_parses_session()
    {
        var handler = new StubHandler(_ => StubHandler.Json(HttpStatusCode.Created,
            """{"access_token":"a","refresh_token":"r","token_type":"Bearer","access_expires_at":"2026-11-24T10:00:00Z","refresh_expires_at":"2026-12-24T10:00:00Z"}"""));
        using var api = Client(handler);

        var s = await api.RegisterAsync("a@b.c", "0123456789", default);

        Assert.Equal("a", s.AccessToken);
        Assert.Equal(DateTimeOffset.Parse("2026-12-24T10:00:00Z"), s.RefreshExpiresAt);
        Assert.Equal("/api/v1/auth/register", handler.Requests.Single().Path);
    }

    [Fact]
    public async Task Redirect_is_not_followed_and_becomes_network_error()
    {
        var handler = new StubHandler(_ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.Redirect);
            r.Headers.Location = new Uri("https://evil.example/");
            return r;
        });
        using var api = Client(handler);

        var ex = await Assert.ThrowsAsync<ApiException>(() => api.LoginAsync("a@b.c", "0123456789", default));

        Assert.Equal(ClientErrorCodes.Network, ex.Code);
        Assert.Single(handler.Requests);
        Assert.DoesNotContain("evil.example", handler.Requests[0].Path);
    }

    [Fact]
    public void Default_handler_disables_automatic_redirects()
    {
        Assert.False(ApiClient.CreateHandler().AllowAutoRedirect);
    }

    [Fact]
    public async Task Rate_limited_exposes_retry_after()
    {
        var handler = new StubHandler(_ =>
        {
            var r = StubHandler.Json((HttpStatusCode)429,
                """{"error":{"code":"rate_limited","message":"Слишком часто","request_id":"0000000000000001"}}""");
            r.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
            return r;
        });
        using var api = Client(handler);

        var ex = await Assert.ThrowsAsync<ApiException>(() => api.GetMeAsync("a", default));

        Assert.Equal("rate_limited", ex.Code);
        Assert.Equal(TimeSpan.FromSeconds(7), ex.RetryAfter);
    }

    [Fact]
    public async Task Nulls_are_kept_as_nulls()
    {
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/me" => StubHandler.Json(HttpStatusCode.OK,
                """{"user":{"id":"11111111-1111-4111-8111-111111111111","email":"a@b.c","display_name":null,"status":"active","locale":"ru","created_at":"2026-11-24T10:00:00Z"},"plan":null,"devices":{"live":0,"limit":0}}"""),
            "/api/v1/servers" => StubHandler.Json(HttpStatusCode.OK,
                """{"servers":[{"id":"22222222-2222-4222-8222-222222222222","name":"s","country_code":"DE","city":"Berlin","host":"203.0.113.1","port":51820,"mtu":1420,"latitude":52.52,"longitude":13.4,"availability":"unknown","latency_ms":null,"load":null,"capacity_mbps":null,"provider":"p","region":""}]}"""),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = Client(handler);

        var me = await api.GetMeAsync("a", default);
        var servers = await api.ListServersAsync("a", default);

        Assert.Null(me.Plan);
        Assert.Equal(0, me.Devices.Limit);
        Assert.Null(servers[0].LatencyMs);
        Assert.Null(servers[0].Load);
        Assert.Null(servers[0].CapacityMbps);
    }

    [Fact]
    public async Task Authenticated_calls_send_bearer_and_idempotency_key()
    {
        var handler = new StubHandler(_ => StubHandler.Json(HttpStatusCode.Created,
            """{"id":"33333333-3333-4333-8333-333333333333","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","platform":"windows","name":"pc","created_at":"2026-11-24T10:00:00Z","last_seen_at":null,"revoked_at":null}"""));
        using var api = Client(handler);

        await api.CreateDeviceAsync("acc", new DeviceCreate(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "windows", "pc"), "key-1", default);

        var r = handler.Requests.Single();
        Assert.Equal("Bearer acc", r.Auth);
        Assert.Equal("key-1", r.Idem);
    }

    [Fact]
    public async Task Config_is_returned_as_plain_text()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("[Interface]\nAddress = 10.0.0.2/32\n", Encoding.UTF8, "text/plain"),
        });
        using var api = Client(handler);

        var text = await api.GetConfigTextAsync("a", Guid.NewGuid(), Guid.NewGuid(), default);

        Assert.StartsWith("[Interface]", text);
    }

    [Fact]
    public void Base_lowercase_code_falls_back_by_status()
    {
        Assert.Equal("internal", ApiExceptionFactory.CodeForStatus(500));
        Assert.Equal("unauthenticated", ApiExceptionFactory.CodeForStatus(401));
        Assert.Equal("conflict", ApiExceptionFactory.CodeForStatus(409));
    }
}
