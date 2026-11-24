using System.Net;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Profiles;
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class ProfileServiceTests
{
    private static readonly Uri Base = new("https://api.example/");
    private static readonly Guid DeviceId = Guid.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly Guid ServerId = Guid.Parse("33333333-3333-4333-8333-333333333333");

    private static HttpResponseMessage Session() => StubHandler.Json(HttpStatusCode.OK,
        """{"access_token":"a1","refresh_token":"r1","token_type":"Bearer","access_expires_at":"2026-11-24T10:05:00Z","refresh_expires_at":"2026-12-24T10:00:00Z"}""");

    private static string ServerJson(string availability = "available", bool measured = false) =>
        JsonSerializer.Serialize(new
        {
            id = ServerId, name = "ams-1", country_code = "NL", city = "Amsterdam",
            host = "203.0.113.1", port = 51820, mtu = 1420, latitude = 52.37, longitude = 4.89,
            availability,
            latency_ms = measured ? 24 : (int?)null,
            load = measured ? 0.4 : (double?)null,
            capacity_mbps = measured ? 1000 : (int?)null,
            provider = "demo", region = "eu-west",
        });

    private static string ProfileJson(string status = "active", string? revokedAt = null) =>
        JsonSerializer.Serialize(new
        {
            id = Guid.NewGuid(), device_id = DeviceId, server_id = ServerId,
            address_v4 = "10.66.0.2", status,
            issued_at = "2026-11-24T10:00:00Z",
            expires_at = "2026-12-24T10:00:00Z",
            overlap_valid_until = (string?)null,
            revoked_at = revokedAt,
        });

    private sealed record Env(StubHandler Handler, ApiClient Api, SessionService Session,
        ProfileService Profiles);

    private static async Task<Env> CreateAsync(TempDir dir, Func<HttpRequestMessage, int, HttpResponseMessage> respond)
    {
        var handler = new StubHandler((req, n) => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => Session(),
            _ => respond(req, n),
        });
        var api = new ApiClient(Base, handler);
        var session = new SessionService(api, Base, new SessionStore(dir.Path));
        await session.LoginAsync("a@b.c", "0123456789", default);
        return new Env(handler, api, session, new ProfileService(api, session));
    }

    [Fact]
    public async Task Catalog_keeps_nulls_and_availability_literal()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, (req, _) => req.RequestUri!.AbsolutePath == "/api/v1/servers"
            ? StubHandler.Json(HttpStatusCode.OK, $$"""{"servers":[{{ServerJson("unknown")}}]}""")
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        var servers = await env.Profiles.ListServersAsync(default);

        var s = Assert.Single(servers);
        Assert.Equal("unknown", s.Availability);
        Assert.Null(s.LatencyMs);
        Assert.Null(s.Load);
        Assert.Null(s.CapacityMbps);
    }

    [Fact]
    public async Task Issue_reuses_key_after_server_error_and_new_key_after_success()
    {
        using var dir = new TempDir();
        var issueCalls = 0;
        var env = await CreateAsync(dir, (req, _) =>
        {
            if (req.Method != HttpMethod.Post) return StubHandler.Json(HttpStatusCode.NotFound, "{}");
            issueCalls++;
            return issueCalls == 1
                ? StubHandler.Json(HttpStatusCode.InternalServerError,
                    """{"error":{"code":"internal","message":"m","request_id":"0000000000000003"}}""")
                : StubHandler.Json(HttpStatusCode.Created, ProfileJson());
        });

        await Assert.ThrowsAsync<ApiException>(() => env.Profiles.IssueAsync(DeviceId, ServerId, default));
        var first = await env.Profiles.IssueAsync(DeviceId, ServerId, default);
        var second = await env.Profiles.IssueAsync(DeviceId, ServerId, default);

        var keys = env.Handler.Requests.Where(r => r.Method == "POST" && r.Path.EndsWith("/profiles"))
            .Select(r => r.Idem).ToList();
        Assert.Equal(3, keys.Count);
        Assert.NotNull(keys[0]);
        Assert.Equal(keys[0], keys[1]);
        Assert.NotEqual(keys[1], keys[2]);
        Assert.Equal("active", first.Status);
        Assert.Equal("active", second.Status);
    }

    [Fact]
    public async Task Issue_drops_key_after_conflict()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, (req, _) => req.Method == HttpMethod.Post
            ? StubHandler.Json(HttpStatusCode.Conflict,
                """{"error":{"code":"conflict","message":"m","details":{"reason":"pool_exhausted"},"request_id":"0000000000000004"}}""")
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        await Assert.ThrowsAsync<ApiException>(() => env.Profiles.IssueAsync(DeviceId, ServerId, default));
        await Assert.ThrowsAsync<ApiException>(() => env.Profiles.IssueAsync(DeviceId, ServerId, default));

        var keys = env.Handler.Requests
            .Where(r => r.Method == "POST" && r.Path.EndsWith("/profiles"))
            .Select(r => r.Idem).ToList();
        Assert.Equal(2, keys.Count);
        Assert.NotEqual(keys[0], keys[1]);
    }

    [Fact]
    public async Task Issue_keeps_key_when_operation_is_in_progress()
    {
        using var dir = new TempDir();
        var calls = 0;
        var env = await CreateAsync(dir, (req, _) =>
        {
            calls++;
            return calls == 1
                ? StubHandler.Json(HttpStatusCode.Conflict,
                    """{"error":{"code":"idempotency_key_in_progress","message":"m","request_id":"0000000000000005"}}""")
                : StubHandler.Json(HttpStatusCode.Created, ProfileJson());
        });

        await Assert.ThrowsAsync<ApiException>(() => env.Profiles.IssueAsync(DeviceId, ServerId, default));
        await env.Profiles.IssueAsync(DeviceId, ServerId, default);

        var keys = env.Handler.Requests
            .Where(r => r.Method == "POST" && r.Path.EndsWith("/profiles"))
            .Select(r => r.Idem).ToList();
        Assert.Equal(2, keys.Count);
        Assert.Equal(keys[0], keys[1]);
    }

    [Fact]
    public async Task Profiles_list_shows_statuses_literally()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, (req, _) => req.RequestUri!.AbsolutePath.Contains("/profiles")
            ? StubHandler.Json(HttpStatusCode.OK,
                $$"""{"profiles":[{{ProfileJson("revoked", "2026-11-24T11:00:00Z")}},{{ProfileJson("superseded")}}]}""")
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        var profiles = await env.Profiles.ListAsync(DeviceId, default);

        Assert.Equal(new[] { "revoked", "superseded" }, profiles.Select(p => p.Status));
        Assert.Equal("2026-11-24T11:00:00Z", profiles[0].RevokedAt!.Value.ToUniversalTime()
            .ToString("yyyy-MM-ddTHH:mm:ssZ"));
    }

    [Fact]
    public async Task Revoke_conflict_reports_actual_status()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, (req, _) => req.Method == HttpMethod.Delete
            ? StubHandler.Json(HttpStatusCode.Conflict,
                """{"error":{"code":"conflict","message":"m","details":{"status":"revoked"},"request_id":"0000000000000006"}}""")
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        var ex = await Assert.ThrowsAsync<ApiException>(() => env.Profiles.RevokeAsync(DeviceId, ServerId, default));

        Assert.Equal("conflict", ex.Code);
        Assert.Contains("revoked", ex.Message);
        Assert.Equal("revoked", ex.DetailString("status"));
    }

    [Fact]
    public async Task Config_returns_text_and_uses_expected_path()
    {
        using var dir = new TempDir();
        const string config = "[Interface]\nAddress = 10.66.0.2/32\n";
        var env = await CreateAsync(dir, (req, _) => req.RequestUri!.AbsolutePath.EndsWith("/config")
            ? StubHandler.Text(HttpStatusCode.OK, config)
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        var text = await env.Profiles.FetchConfigAsync(DeviceId, ServerId, default);

        Assert.Equal(config, text);
        Assert.Contains(env.Handler.Requests, r => r.Path ==
            $"/api/v1/devices/{DeviceId}/profiles/{ServerId}/config");
    }
}
