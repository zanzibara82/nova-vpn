using System.Net;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Devices;
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class DeviceServiceTests
{
    private static readonly Uri Base = new("https://api.example/");
    private static readonly Guid UserId = Guid.Parse("11111111-1111-4111-8111-111111111111");

    private static HttpResponseMessage Session() => StubHandler.Json(HttpStatusCode.OK,
        """{"access_token":"a1","refresh_token":"r1","token_type":"Bearer","access_expires_at":"2026-11-24T10:05:00Z","refresh_expires_at":"2026-12-24T10:00:00Z"}""");

    private static string MeJson() => JsonSerializer.Serialize(new
    {
        user = new
        {
            id = UserId,
            email = "a@b.c",
            display_name = (string?)null,
            status = "active",
            locale = "ru",
            created_at = "2026-11-24T10:00:00Z",
        },
        plan = new { slug = "internal-default", device_limit = 3, traffic_quota_bytes = (long?)null },
        devices = new { live = 0, limit = 3 },
    });

    private static string DeviceJson(Guid id, string publicKey, string? revokedAt = null) =>
        JsonSerializer.Serialize(new
        {
            id,
            public_key = publicKey,
            platform = "windows",
            name = "pc",
            created_at = "2026-11-24T10:00:00Z",
            last_seen_at = (string?)null,
            revoked_at = revokedAt,
        });

    private static HttpResponseMessage List(params object[] devices) =>
        StubHandler.Json(HttpStatusCode.OK, JsonSerializer.Serialize(new { devices }));

    private static HttpResponseMessage Error(HttpStatusCode status, string code) =>
        StubHandler.Json(status, JsonSerializer.Serialize(new
        {
            error = new { code, message = "m", request_id = "0000000000000001" },
        }));

    private static string ReadBody(HttpRequestMessage req) =>
        req.Content is null ? "" : req.Content.ReadAsStringAsync().GetAwaiter().GetResult();

    private sealed record Env(StubHandler Handler, ApiClient Api, SessionService Session,
        DeviceIdentityStore Store, DeviceService Devices, string AccountKey);

    private static async Task<Env> CreateAsync(TempDir dir,
        Func<string, HttpResponseMessage> onPost,
        Func<HttpResponseMessage>? devicesResponse = null)
    {
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => Session(),
            "/api/v1/auth/refresh" => Session(),
            "/api/v1/me" => StubHandler.Json(HttpStatusCode.OK, MeJson()),
            "/api/v1/devices" when req.Method == HttpMethod.Post => onPost(ReadBody(req)),
            "/api/v1/devices" when req.Method == HttpMethod.Get => devicesResponse is null ? List() : devicesResponse(),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        var store = new SessionStore(dir.Path);
        var identities = new DeviceIdentityStore(dir.Path);
        var api = new ApiClient(Base, handler);
        var session = new SessionService(api, Base, store);
        await session.LoginAsync("a@b.c", "0123456789", default);
        var devices = new DeviceService(api, session, identities);
        return new Env(handler, api, session, identities, devices,
            DeviceIdentityStore.AccountKey(Base, "a@b.c"));
    }

    [Fact]
    public async Task First_registration_saves_pair_before_post_and_fills_device_id()
    {
        using var dir = new TempDir();
        Guid? createdId = null;
        string? postedKey = null;
        var env = await CreateAsync(dir, body =>
        {
            using var doc = JsonDocument.Parse(body);
            postedKey = doc.RootElement.GetProperty("public_key").GetString();
            createdId = Guid.NewGuid();
            return StubHandler.Json(HttpStatusCode.Created, DeviceJson(createdId.Value, postedKey!));
        });

        var device = await env.Devices.EnsureRegisteredAsync(default);

        Assert.Equal(createdId, device.Id);
        var stored = env.Store.Get(env.AccountKey)!;
        Assert.Equal(createdId, stored.DeviceId);
        Assert.Equal(postedKey, stored.PublicKey);
    }

    [Fact]
    public async Task Existing_live_device_is_reused_without_post()
    {
        using var dir = new TempDir();
        var pair = DeviceKeyPair.Generate();
        var liveId = Guid.NewGuid();
        var env = await CreateAsync(dir,
            _ => throw new InvalidOperationException("POST must not happen"),
            devicesResponse: () => List(new
            {
                id = liveId,
                public_key = pair.PublicKeyBase64,
                platform = "windows",
                name = "pc",
                created_at = "2026-11-24T10:00:00Z",
                last_seen_at = (string?)null,
                revoked_at = (string?)null,
            }));
        env.Store.Put(env.AccountKey, new DeviceIdentity(Base, "a@b.c", null,
            pair.PublicKeyBase64, pair.PrivateKeyBase64, "pc", DateTimeOffset.UtcNow));

        var device = await env.Devices.EnsureRegisteredAsync(default);

        Assert.Equal(liveId, device.Id);
        Assert.Equal(liveId, env.Store.Get(env.AccountKey)!.DeviceId);
        Assert.DoesNotContain(env.Handler.Requests,
            r => r.Method == "POST" && r.Path == "/api/v1/devices");
    }

    [Fact]
    public async Task Revoked_key_is_replaced_by_new_pair()
    {
        using var dir = new TempDir();
        var oldPair = DeviceKeyPair.Generate();
        string? postedKey = null;
        var env = await CreateAsync(dir, body =>
        {
            using var doc = JsonDocument.Parse(body);
            postedKey = doc.RootElement.GetProperty("public_key").GetString();
            return StubHandler.Json(HttpStatusCode.Created, DeviceJson(Guid.NewGuid(), postedKey!));
        }, devicesResponse: () => List(new
        {
            id = Guid.NewGuid(),
            public_key = oldPair.PublicKeyBase64,
            platform = "windows",
            name = "pc",
            created_at = "2026-11-24T10:00:00Z",
            last_seen_at = (string?)null,
            revoked_at = "2026-11-24T11:00:00Z",
        }));
        env.Store.Put(env.AccountKey, new DeviceIdentity(Base, "a@b.c", Guid.NewGuid(),
            oldPair.PublicKeyBase64, oldPair.PrivateKeyBase64, "pc", DateTimeOffset.UtcNow));

        await env.Devices.EnsureRegisteredAsync(default);

        Assert.NotNull(postedKey);
        Assert.NotEqual(oldPair.PublicKeyBase64, postedKey);
        Assert.Equal(postedKey, env.Store.Get(env.AccountKey)!.PublicKey);
    }

    [Fact]
    public async Task Duplicate_device_is_reconciled_with_live_list()
    {
        using var dir = new TempDir();
        string? postedKey = null;
        var deviceId = Guid.NewGuid();
        var env = await CreateAsync(dir, body =>
        {
            using var doc = JsonDocument.Parse(body);
            postedKey = doc.RootElement.GetProperty("public_key").GetString();
            return Error(HttpStatusCode.Conflict, "duplicate_device");
        }, devicesResponse: () => postedKey is null
            ? List()
            : List(new
            {
                id = deviceId,
                public_key = postedKey,
                platform = "windows",
                name = "pc",
                created_at = "2026-11-24T10:00:00Z",
                last_seen_at = (string?)null,
                revoked_at = (string?)null,
            }));

        var device = await env.Devices.EnsureRegisteredAsync(default);

        Assert.Equal(deviceId, device.Id);
    }

    [Fact]
    public async Task Limit_error_is_propagated()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, _ => Error(HttpStatusCode.Conflict, "device_limit_reached"));

        var ex = await Assert.ThrowsAsync<ApiException>(() => env.Devices.EnsureRegisteredAsync(default));

        Assert.Equal("device_limit_reached", ex.Code);
    }

    [Fact]
    public async Task Delete_removes_local_pair_and_treats_404_as_gone()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, _ => Error(HttpStatusCode.Conflict, "device_limit_reached"));
        var deviceId = Guid.NewGuid();
        env.Store.Put(env.AccountKey, new DeviceIdentity(Base, "a@b.c", deviceId,
            "pub", "priv", "pc", DateTimeOffset.UtcNow));

        await env.Devices.DeleteAsync(deviceId, default);

        Assert.Null(env.Store.Get(env.AccountKey));
    }

    [Fact]
    public async Task Idempotency_key_depends_on_public_key()
    {
        Assert.Equal(DeviceService.IdempotencyKeyFor("A"), DeviceService.IdempotencyKeyFor("A"));
        Assert.NotEqual(DeviceService.IdempotencyKeyFor("A"), DeviceService.IdempotencyKeyFor("B"));
    }
}
