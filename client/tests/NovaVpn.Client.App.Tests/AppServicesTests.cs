using System.Net;
using System.Text.Json;
using NovaVpn.Client.App.Export;
using NovaVpn.Client.App.Host;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Storage;
using static NovaVpn.Client.App.Tests.StubHandler;

namespace NovaVpn.Client.App.Tests;

public sealed class AppServicesTests
{
    private static readonly Uri Base = new("https://api.example/");
    private static readonly Guid DeviceId = Guid.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly Guid ServerId = Guid.Parse("33333333-3333-4333-8333-333333333333");
    private const string Password = "0123456789";
    private const string Warning =
        "В файле приватный ключ. Это секрет; не пересылайте файл и не храните его в общих папках.";

    private const string SessionJson =
        """{"access_token":"a1","refresh_token":"r1","token_type":"Bearer","access_expires_at":"2026-11-24T10:05:00Z","refresh_expires_at":"2026-12-24T10:00:00Z"}""";

    private static readonly string MeJson = JsonSerializer.Serialize(new
    {
        user = new { id = Guid.NewGuid(), email = "a@b.c", display_name = (string?)null,
            status = "active", locale = "ru", created_at = "2026-11-24T10:00:00Z" },
        plan = new { slug = "internal-default", device_limit = 3, traffic_quota_bytes = (long?)null },
        devices = new { live = 1, limit = 3 },
    });

    private static string ServerJson() => JsonSerializer.Serialize(new
    {
        id = ServerId, name = "ams-1", country_code = "NL", city = "Amsterdam",
        host = "203.0.113.1", port = 51820, mtu = 1420, latitude = 52.37, longitude = 4.89,
        availability = "available", latency_ms = (int?)null, load = (double?)null,
        capacity_mbps = (int?)null, provider = "demo", region = "eu-west",
    });

    private static string ProfileJson(string status = "active") => JsonSerializer.Serialize(new
    {
        id = Guid.NewGuid(), device_id = DeviceId, server_id = ServerId, address_v4 = "10.66.0.2",
        status, issued_at = "2026-11-24T10:00:00Z", expires_at = "2026-12-24T10:00:00Z",
        overlap_valid_until = (string?)null, revoked_at = (string?)null,
    });

    private static string DeviceJson(string publicKey) => JsonSerializer.Serialize(new
    {
        id = DeviceId, public_key = publicKey, platform = "windows", name = "test-pc",
        created_at = "2026-11-24T10:00:00Z", last_seen_at = (string?)null, revoked_at = (string?)null,
    });

    private const string ConfigText =
        "[Interface]\nAddress = 10.66.0.2/32\nDNS = 10.66.0.1\nMTU = 1420\n\n[Peer]\n" +
        "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
        "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.1:51820\nPersistentKeepalive = 25\n";

    private sealed class FakePicker : IFileSavePicker
    {
        public string? NextPath { get; set; }
        public string? ReceivedWarning { get; private set; }
        public string? SuggestedName { get; private set; }
        public int Calls { get; private set; }

        public string? Ask(string suggestedFileName, string warning)
        {
            Calls++;
            SuggestedName = suggestedFileName;
            ReceivedWarning = warning;
            return NextPath;
        }
    }

    private sealed class Env : IAsyncDisposable
    {
        public Env(StubHandler handler)
        {
            Dir = new TempDir();
            Handler = handler;
            Services = new AppServices(Dir.Path, Picker, handler, TimeProvider.System,
                "test-pc", "120.0.0.0");
        }

        public TempDir Dir { get; }
        public StubHandler Handler { get; }
        public FakePicker Picker { get; } = new();
        public AppServices Services { get; }

        public async ValueTask DisposeAsync()
        {
            await Services.DisposeAsync();
            Dir.Dispose();
        }
    }

    private static async Task<Env> SignedInAsync(
        Func<HttpRequestMessage, string?, int, HttpResponseMessage> extra)
    {
        var env = new Env(new StubHandler((req, body, n) => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => Json(HttpStatusCode.OK, SessionJson),
            "/api/v1/me" => Json(HttpStatusCode.OK, MeJson),
            _ => extra(req, body, n),
        }));
        await env.Services.SetSettingsAsync(Base.ToString(), default);
        await env.Services.LoginAsync("a@b.c", Password, default);
        return env;
    }

    private static Func<HttpRequestMessage, string?, int, HttpResponseMessage> WithRegisteredDevice()
    {
        var gets = 0;
        string? publicKey = null;

        HttpResponseMessage Create(string? body)
        {
            using var doc = JsonDocument.Parse(body!);
            publicKey = doc.RootElement.GetProperty("public_key").GetString();
            return Json(HttpStatusCode.Created, DeviceJson(publicKey!));
        }

        return (req, body, _) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path == "/api/v1/devices" && req.Method == HttpMethod.Get)
                return Json(HttpStatusCode.OK, ++gets == 1
                    ? """{"devices":[]}"""
                    : $$"""{"devices":[{{DeviceJson(publicKey!)}}]}""");
            if (path == "/api/v1/devices" && req.Method == HttpMethod.Post) return Create(body);
            if (path == "/api/v1/servers")
                return Json(HttpStatusCode.OK, $$"""{"servers":[{{ServerJson()}}]}""");
            if (path == $"/api/v1/devices/{DeviceId}/profiles")
                return Json(HttpStatusCode.OK, $$"""{"profiles":[{{ProfileJson()}}]}""");
            if (path == $"/api/v1/devices/{DeviceId}/profiles/{ServerId}/config")
                return Text(HttpStatusCode.OK, ConfigText);
            return Json(HttpStatusCode.NotFound,
                """{"error":{"code":"not_found","message":"m","request_id":"0000000000000001"}}""");
        };
    }

    [Fact]
    public async Task First_launch_has_no_api_url_and_no_session()
    {
        await using var env = new Env(new StubHandler((_, _, _) =>
            Json(HttpStatusCode.InternalServerError, "{}")));

        var state = await env.Services.GetSessionStateAsync(default);

        Assert.False(state.SignedIn);
        Assert.Null(state.ApiBaseUrl);
        Assert.Null(env.Services.GetSettings().ApiBaseUrl);
        Assert.Null(state.StartupError);
    }

    [Fact]
    public async Task Settings_reject_invalid_origin_and_changes_while_signed_in()
    {
        await using var env = new Env(new StubHandler((req, _, _) => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => Json(HttpStatusCode.OK, SessionJson),
            "/api/v1/me" => Json(HttpStatusCode.OK, MeJson),
            _ => Json(HttpStatusCode.NotFound, "{}"),
        }));

        var insecure = await Assert.ThrowsAsync<ApiException>(() =>
            env.Services.SetSettingsAsync("http://example.com/", default));
        var withPath = await Assert.ThrowsAsync<ApiException>(() =>
            env.Services.SetSettingsAsync("https://api.example/v1", default));
        Assert.Equal("bad_args", insecure.Code);
        Assert.Equal("bad_args", withPath.Code);

        await env.Services.SetSettingsAsync(Base.ToString(), default);
        await env.Services.LoginAsync("a@b.c", Password, default);
        var change = await Assert.ThrowsAsync<ApiException>(() =>
            env.Services.SetSettingsAsync("https://other.example/", default));

        Assert.Equal("bad_args", change.Code);
        Assert.Contains("выйдите", change.Message);
        Assert.Equal(Base.ToString(), env.Services.GetSettings().ApiBaseUrl);
    }

    [Fact]
    public async Task Login_and_logout_manage_session_store()
    {
        await using var env = await SignedInAsync((_, _, _) => Json(HttpStatusCode.NotFound, "{}"));
        var store = new SessionStore(env.Dir.Path);

        var signedIn = await env.Services.GetSessionStateAsync(default);
        Assert.True(signedIn.SignedIn);
        Assert.Equal("a@b.c", signedIn.Email);
        Assert.True(store.Exists);

        await env.Services.LogoutAsync(default);

        var signedOut = await env.Services.GetSessionStateAsync(default);
        Assert.False(signedOut.SignedIn);
        Assert.False(store.Exists);
    }

    [Fact]
    public async Task Corrupt_session_store_is_reported_and_kept()
    {
        await using var env = new Env(new StubHandler((_, _, _) => Json(HttpStatusCode.NotFound, "{}")));
        await env.Services.SetSettingsAsync(Base.ToString(), default);
        File.WriteAllBytes(Path.Combine(env.Dir.Path, "session.dat"), new byte[] { 1, 2, 3 });

        await env.Services.InitializeAsync(default);

        var state = await env.Services.GetSessionStateAsync(default);
        Assert.False(state.SignedIn);
        Assert.Contains("Хранилище повреждено", state.StartupError);
        Assert.True(File.Exists(Path.Combine(env.Dir.Path, "session.dat")));
    }

    [Fact]
    public async Task Devices_list_auto_registers_current_device()
    {
        string? postedName = null;
        var inner = WithRegisteredDevice();
        await using var env = await SignedInAsync((req, body, n) =>
        {
            if (req.RequestUri!.AbsolutePath == "/api/v1/devices" && req.Method == HttpMethod.Post)
                postedName = JsonDocument.Parse(body!).RootElement.GetProperty("name").GetString();
            return inner(req, body, n);
        });

        var devices = await env.Services.ListDevicesAsync(default);

        Assert.Equal(DeviceId, devices.CurrentDeviceId);
        Assert.Single(devices.Devices);
        Assert.Equal("test-pc", postedName);
        Assert.Contains(env.Handler.Requests, r => r.Method == "POST" && r.IdempotencyKey is not null);
    }

    [Fact]
    public async Task Export_cancel_warns_and_writes_nothing()
    {
        await using var env = await SignedInAsync(WithRegisteredDevice());
        await env.Services.ListDevicesAsync(default);
        env.Picker.NextPath = null;

        var result = await env.Services.ExportProfileAsync(DeviceId, ServerId, default);

        Assert.True(result.Cancelled);
        Assert.False(result.Saved);
        Assert.Equal(Warning, env.Picker.ReceivedWarning);
        Assert.Equal("NovaVPN-ams-1.conf", env.Picker.SuggestedName);
    }

    [Fact]
    public async Task Export_writes_conf_with_key_and_keeps_text_out_of_result_and_log()
    {
        await using var env = await SignedInAsync(WithRegisteredDevice());
        await env.Services.ListDevicesAsync(default);
        var target = Path.Combine(env.Dir.Path, "out.conf");
        env.Picker.NextPath = target;

        var result = await env.Services.ExportProfileAsync(DeviceId, ServerId, default);

        Assert.True(result.Saved);
        Assert.False(result.Cancelled);
        Assert.Equal("out.conf", result.FileName);
        Assert.NotNull(result.SavedAt);
        var text = File.ReadAllText(target);
        Assert.StartsWith("[Interface]\nPrivateKey = ", text);
        Assert.EndsWith("PersistentKeepalive = 25\n", text);
        Assert.DoesNotContain("PrivateKey", JsonSerializer.Serialize(result));

        var logs = Directory.Exists(Path.Combine(env.Dir.Path, "logs"))
            ? string.Join("\n", Directory.GetFiles(Path.Combine(env.Dir.Path, "logs"))
                .Select(File.ReadAllText))
            : "";
        Assert.DoesNotContain("PrivateKey", logs);
        Assert.DoesNotContain(Password, logs);
        Assert.DoesNotContain("a@b.c", logs);
        Assert.DoesNotContain("eyJ", logs);
    }

    [Fact]
    public async Task Export_of_non_active_profile_is_conflict_and_never_opens_picker()
    {
        await using var env = await SignedInAsync((req, body, n) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path == "/api/v1/devices" && req.Method == HttpMethod.Get)
                return Json(HttpStatusCode.OK,
                    $$"""{"devices":[{{DeviceJson("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")}}]}""");
            if (path == "/api/v1/servers")
                return Json(HttpStatusCode.OK, $$"""{"servers":[{{ServerJson()}}]}""");
            if (path == $"/api/v1/devices/{DeviceId}/profiles")
                return Json(HttpStatusCode.OK, $$"""{"profiles":[{{ProfileJson("revoked")}}]}""");
            return Json(HttpStatusCode.NotFound, "{}");
        });
        env.Picker.NextPath = Path.Combine(env.Dir.Path, "never.conf");

        var ex = await Assert.ThrowsAsync<ApiException>(() =>
            env.Services.ExportProfileAsync(DeviceId, ServerId, default));

        Assert.Equal("conflict", ex.Code);
        Assert.Equal(0, env.Picker.Calls);
        Assert.False(File.Exists(Path.Combine(env.Dir.Path, "never.conf")));
        Assert.DoesNotContain(env.Handler.Requests, r => r.Path.EndsWith("/config"));
    }
}
