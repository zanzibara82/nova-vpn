using System.Text;
using System.Text.Json;
using NovaVpn.Client.App.Bridge;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Diagnostics;
using NovaVpn.Client.Core.Storage;

namespace NovaVpn.Client.App.Tests;

public sealed class BridgeRouterTests
{
    private const string ProfileArgs =
        """{"device_id":"22222222-2222-4222-8222-222222222222","server_id":"33333333-3333-4333-8333-333333333333"}""";

    private static (BridgeRouter Router, FakeBackend Backend) Create()
    {
        var backend = new FakeBackend();
        return (new BridgeRouter(backend, backend.Ring), backend);
    }

    private static string Req(string command, string? args = null, string id = "r1") =>
        args is null
            ? $$"""{"id":"{{id}}","command":"{{command}}"}"""
            : $$"""{"id":"{{id}}","command":"{{command}}","args":{{args}}}""";

    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public async Task Whitelisted_command_returns_data_with_id()
    {
        var (router, _) = Create();

        var doc = Parse(await router.HandleAsync(Req("servers.list"), default));

        Assert.True(doc.GetProperty("ok").GetBoolean());
        Assert.Equal("r1", doc.GetProperty("id").GetString());
        Assert.Equal("available", doc.GetProperty("data")[0].GetProperty("availability").GetString());
    }

    [Fact]
    public async Task Unknown_command_is_rejected()
    {
        var (router, _) = Create();

        var doc = Parse(await router.HandleAsync(Req("devices.rotate"), default));

        Assert.False(doc.GetProperty("ok").GetBoolean());
        Assert.Equal("unknown_command", doc.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Malformed_json_and_deep_json_are_bad_args()
    {
        var (router, _) = Create();

        var malformed = Parse(await router.HandleAsync("{", default));
        var deep = Parse(await router.HandleAsync(
            """{"id":"x","command":"app.info","args":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}}}""", default));

        Assert.Equal("bad_args", malformed.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("bad_args", deep.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Oversized_message_is_bad_args()
    {
        var (router, _) = Create();
        var huge = new string('x', 70 * 1024);

        var doc = Parse(await router.HandleAsync(
            $$$"""{"id":"x","command":"device.create","args":{"name":"{{{huge}}}"}}""", default));

        Assert.Equal("bad_args", doc.GetProperty("error").GetProperty("code").GetString());
    }

    [Theory]
    [InlineData("devices.delete", "{}")]
    [InlineData("devices.delete", """{"device_id":"not-a-guid"}""")]
    [InlineData("profiles.issue", """{"device_id":"22222222-2222-4222-8222-222222222222"}""")]
    [InlineData("auth.login", """{"email":"a@b.c","password":"short"}""")]
    [InlineData("settings.set", """{"api_base_url":42}""")]
    [InlineData("devices.create", """{"name":""}""")]
    public async Task Invalid_args_are_rejected(string command, string args)
    {
        var (router, _) = Create();

        var doc = Parse(await router.HandleAsync(Req(command, args), default));

        Assert.Equal("bad_args", doc.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Api_error_keeps_code_and_request_id()
    {
        var failing = new ThrowingBackend
        {
            Failure = new ApiException("server_not_available", 409, "server says",
                requestId: "9a1b2c3d4e5f6071"),
        };
        var r = new BridgeRouter(failing, new DiagnosticRing());

        var doc = Parse(await r.HandleAsync(Req("profiles.issue",
            """{"device_id":"22222222-2222-4222-8222-222222222222","server_id":"33333333-3333-4333-8333-333333333333"}"""),
            default));

        Assert.Equal("server_not_available", doc.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("9a1b2c3d4e5f6071", doc.GetProperty("error").GetProperty("request_id").GetString());
        Assert.DoesNotContain("server says", doc.ToString());
    }

    [Fact]
    public async Task Export_cancel_is_a_result_not_an_error()
    {
        var (router, backend) = Create();
        backend.ExportCancelled = true;

        var doc = Parse(await router.HandleAsync(Req("profiles.export",
            """{"device_id":"22222222-2222-4222-8222-222222222222","server_id":"33333333-3333-4333-8333-333333333333"}"""),
            default));

        Assert.True(doc.GetProperty("ok").GetBoolean());
        Assert.True(doc.GetProperty("data").GetProperty("cancelled").GetBoolean());
        Assert.False(doc.GetProperty("data").GetProperty("saved").GetBoolean());
    }

    [Fact]
    public async Task All_responses_are_free_of_secret_markers()
    {
        var (router, _) = Create();
        var args = """{"device_id":"22222222-2222-4222-8222-222222222222","server_id":"33333333-3333-4333-8333-333333333333"}""";
        var calls = new[]
        {
            Req("app.info"), Req("settings.get"), Req("settings.set", """{"api_base_url":"https://api.example/"}"""),
            Req("session.state"), Req("account.get"),
            Req("auth.login", """{"email":"a@b.c","password":"0123456789"}"""),
            Req("auth.register", """{"email":"a@b.c","password":"0123456789"}"""),
            Req("auth.logout"), Req("devices.list"), Req("devices.create", """{"name":"pc"}"""),
            Req("devices.delete", args), Req("servers.list"), Req("profiles.list", args),
            Req("profiles.issue", args), Req("profiles.revoke", args), Req("profiles.export", args),
            Req("diagnostics.get"),
        };

        var responses = new List<string>();
        foreach (var call in calls) responses.Add(await router.HandleAsync(call, default));

        foreach (var json in responses)
        {
            Assert.DoesNotContain("eyJ", json);
            Assert.DoesNotContain("PrivateKey", json);
            Assert.DoesNotContain("private_key", json);
            Assert.DoesNotContain("refresh_token", json);
            Assert.DoesNotContain("access_token", json);
            Assert.DoesNotContain("password", json);
            Assert.DoesNotContain("Authorization", json);
        }
    }

    [Fact]
    public async Task Diagnostics_records_command_and_code()
    {
        var (router, backend) = Create();

        await router.HandleAsync(Req("app.info"), default);
        await router.HandleAsync(Req("nope"), default);

        var events = backend.Ring.Snapshot();
        Assert.Equal(2, events.Count);
        Assert.Equal(("app.info", "ok"), (events[0].Command, events[0].Code));
        Assert.Equal("unknown_command", events[1].Code);
    }

    [Fact]
    public async Task Corrupted_storage_is_reported_as_storage_corrupted()
    {
        var backend = new ThrowingBackend
        {
            Failure = new StorageCorruptedException(@"C:\data\session.bin", new InvalidDataException("dpapi")),
        };
        var ring = new DiagnosticRing();
        var router = new BridgeRouter(backend, ring);

        var json = await router.HandleAsync(Req("profiles.issue", ProfileArgs), default);
        var doc = Parse(json);

        Assert.False(doc.GetProperty("ok").GetBoolean());
        Assert.Equal(ClientErrorCodes.StorageCorrupted, doc.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("Хранилище повреждено или принадлежит другому пользователю. Войдите заново.",
            doc.GetProperty("error").GetProperty("message").GetString());
        Assert.Equal(JsonValueKind.Null, doc.GetProperty("error").GetProperty("request_id").ValueKind);
        Assert.DoesNotContain("session.bin", json);
        Assert.DoesNotContain("dpapi", json);

        var ev = Assert.Single(ring.Snapshot());
        Assert.Equal(("profiles.issue", ClientErrorCodes.StorageCorrupted), (ev.Command, ev.Code));
    }

    [Fact]
    public async Task Unexpected_exception_keeps_type_name_in_diagnostics_only()
    {
        var backend = new ThrowingBackend { Failure = new InvalidOperationException("boom") };
        var ring = new DiagnosticRing();
        var router = new BridgeRouter(backend, ring);

        var json = await router.HandleAsync(Req("profiles.issue", ProfileArgs), default);
        var doc = Parse(json);

        Assert.False(doc.GetProperty("ok").GetBoolean());
        Assert.Equal("internal", doc.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("Внутренняя ошибка клиента.", doc.GetProperty("error").GetProperty("message").GetString());
        Assert.DoesNotContain("boom", json);

        var ev = Assert.Single(ring.Snapshot());
        Assert.Equal("internal:InvalidOperationException", ev.Code);
    }

    [Fact]
    public async Task Early_rejections_reach_diagnostics_ring()
    {
        var (router, backend) = Create();
        var oversized = new string('x', 70 * 1024);

        var tooBig = Parse(await router.HandleAsync(
            $$$"""{"id":"x","command":"app.info","args":{"pad":"{{{oversized}}}"}}""", default));
        var notObject = Parse(await router.HandleAsync("\"not an object\"", default));
        var noId = Parse(await router.HandleAsync("""{"command":"app.info"}""", default));

        Assert.Equal("bad_args", tooBig.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("bad_args", notObject.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("bad_args", noId.GetProperty("error").GetProperty("code").GetString());

        var events = backend.Ring.Snapshot();
        Assert.Equal(3, events.Count);
        Assert.Equal(("oversized", "bad_args"), (events[0].Command, events[0].Code));
        Assert.Equal(("", "bad_args"), (events[1].Command, events[1].Code));
        Assert.Equal(("", "bad_args"), (events[2].Command, events[2].Code));
    }

    [Theory]
    [InlineData("   ")]
    [InlineData(" \t\r\n ")]
    public async Task Whitespace_only_device_name_is_bad_args(string name)
    {
        var (router, backend) = Create();

        var doc = Parse(await router.HandleAsync(
            Req("devices.create", JsonSerializer.Serialize(new { name })), default));

        Assert.False(doc.GetProperty("ok").GetBoolean());
        Assert.Equal("bad_args", doc.GetProperty("error").GetProperty("code").GetString());
        Assert.Contains("недопустимую длину", doc.GetProperty("error").GetProperty("message").GetString());
        Assert.Null(backend.LastDeviceName);
    }

    [Fact]
    public async Task Device_name_is_trimmed_before_backend_call()
    {
        var (router, backend) = Create();

        var doc = Parse(await router.HandleAsync(Req("devices.create", """{"name":"  pc  "}"""), default));

        Assert.True(doc.GetProperty("ok").GetBoolean());
        Assert.Equal("pc", backend.LastDeviceName);
    }

    [Fact]
    public async Task Message_of_exactly_max_bytes_is_accepted()
    {
        var (router, _) = Create();
        var prefix = "{\"id\":\"x\",\"command\":\"app.info\",\"args\":{\"pad\":\"";
        var suffix = "\"}}";
        var overhead = Encoding.UTF8.GetByteCount(prefix) + Encoding.UTF8.GetByteCount(suffix);
        var message = prefix + new string('a', BridgeRouter.MaxMessageBytes - overhead) + suffix;

        Assert.Equal(BridgeRouter.MaxMessageBytes, Encoding.UTF8.GetByteCount(message));

        var doc = Parse(await router.HandleAsync(message, default));

        Assert.True(doc.GetProperty("ok").GetBoolean());
        Assert.Equal("0.1.0-preview", doc.GetProperty("data").GetProperty("version").GetString());
    }

    [Fact]
    public async Task Multibyte_message_over_max_bytes_is_bad_args()
    {
        var (router, _) = Create();
        var prefix = "{\"id\":\"x\",\"command\":\"app.info\",\"args\":{\"pad\":\"";
        var suffix = "\"}}";
        var overhead = Encoding.UTF8.GetByteCount(prefix) + Encoding.UTF8.GetByteCount(suffix);
        const int chars = 40000; // кириллическая «а» занимает 2 байта в UTF-8
        var message = prefix + new string('а', chars) + suffix;

        Assert.Equal(chars * 2 + overhead, Encoding.UTF8.GetByteCount(message));
        Assert.Equal(chars + overhead, message.Length);
        Assert.True(message.Length < BridgeRouter.MaxMessageBytes);
        Assert.True(Encoding.UTF8.GetByteCount(message) > BridgeRouter.MaxMessageBytes);

        var doc = Parse(await router.HandleAsync(message, default));

        Assert.False(doc.GetProperty("ok").GetBoolean());
        Assert.Equal(ClientErrorCodes.BadArgs, doc.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Every_whitelisted_command_is_dispatched()
    {
        var (router, _) = Create();
        var calls = new (string Command, string? Args)[]
        {
            ("app.info", null), ("settings.get", null), ("settings.set", """{"api_base_url":"https://api.example/"}"""),
            ("session.state", null), ("account.get", null),
            ("auth.login", """{"email":"a@b.c","password":"0123456789"}"""),
            ("auth.register", """{"email":"a@b.c","password":"0123456789"}"""),
            ("auth.logout", null), ("devices.list", null), ("devices.create", """{"name":"pc"}"""),
            ("devices.delete", ProfileArgs), ("servers.list", null), ("profiles.list", ProfileArgs),
            ("profiles.issue", ProfileArgs), ("profiles.revoke", ProfileArgs), ("profiles.export", ProfileArgs),
            ("diagnostics.get", null),
        };

        Assert.Equal(17, calls.Length);
        foreach (var (command, args) in calls)
        {
            var doc = Parse(await router.HandleAsync(Req(command, args), default));
            Assert.True(doc.GetProperty("ok").GetBoolean(), $"команда {command} не диспатчится");
        }
    }

    private sealed class ThrowingBackend : FakeBackend
    {
        public Exception? Failure { get; init; }

        public override Task<ProfileView> IssueProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
            Failure is ApiException api
                ? Task.FromException<ProfileView>(api)
                : Failure is not null
                    ? Task.FromException<ProfileView>(Failure)
                    : base.IssueProfileAsync(deviceId, serverId, ct);
    }
}
