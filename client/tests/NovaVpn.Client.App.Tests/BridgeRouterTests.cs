using System.Text.Json;
using NovaVpn.Client.App.Bridge;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Diagnostics;

namespace NovaVpn.Client.App.Tests;

public sealed class BridgeRouterTests
{
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
