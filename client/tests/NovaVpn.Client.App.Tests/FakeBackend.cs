using NovaVpn.Client.App.Bridge;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Diagnostics;

namespace NovaVpn.Client.App.Tests;

internal class FakeBackend : IBridgeBackend
{
    public static readonly Guid DeviceId = Guid.Parse("22222222-2222-4222-8222-222222222222");
    public static readonly Guid ServerId = Guid.Parse("33333333-3333-4333-8333-333333333333");
    public DiagnosticRing Ring { get; } = new();
    public AppInfoView LastAppInfo { get; } = new("0.1.0-preview", "windows", "120.0.0", "preview");
    public bool ExportCancelled { get; set; }

    public Task<AppInfoView> GetAppInfoAsync(CancellationToken ct) => Task.FromResult(LastAppInfo);
    public SettingsView GetSettings() => new("https://api.example/", 900, 700);
    public Task<SettingsView> SetSettingsAsync(string apiBaseUrl, CancellationToken ct) =>
        Task.FromResult(new SettingsView(apiBaseUrl, 900, 700));
    public Task<SessionStateView> GetSessionStateAsync(CancellationToken ct) =>
        Task.FromResult(new SessionStateView(true, "a@b.c", "https://api.example/", null));

    public Task<MeView> GetAccountAsync(CancellationToken ct) =>
        Task.FromResult(Me("a@b.c"));

    public Task<MeView> LoginAsync(string email, string password, CancellationToken ct) =>
        Task.FromResult(Me(email));

    public Task<MeView> RegisterAsync(string email, string password, CancellationToken ct) =>
        Task.FromResult(Me(email));

    public Task LogoutAsync(CancellationToken ct) => Task.CompletedTask;

    public Task<DevicesView> ListDevicesAsync(CancellationToken ct) =>
        Task.FromResult(new DevicesView(new[] { Device() }, DeviceId));

    public Task<DeviceView> CreateDeviceAsync(string name, CancellationToken ct) => Task.FromResult(Device());
    public Task DeleteDeviceAsync(Guid deviceId, CancellationToken ct) => Task.CompletedTask;

    public Task<IReadOnlyList<ServerView>> ListServersAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<ServerView>>(new[] { Server() });

    public Task<IReadOnlyList<ProfileView>> ListProfilesAsync(Guid deviceId, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<ProfileView>>(new[] { Profile() });

    public virtual Task<ProfileView> IssueProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        Task.FromResult(Profile());

    public Task RevokeProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) => Task.CompletedTask;

    public Task<ExportResult> ExportProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        Task.FromResult(ExportCancelled
            ? new ExportResult(false, true, null, null)
            : new ExportResult(true, false, "NovaVPN-ams-1.conf", DateTimeOffset.Parse("2026-11-24T12:00:00Z")));

    public Task<DiagnosticsView> GetDiagnosticsAsync(CancellationToken ct) =>
        Task.FromResult(new DiagnosticsView("0.1.0-preview", Ring.Snapshot()));

    private static MeView Me(string email) => new(
        new UserView(Guid.NewGuid(), email, null, "active", "ru",
            DateTimeOffset.Parse("2026-11-24T10:00:00Z")),
        new PlanView("internal-default", 3, null),
        new DeviceUsage(1, 3));

    private static DeviceView Device() => new(DeviceId,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "windows", "pc",
        DateTimeOffset.Parse("2026-11-24T10:00:00Z"), null, null);

    private static ServerView Server() => new(ServerId, "ams-1", "NL", "Amsterdam",
        "203.0.113.1", 51820, 1420, 52.37, 4.89, "available", null, null, null, "demo", "eu-west");

    private static ProfileView Profile() => new(Guid.NewGuid(), DeviceId, ServerId, "10.66.0.2",
        "active", DateTimeOffset.Parse("2026-11-24T10:00:00Z"),
        DateTimeOffset.Parse("2026-12-24T10:00:00Z"), null, null);
}
