using NovaVpn.Client.Core.Api;

namespace NovaVpn.Client.App.Bridge;

public interface IBridgeBackend
{
    Task<AppInfoView> GetAppInfoAsync(CancellationToken ct);
    SettingsView GetSettings();
    Task<SettingsView> SetSettingsAsync(string apiBaseUrl, CancellationToken ct);
    Task<SessionStateView> GetSessionStateAsync(CancellationToken ct);
    Task<MeView> GetAccountAsync(CancellationToken ct);
    Task<MeView> LoginAsync(string email, string password, CancellationToken ct);
    Task<MeView> RegisterAsync(string email, string password, CancellationToken ct);
    Task LogoutAsync(CancellationToken ct);
    Task<DevicesView> ListDevicesAsync(CancellationToken ct);
    Task<DeviceView> CreateDeviceAsync(string name, CancellationToken ct);
    Task DeleteDeviceAsync(Guid deviceId, CancellationToken ct);
    Task<IReadOnlyList<ServerView>> ListServersAsync(CancellationToken ct);
    Task<IReadOnlyList<ProfileView>> ListProfilesAsync(Guid deviceId, CancellationToken ct);
    Task<ProfileView> IssueProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct);
    Task RevokeProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct);
    Task<ExportResult> ExportProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct);
    Task<DiagnosticsView> GetDiagnosticsAsync(CancellationToken ct);
}
