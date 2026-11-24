using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Diagnostics;

namespace NovaVpn.Client.App.Bridge;

public sealed record AppInfoView(string Version, string Platform, string WebView, string Mode);

public sealed record SettingsView(string? ApiBaseUrl, int WindowWidth, int WindowHeight);

public sealed record SessionStateView(bool SignedIn, string? Email, string? ApiBaseUrl, string? StartupError);

public sealed record DevicesView(IReadOnlyList<DeviceView> Devices, Guid? CurrentDeviceId);

public sealed record ExportResult(bool Saved, bool Cancelled, string? FileName, DateTimeOffset? SavedAt);

public sealed record DiagnosticsView(string Version, IReadOnlyList<DiagnosticEvent> Events);
