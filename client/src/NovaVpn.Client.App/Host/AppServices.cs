using System.Text.Json;
using NovaVpn.Client.App.Bridge;
using NovaVpn.Client.App.Export;
using NovaVpn.Client.Core;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Config;
using NovaVpn.Client.Core.Devices;
using NovaVpn.Client.Core.Diagnostics;
using NovaVpn.Client.Core.Profiles;
using NovaVpn.Client.Core.Storage;

namespace NovaVpn.Client.App.Host;

public sealed class AppServices : IBridgeBackend, IAsyncDisposable
{
    public const string ExportWarning =
        "В файле приватный ключ. Это секрет; не пересылайте файл и не храните его в общих папках.";

    private readonly IFileSavePicker _picker;
    private readonly HttpMessageHandler? _apiHandler;
    private readonly TimeProvider _time;
    private readonly string _hostName;
    private readonly ClientLog _log;
    private readonly SettingsStore _settingsStore;
    private readonly SessionStore _sessionStore;
    private readonly DeviceIdentityStore _identityStore;
    private ApiClient? _api;
    private SessionService? _session;
    private DeviceService? _devices;
    private ProfileService? _profiles;

    public AppServices(string dataDir, IFileSavePicker picker)
        : this(dataDir, picker, null, TimeProvider.System, Environment.MachineName, "не запущен") { }

    internal AppServices(string dataDir, IFileSavePicker picker, HttpMessageHandler? apiHandler,
        TimeProvider? time, string hostName, string webViewVersion)
    {
        DataDir = dataDir;
        _picker = picker;
        _apiHandler = apiHandler;
        _time = time ?? TimeProvider.System;
        _hostName = hostName;
        WebViewVersion = webViewVersion;
        Directory.CreateDirectory(dataDir);
        _log = new ClientLog(Path.Combine(dataDir, "logs"));
        _settingsStore = new SettingsStore(dataDir);
        _sessionStore = new SessionStore(dataDir);
        _identityStore = new DeviceIdentityStore(dataDir);
        Settings = _settingsStore.Load();
    }

    public string DataDir { get; }
    public ClientSettings Settings { get; private set; }
    public string? StartupError { get; private set; }
    public string WebViewVersion { get; set; }
    public DiagnosticRing Ring { get; } = new();
    internal ClientLog Log => _log;

    public async Task InitializeAsync(CancellationToken ct)
    {
        StartupError = null;
        if (Settings.ApiBaseUrl is null) return;
        Build(Settings.ApiBaseUrl);
        try
        {
            await _session!.TryRestoreAsync(ct);
        }
        catch (ApiException ex) when (ex.Code is ClientErrorCodes.Network or ClientErrorCodes.Timeout)
        {
            StartupError = "Нет связи с API.";
        }
        StartupError = _session!.StartupError ?? StartupError;
    }

    public Task<AppInfoView> GetAppInfoAsync(CancellationToken ct) =>
        Task.FromResult(new AppInfoView(ClientVersion.Value, "windows", WebViewVersion, "preview"));

    public SettingsView GetSettings() =>
        new(Settings.ApiBaseUrl?.ToString(), Settings.WindowWidth, Settings.WindowHeight);

    public async Task<SettingsView> SetSettingsAsync(string apiBaseUrl, CancellationToken ct)
    {
        if (_session?.Current is not null)
            throw new ApiException(ClientErrorCodes.BadArgs, 0, "Сначала выйдите из аккаунта.");
        if (!ApiBaseUrl.TryParse(apiBaseUrl, out var url, out var error))
            throw new ApiException(ClientErrorCodes.BadArgs, 0, error);

        Settings = Settings with { ApiBaseUrl = url };
        _settingsStore.Save(Settings);
        Build(url);
        StartupError = null;
        return await Task.FromResult(GetSettings());
    }

    public Task<SessionStateView> GetSessionStateAsync(CancellationToken ct) =>
        Task.FromResult(new SessionStateView(
            _session?.Current is not null,
            _session?.Current?.Email,
            Settings.ApiBaseUrl?.ToString(),
            StartupError));

    public Task<MeView> GetAccountAsync(CancellationToken ct) =>
        RequireSession().GetMeAsync(ct);

    public async Task<MeView> LoginAsync(string email, string password, CancellationToken ct)
    {
        var session = RequireSession();
        await session.LoginAsync(email, password, ct);
        var me = await session.GetMeAsync(ct);
        StartupError = null;
        ResetDevices();
        return me;
    }

    public async Task<MeView> RegisterAsync(string email, string password, CancellationToken ct)
    {
        var session = RequireSession();
        await session.RegisterAsync(email, password, ct);
        var me = await session.GetMeAsync(ct);
        StartupError = null;
        ResetDevices();
        return me;
    }

    public async Task LogoutAsync(CancellationToken ct)
    {
        var session = _session;
        if (session is null) return;
        await session.LogoutAsync(ct);
        ResetDevices();
    }

    public async Task<DevicesView> ListDevicesAsync(CancellationToken ct)
    {
        var session = RequireSession();
        var devices = _devices!;
        if (devices.AutoCreateSuppressed)
        {
            var (existing, currentId) = await devices.ListReadOnlyAsync(ct);
            return new DevicesView(existing, currentId);
        }
        var current = await devices.EnsureRegisteredAsync(ct);
        var all = await session.AuthorizedAsync((t, c) => _api!.ListDevicesAsync(t, c), ct);
        return new DevicesView(all, current.Id);
    }

    public Task<DeviceView> CreateDeviceAsync(string name, CancellationToken ct) =>
        RequireDevices().CreateAsync(name, ct);

    public Task DeleteDeviceAsync(Guid deviceId, CancellationToken ct) =>
        RequireDevices().DeleteAsync(deviceId, ct);

    public Task<IReadOnlyList<ServerView>> ListServersAsync(CancellationToken ct) =>
        RequireProfiles().ListServersAsync(ct);

    public Task<IReadOnlyList<ProfileView>> ListProfilesAsync(Guid deviceId, CancellationToken ct) =>
        RequireProfiles().ListAsync(deviceId, ct);

    public Task<ProfileView> IssueProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        RequireProfiles().IssueAsync(deviceId, serverId, ct);

    public Task RevokeProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        RequireProfiles().RevokeAsync(deviceId, serverId, ct);

    public async Task<ExportResult> ExportProfileAsync(Guid deviceId, Guid serverId,
        CancellationToken ct)
    {
        var profiles = RequireProfiles();
        var identity = RequireDevices().CurrentIdentity;
        // Локальной личности может ещё не быть: «Список устройств» не вызывали. Тогда
        // состояние профиля — более точный ответ, чем «зарегистрируйте устройство»,
        // а совпадение устройства проверяется сразу же, если личность уже есть.
        if (identity is { } known && known.DeviceId != deviceId)
            throw new ApiException(ClientErrorCodes.BadArgs, 0,
                "Выбранное устройство не является текущим на этой установке.");

        var servers = await profiles.ListServersAsync(ct);
        var server = servers.FirstOrDefault(s => s.Id == serverId)
            ?? throw new ApiException("not_found", 404, "Сервер не найден.");
        var list = await profiles.ListAsync(deviceId, ct);
        var profile = list.FirstOrDefault(p => p.ServerId == serverId)
            ?? throw new ApiException("not_found", 404, "Профиль не выдан.");
        if (profile.Status != "active")
            throw new ApiException("conflict", 409, $"Профиль в состоянии «{profile.Status}».",
                StatusDetails(profile.Status));

        var current = identity
            ?? throw new ApiException(ClientErrorCodes.BadArgs, 0, "Сначала зарегистрируйте устройство.");
        var serverText = await profiles.FetchConfigAsync(deviceId, serverId, ct);
        var composed = WireGuardConfig.Compose(serverText, current.PrivateKey, current.PublicKey);
        var suggested = ConfigExporter.DefaultFileName(server.Name);
        var path = _picker.Ask(suggested, ExportWarning);
        if (path is null) return new ExportResult(false, true, null, null);

        ConfigExporter.Write(path, composed);
        return new ExportResult(true, false, Path.GetFileName(path), _time.GetUtcNow());
    }

    public Task<DiagnosticsView> GetDiagnosticsAsync(CancellationToken ct) =>
        Task.FromResult(new DiagnosticsView(ClientVersion.Value, Ring.Snapshot()));

    public void SaveWindowSize(int width, int height)
    {
        Settings = Settings with { WindowWidth = width, WindowHeight = height };
        try { _settingsStore.Save(Settings); }
        catch (IOException) { }
    }

    public ValueTask DisposeAsync()
    {
        _api?.Dispose();
        return ValueTask.CompletedTask;
    }

    private void Build(Uri baseUrl)
    {
        _api?.Dispose();
        _api = new ApiClient(baseUrl, _apiHandler, observer: new LogObserver(_log));
        _session = new SessionService(_api, baseUrl, _sessionStore, _time);
        ResetDevices();
    }

    private void ResetDevices()
    {
        _devices = _api is null || _session is null
            ? null
            : new DeviceService(_api, _session, _identityStore, _hostName);
        _profiles = _api is null || _session is null
            ? null
            : new ProfileService(_api, _session);
    }

    private SessionService RequireSession() =>
        _session ?? throw new ApiException(ClientErrorCodes.BadArgs, 0, "Сначала укажите адрес API.");

    private DeviceService RequireDevices()
    {
        RequireSession();
        return _devices ?? throw new ApiException("unauthenticated", 401, "Сессия не открыта.");
    }

    private ProfileService RequireProfiles()
    {
        RequireSession();
        return _profiles ?? throw new ApiException("unauthenticated", 401, "Сессия не открыта.");
    }

    private static JsonElement StatusDetails(string status)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(new { status }));
        return doc.RootElement.Clone();
    }

    private sealed class LogObserver(ClientLog log) : IApiObserver
    {
        public void OnRequestCompleted(ApiCall call)
        {
            // Сбой журнала не должен подменять результат вызова API.
            try
            {
                log.Write($"{DateTimeOffset.UtcNow:O} {call.Method} {call.Path} {call.Status} " +
                          $"{call.RequestId ?? "-"} {call.Duration.TotalMilliseconds:F0}ms");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}
