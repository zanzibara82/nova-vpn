using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using NovaVpn.Client.App.Bridge;
using NovaVpn.Client.Core;
using NovaVpn.Client.Core.Api;

namespace NovaVpn.Client.App.Host;

public sealed class MainForm : Form
{
    private const string Origin = "https://app.novavpn.local";
    private readonly AppServices _services;
    private readonly WebView2 _webView = new() { Dock = DockStyle.Fill };
    private readonly BridgeRouter _router;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<string> _consoleErrors = new();

    internal IReadOnlyList<string> ConsoleErrors => _consoleErrors;
    internal CoreWebView2? Core => _webView.CoreWebView2;
    internal TaskCompletionSource<CoreWebView2> Ready { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Exception? StartupFailure { get; private set; }

    // Свойство нужно самопроверке, а не конструктору форм: без атрибута
    // WinForms-анализатор требует код сериализации (WFO1000).
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    internal bool Silent { get; init; }

    public MainForm(AppServices services)
    {
        _services = services;
        _router = new BridgeRouter(services, services.Ring, services.Log);
        Text = $"NovaVPN {ClientVersion.Value}";
        Width = Math.Max(services.Settings.WindowWidth, 720);
        Height = Math.Max(services.Settings.WindowHeight, 600);
        MinimumSize = new Size(720, 600);
        StartPosition = FormStartPosition.CenterScreen;
        Controls.Add(_webView);
        Load += OnLoadAsync;
        FormClosing += OnFormClosing;
    }

    private async void OnLoadAsync(object? sender, EventArgs e)
    {
        try
        {
            await _services.InitializeAsync(_shutdown.Token);
            var uiDir = Path.Combine(AppContext.BaseDirectory, "ui");
            if (!File.Exists(Path.Combine(uiDir, "index.html")))
            {
                Fail("Не найдены файлы интерфейса (ui/index.html).");
                return;
            }

            var userData = Path.Combine(_services.DataDir, "webview");
            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: userData);
            await _webView.EnsureCoreWebView2Async(environment);
            var core = _webView.CoreWebView2;
            _services.WebViewVersion = CoreWebView2Environment.GetAvailableBrowserVersionString() ?? "неизвестна";

            core.Settings.IsWebMessageEnabled = true;
            core.Settings.AreHostObjectsAllowed = false;
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;

            core.SetVirtualHostNameToFolderMapping("app.novavpn.local", uiDir,
                CoreWebView2HostResourceAccessKind.DenyCors);
            core.NavigationStarting += OnNavigationStarting;
            core.NewWindowRequested += OnNewWindowRequested;
            core.WebMessageReceived += OnWebMessageReceived;
            await AttachConsoleCaptureAsync(core);
            core.Navigate(Origin + "/index.html");
            Ready.TrySetResult(core);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
            // Окно закрывают во время восстановления сессии: показывать нечего.
        }
        catch (WebView2RuntimeNotFoundException ex)
        {
            Fail(
                "Не найден WebView2 Runtime. Установите его и запустите NovaVPN снова.\n" +
                "https://developer.microsoft.com/microsoft-edge/webview2/",
                ex);
        }
        catch (ApiException ex)
        {
            Fail("Не удалось восстановить сессию: " + ex.Message, ex);
        }
        catch (IOException ex)
        {
            Fail("Не удалось прочитать данные NovaVPN: " + ex.Message, ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            Fail("Нет доступа к данным NovaVPN: " + ex.Message, ex);
        }
        catch (Exception ex)
        {
            Fail("Не удалось запустить NovaVPN: " + ex.Message, ex);
        }
    }

    private void Fail(string message, Exception? error = null)
    {
        StartupFailure = error ?? new InvalidOperationException(message);
        if (Silent)
        {
            Ready.TrySetException(StartupFailure);
            Console.Error.WriteLine("nova: " + message);
        }
        else
        {
            MessageBox.Show(message, "NovaVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        Close();
    }

    private void OnNavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (!e.Uri.StartsWith(Origin + "/", StringComparison.Ordinal))
            e.Cancel = true;
    }

    private void OnNewWindowRequested(object? sender, CoreWebView2NewWindowRequestedEventArgs e)
    {
        e.Handled = true;
        if (!Uri.TryCreate(e.Uri, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            return;
        try
        {
            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception)
        {
            // Внешний браузер недоступен; ссылка останется в справке текстом.
        }
    }

    private async void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        string json;
        try { json = e.WebMessageAsJson; }
        catch (InvalidOperationException) { return; }

        await _gate.WaitAsync();
        try
        {
            var response = await _router.HandleAsync(json, _shutdown.Token);
            _webView.CoreWebView2?.PostWebMessageAsJson(response);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
        {
            // Окно закрывается: ответить уже некому.
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task AttachConsoleCaptureAsync(CoreWebView2 core)
    {
        // В этой версии пакета нет события ConsoleMessageReceived:
        // консольные ошибки снимаются событиями DevTools-протокола.
        var runtime = core.GetDevToolsProtocolEventReceiver("Runtime.consoleAPICalled");
        runtime.DevToolsProtocolEventReceived += (_, e) =>
        {
            using var doc = JsonDocument.Parse(e.ParameterObjectAsJson);
            if (doc.RootElement.TryGetProperty("type", out var type) &&
                type.ValueKind == JsonValueKind.String && type.GetString() == "error")
                AddConsoleError(DescribeConsoleEvent(doc.RootElement));
        };
        var exceptions = core.GetDevToolsProtocolEventReceiver("Runtime.exceptionThrown");
        exceptions.DevToolsProtocolEventReceived += (_, e) =>
        {
            using var doc = JsonDocument.Parse(e.ParameterObjectAsJson);
            AddConsoleError(DescribeConsoleEvent(doc.RootElement));
        };
        await core.CallDevToolsProtocolMethodAsync("Runtime.enable", "{}");
    }

    private static string DescribeConsoleEvent(JsonElement root)
    {
        if (root.TryGetProperty("exceptionDetails", out var details) &&
            details.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String)
            return text.GetString()!;
        if (root.TryGetProperty("args", out var args) && args.ValueKind == JsonValueKind.Array)
        {
            var parts = new List<string>();
            foreach (var arg in args.EnumerateArray())
            {
                if (arg.TryGetProperty("value", out var value)) parts.Add(value.ToString());
                else if (arg.TryGetProperty("description", out var d) && d.ValueKind == JsonValueKind.String)
                    parts.Add(d.GetString()!);
            }
            if (parts.Count > 0) return string.Join(' ', parts);
        }
        return root.GetRawText();
    }

    private void AddConsoleError(string message)
    {
        var line = message.Length > 300 ? message[..300] : message;
        if (_consoleErrors.Count < 20) _consoleErrors.Add(line);
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        _shutdown.Cancel();
        var bounds = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;
        _services.SaveWindowSize(bounds.Width, bounds.Height);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _shutdown.Dispose();
            _gate.Dispose();
            _webView.Dispose();
        }
        base.Dispose(disposing);
    }
}
