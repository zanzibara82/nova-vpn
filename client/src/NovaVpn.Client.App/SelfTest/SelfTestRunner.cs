using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using NovaVpn.Client.App.Export;
using NovaVpn.Client.App.Host;
using NovaVpn.Client.Core;

namespace NovaVpn.Client.App.SelfTest;

internal static class SelfTestRunner
{
    private const string ExpectedCsp =
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; " +
        "connect-src 'none'; base-uri 'none'; form-action 'none'";
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan BootTimeout = TimeSpan.FromSeconds(30);

    public static int Run()
    {
        var dataDir = Path.Combine(Path.GetTempPath(), "novavpn-selftest-" + Guid.NewGuid().ToString("N"));
        var code = 5;
        try
        {
            // AppServices реализует только IAsyncDisposable: используем явное
            // освобождение, форма закрывается раньше сервисов.
            var services = new AppServices(dataDir, new FileSavePicker());
            try
            {
                using (var form = new MainForm(services)
                       {
                           Silent = true,
                           ShowInTaskbar = false,
                           StartPosition = FormStartPosition.Manual,
                           Location = new Point(-32000, -32000),
                       })
                {
                    form.Shown += (_, _) => _ = VerifyAsync(form, value => code = value);
                    Application.Run(form);

                    // Отказ до Shown (например, нет WebView2 Runtime) не запускает
                    // VerifyAsync: пересматриваем причину после выхода из цикла.
                    if (code == 5 && form.StartupFailure is WebView2RuntimeNotFoundException)
                    {
                        Console.Error.WriteLine("selftest: WebView2 Runtime не установлен.");
                        code = 2;
                    }
                }
            }
            finally
            {
                services.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("selftest: " + ex.GetType().Name + ": " + ex.Message);
            code = 5;
        }
        finally
        {
            Cleanup(dataDir);
        }

        if (code == 0) Console.WriteLine("selftest: ok");
        return code;
    }

    private static async Task VerifyAsync(MainForm form, Action<int> setCode)
    {
        try
        {
            CoreWebView2 core;
            try
            {
                core = await form.Ready.Task.WaitAsync(StartupTimeout);
            }
            catch (TimeoutException)
            {
                Fail(setCode, form, 3, $"окно не подготовило WebView2 за {StartupTimeout.TotalSeconds:0} с.");
                return;
            }
            catch (WebView2RuntimeNotFoundException)
            {
                Fail(setCode, form, 2, "WebView2 Runtime не установлен.");
                return;
            }
            catch (Exception ex)
            {
                Fail(setCode, form, 5, "сбой запуска: " + ex.Message);
                return;
            }

            var deadline = DateTime.UtcNow + BootTimeout;
            var mode = "none";
            while (DateTime.UtcNow < deadline)
            {
                mode = await EvaluateStringAsync(core,
                    "window.__nova && window.__nova.booted === true ? window.__nova.mode : 'pending'");
                if (mode is "live" or "stub") break;
                await Task.Delay(250);
            }
            if (mode != "live")
            {
                Fail(setCode, form, 3, $"интерфейс не загрузился за {BootTimeout.TotalSeconds:0} с (режим: {mode}).");
                return;
            }

            var stateJson = await core.ExecuteScriptAsync(
                "JSON.stringify({" +
                "stub: !document.getElementById('stub-banner').hidden," +
                "authVisible: !document.getElementById('screen-auth').hidden," +
                "badge: document.getElementById('version-badge').textContent," +
                "csp: (document.querySelector('meta[http-equiv=\"Content-Security-Policy\"]') || {}).content || ''" +
                "})");
            using var outer = JsonDocument.Parse(stateJson);
            using var state = JsonDocument.Parse(outer.RootElement.GetString()!);
            var root = state.RootElement;
            if (root.GetProperty("stub").GetBoolean())
            {
                Fail(setCode, form, 5, "в живом режиме показан баннер заглушки.");
                return;
            }
            if (!root.GetProperty("authVisible").GetBoolean())
            {
                Fail(setCode, form, 5, "экран входа не показан при пустом профиле.");
                return;
            }
            if (!string.Equals(root.GetProperty("badge").GetString(), ClientVersion.Value, StringComparison.Ordinal))
            {
                Fail(setCode, form, 5, "версия в интерфейсе не совпадает с " + ClientVersion.Value + ".");
                return;
            }
            if (!string.Equals(root.GetProperty("csp").GetString(), ExpectedCsp, StringComparison.Ordinal))
            {
                Fail(setCode, form, 5, "CSP страницы отличается от ожидаемой.");
                return;
            }
            if (form.ConsoleErrors.Count > 0)
            {
                Fail(setCode, form, 4,
                    "ошибки в консоли страницы (" + form.ConsoleErrors.Count + "): " + form.ConsoleErrors[0]);
                return;
            }

            setCode(0);
            form.Close();
        }
        catch (Exception ex)
        {
            Fail(setCode, form, 5, "непойманный сбой: " + ex.GetType().Name + ": " + ex.Message);
        }
    }

    private static async Task<string> EvaluateStringAsync(CoreWebView2 core, string script)
    {
        var raw = await core.ExecuteScriptAsync(script);
        return JsonSerializer.Deserialize<string>(raw) ?? "";
    }

    private static void Fail(Action<int> setCode, MainForm form, int exitCode, string message)
    {
        Console.Error.WriteLine("selftest: " + message);
        setCode(exitCode);
        form.Close();
    }

    private static void Cleanup(string dataDir)
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                if (!Directory.Exists(dataDir)) return;
                Directory.Delete(dataDir, recursive: true);
                return;
            }
            catch (IOException) { Thread.Sleep(300); }
            catch (UnauthorizedAccessException) { Thread.Sleep(300); }
        }
        Console.Error.WriteLine("selftest: временный каталог не удалён: " + dataDir);
    }
}
