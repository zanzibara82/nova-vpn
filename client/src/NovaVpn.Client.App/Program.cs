using NovaVpn.Client.App.Export;
using NovaVpn.Client.App.Host;
using NovaVpn.Client.App.SelfTest;

namespace NovaVpn.Client.App;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        // Самопроверка стоит до мьютекса: она не зависит от открытого экземпляра
        // и не показывает модальных окон.
        if (args.Contains("--selftest", StringComparer.Ordinal))
            return SelfTestRunner.Run();

        using var mutex = new Mutex(initiallyOwned: true, @"Local\NovaVpn.Client.SingleInstance",
            out var createdNew);
        if (!createdNew)
        {
            MessageBox.Show("NovaVPN уже запущен.", "NovaVPN",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }

        var dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NovaVPN");
        AppServices services;
        try
        {
            services = new AppServices(dataDir, new FileSavePicker());
        }
        catch (Exception ex)
        {
            MessageBox.Show("Не удалось подготовить каталог данных NovaVPN: " + ex.Message,
                "NovaVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 0;
        }

        // AppServices реализует только IAsyncDisposable, а точка входа WinForms синхронна:
        // освобождаем явно, в finally, не заводя второй синхронный Dispose.
        try
        {
            using var form = new MainForm(services);
            Application.Run(form);
        }
        finally
        {
            services.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        return 0;
    }
}
