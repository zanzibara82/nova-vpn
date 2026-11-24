using NovaVpn.Client.App.Export;
using NovaVpn.Client.App.Host;

namespace NovaVpn.Client.App;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        using var mutex = new Mutex(initiallyOwned: true, @"Local\NovaVpn.Client.SingleInstance",
            out var createdNew);
        if (!createdNew)
        {
            MessageBox.Show("NovaVPN уже запущен.", "NovaVPN",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        var dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NovaVPN");
        // AppServices реализует только IAsyncDisposable, а точка входа WinForms синхронна:
        // освобождаем явно, в finally, не заводя второй синхронный Dispose.
        var services = new AppServices(dataDir, new FileSavePicker());
        try
        {
            using var form = new MainForm(services);
            Application.Run(form);
        }
        finally
        {
            services.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }
}
