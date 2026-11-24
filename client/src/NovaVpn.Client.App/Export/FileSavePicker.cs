namespace NovaVpn.Client.App.Export;

public interface IFileSavePicker
{
    string? Ask(string suggestedFileName, string warning);
}

public sealed class FileSavePicker : IFileSavePicker
{
    public string? Ask(string suggestedFileName, string warning)
    {
        var confirmed = MessageBox.Show(warning, "NovaVPN",
            MessageBoxButtons.OKCancel, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (confirmed != DialogResult.OK) return null;

        using var dialog = new SaveFileDialog
        {
            Title = "Сохранить конфиг WireGuard",
            FileName = suggestedFileName,
            Filter = "WireGuard (*.conf)|*.conf|Все файлы (*.*)|*.*",
            DefaultExt = "conf",
            AddExtension = true,
            OverwritePrompt = true,
        };
        return dialog.ShowDialog() == DialogResult.OK ? dialog.FileName : null;
    }
}
