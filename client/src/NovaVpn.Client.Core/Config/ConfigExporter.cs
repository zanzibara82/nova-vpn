using System.Text;

namespace NovaVpn.Client.Core.Config;

public static class ConfigExporter
{
    public static string DefaultFileName(string serverName)
    {
        var cleaned = new string((serverName ?? "")
            .Where(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')
            .ToArray());
        if (cleaned.Length == 0 || cleaned.All(c => c == '.')) cleaned = "server";
        return $"NovaVPN-{cleaned}.conf";
    }

    public static void Write(string path, string text)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(text);
        fs.Write(bytes);
        fs.Flush(flushToDisk: true);
    }
}
