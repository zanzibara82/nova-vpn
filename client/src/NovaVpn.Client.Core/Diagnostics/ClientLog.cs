using System.Text;

namespace NovaVpn.Client.Core.Diagnostics;

public sealed class ClientLog
{
    private readonly string _dir;
    private readonly long _maxBytes;
    private readonly object _gate = new();

    public ClientLog(string directory, long maxBytes = 1_048_576)
    {
        _dir = directory;
        _maxBytes = maxBytes;
    }

    public void Write(string line)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(_dir);
            var path = Path.Combine(_dir, $"client-{DateTime.Now:yyyyMMdd}.log");
            var clean = line.Replace('\r', ' ').Replace('\n', ' ');
            var bytes = Encoding.UTF8.GetBytes(clean + Environment.NewLine);
            var current = File.Exists(path) ? new FileInfo(path).Length : 0;
            if (current + bytes.Length > _maxBytes) Rotate(path);
            using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            fs.Write(bytes);
            fs.Flush(true);
        }
    }

    private static void Rotate(string path)
    {
        var second = path + ".2";
        if (File.Exists(second)) File.Delete(second);
        if (File.Exists(path + ".1")) File.Move(path + ".1", second);
        if (File.Exists(path)) File.Move(path, path + ".1");
    }
}
