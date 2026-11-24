using System.Security.Cryptography;
using System.Text;

namespace NovaVpn.Client.Core.Storage;

public sealed class StorageCorruptedException : Exception
{
    public StorageCorruptedException(string file, Exception inner)
        : base("Хранилище повреждено или принадлежит другому пользователю. Войдите заново.", inner)
    {
        File = file;
    }

    public string File { get; }
}

public sealed class DpapiFile
{
    private readonly byte[] _entropy;

    public DpapiFile(string path, string entropy)
    {
        Path = path;
        _entropy = Encoding.UTF8.GetBytes(entropy);
    }

    public string Path { get; }
    public bool Exists => File.Exists(Path);

    public byte[]? Read()
    {
        if (!File.Exists(Path)) return null;
        var raw = File.ReadAllBytes(Path);
        try
        {
            // Клиент — Windows-приложение: DPAPI CurrentUser доступен только на Windows.
#pragma warning disable CA1416
            return ProtectedData.Unprotect(raw, _entropy, DataProtectionScope.CurrentUser);
#pragma warning restore CA1416
        }
        catch (CryptographicException ex)
        {
            throw new StorageCorruptedException(Path, ex);
        }
    }

    public void Write(byte[] plain)
    {
        var dir = System.IO.Path.GetDirectoryName(Path)!;
        Directory.CreateDirectory(dir);
        // Клиент — Windows-приложение: DPAPI CurrentUser доступен только на Windows.
#pragma warning disable CA1416
        var encrypted = ProtectedData.Protect(plain, _entropy, DataProtectionScope.CurrentUser);
#pragma warning restore CA1416
        var tmp = Path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(encrypted);
                fs.Flush(flushToDisk: true);
            }
            if (File.Exists(Path)) File.Replace(tmp, Path, destinationBackupFileName: null);
            else File.Move(tmp, Path);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    public void Delete()
    {
        if (File.Exists(Path)) File.Delete(Path);
    }
}
