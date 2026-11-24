using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;

namespace NovaVpn.Client.Core.Devices;

public sealed class DeviceKeyPair
{
    private DeviceKeyPair(byte[] privateKey)
    {
        PrivateKeyBase64 = Convert.ToBase64String(privateKey);
        var pub = new X25519PrivateKeyParameters(privateKey, 0).GeneratePublicKey().GetEncoded();
        PublicKeyBase64 = Convert.ToBase64String(pub);
    }

    public string PrivateKeyBase64 { get; }
    public string PublicKeyBase64 { get; }

    public static DeviceKeyPair Generate()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return new DeviceKeyPair(key);
    }

    public static DeviceKeyPair FromPrivate(string base64)
    {
        var raw = Convert.FromBase64String(base64);
        if (raw.Length != 32) throw new ArgumentException("Приватный ключ должен быть 32 байта.", nameof(base64));
        return new DeviceKeyPair(raw);
    }

    public static string PublicFromPrivate(string privateKeyBase64) =>
        FromPrivate(privateKeyBase64).PublicKeyBase64;
}
