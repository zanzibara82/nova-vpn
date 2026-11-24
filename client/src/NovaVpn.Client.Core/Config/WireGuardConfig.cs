using System.Text;
using System.Text.RegularExpressions;
using NovaVpn.Client.Core.Devices;

namespace NovaVpn.Client.Core.Config;

public static partial class WireGuardConfig
{
    [GeneratedRegex(@"^([A-Za-z][A-Za-z0-9]*) = (.+)$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyValue();

    public static string Compose(string serverText, string privateKeyBase64, string expectedPublicKey)
    {
        if (string.IsNullOrEmpty(serverText))
            throw new ConfigException("Сервер вернул пустой конфиг.");
        if (serverText[0] == '\uFEFF')
            throw new ConfigException("Конфиг начинается с BOM.");
        if (serverText.Contains('\r') || serverText.Contains('\0'))
            throw new ConfigException("Конфиг содержит недопустимые символы.");
        if (!serverText.EndsWith('\n'))
            throw new ConfigException("Конфиг не заканчивается переводом строки.");

        DeviceKeyPair pair;
        try
        {
            pair = DeviceKeyPair.FromPrivate(privateKeyBase64);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw new ConfigException("Приватный ключ устройства не разобран.");
        }
        if (!string.Equals(pair.PublicKeyBase64, expectedPublicKey, StringComparison.Ordinal))
            throw new ConfigException("Публичный ключ пары не совпадает с публичным ключом устройства.");

        var lines = serverText[..^1].Split('\n');
        var output = new List<string>(lines.Length + 1);
        var interfaceCount = 0;
        var peerCount = 0;
        var section = "";

        foreach (var line in lines)
        {
            if (line.Length == 0)
            {
                output.Add(line);
                continue;
            }
            if (line == "[Interface]")
            {
                interfaceCount++;
                if (interfaceCount > 1 || peerCount > 0)
                    throw new ConfigException("Секция [Interface] повторяется или идёт после [Peer].");
                section = "interface";
                output.Add(line);
                output.Add("PrivateKey = " + pair.PrivateKeyBase64);
                continue;
            }
            if (line == "[Peer]")
            {
                peerCount++;
                if (peerCount > 1 || interfaceCount == 0)
                    throw new ConfigException("Секция [Peer] повторяется или идёт раньше [Interface].");
                section = "peer";
                output.Add(line);
                continue;
            }
            if (line.StartsWith('[') || line.EndsWith(']'))
                throw new ConfigException("Неизвестная секция конфига.");
            if (section.Length == 0)
                throw new ConfigException("Строка вне секции конфига.");

            var m = KeyValue().Match(line);
            if (!m.Success)
                throw new ConfigException("Строка конфига не в формате «Ключ = значение».");
            if (string.Equals(m.Groups[1].Value, "PrivateKey", StringComparison.OrdinalIgnoreCase))
                throw new ConfigException("Сервер уже прислал PrivateKey.");
            output.Add(line);
        }

        if (interfaceCount != 1 || peerCount != 1)
            throw new ConfigException("В конфиге должна быть ровно одна секция [Interface] и одна [Peer].");
        return string.Join('\n', output) + "\n";
    }
}
