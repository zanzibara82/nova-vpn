namespace NovaVpn.Client.Core.Api;

public static class ApiBaseUrl
{
    public static bool TryParse(string? input, out Uri baseUrl, out string error)
    {
        baseUrl = null!;
        error = "";
        var raw = (input ?? "").Trim();
        if (raw.Length == 0)
        {
            error = "Укажите адрес API.";
            return false;
        }
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var u))
        {
            error = "Адрес API не разобран.";
            return false;
        }
        if (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp)
        {
            error = "Адрес API должен начинаться с https:// (http:// — только для localhost).";
            return false;
        }
        if (u.UserInfo.Length != 0 || u.Query.Length != 0 || u.Fragment.Length != 0)
        {
            error = "Адрес API — только схема, хост и порт.";
            return false;
        }
        if (u.AbsolutePath is not ("" or "/"))
        {
            error = "Адрес API не должен содержать путь.";
            return false;
        }
        if (u.Scheme == Uri.UriSchemeHttp && !IsLoopback(u))
        {
            error = "http:// разрешён только для 127.0.0.1, localhost или [::1].";
            return false;
        }
        baseUrl = new Uri(u.GetLeftPart(UriPartial.Authority) + "/");
        return true;
    }

    private static bool IsLoopback(Uri u) =>
        u.IsLoopback || string.Equals(u.Host, "localhost", StringComparison.OrdinalIgnoreCase);
}
