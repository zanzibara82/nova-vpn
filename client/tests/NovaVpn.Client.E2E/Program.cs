using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Config;
using NovaVpn.Client.Core.Devices;
using NovaVpn.Client.Core.Profiles;
using NovaVpn.Client.Core.Storage;

namespace NovaVpn.Client.E2E;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is ["prepare", var baseUrl, var adminEmail, var userEmail, var stateDir])
                return await PrepareAsync(new Uri(baseUrl), adminEmail, userEmail, stateDir);
            if (args is ["run", var url, var email, var serverId, var state, var outDir])
                return await RunAsync(new Uri(url), email, Guid.Parse(serverId), state, outDir);
            Console.Error.WriteLine(
                "usage: prepare <baseUrl> <adminEmail> <userEmail> <stateDir> | " +
                "run <baseUrl> <userEmail> <serverId> <stateDir> <outDir>");
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("E2E FAIL: " + ex.GetType().Name + ": " + ex.Message);
            return 1;
        }
    }

    private static async Task<int> PrepareAsync(Uri baseUrl, string adminEmail, string userEmail, string stateDir)
    {
        var adminPassword = ReadSecret("администратора");
        var userPassword = ReadSecret("пользователя");

        using var http = new HttpClient { BaseAddress = baseUrl, Timeout = TimeSpan.FromSeconds(30) };
        var token = await AdminLoginAsync(http, adminEmail, adminPassword);
        var suffix = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var serverId = await CreateServerAsync(http, token, "e2e-" + suffix);
        await SetOnlineAsync(http, token, serverId);
        Console.WriteLine("E2E_SERVER=" + serverId);

        Directory.CreateDirectory(stateDir);
        using var api = new ApiClient(baseUrl);
        var session = await api.RegisterAsync(userEmail, userPassword, CancellationToken.None);
        var me = await api.GetMeAsync(session.AccessToken, CancellationToken.None);
        Console.WriteLine("E2E_USER=" + me.User.Id);
        Console.WriteLine("E2E PREPARE OK");
        return 0;
    }

    private static async Task<string> AdminLoginAsync(HttpClient http, string email, string password)
    {
        using var body = JsonBody(new { email, password });
        using var response = await http.PostAsync("/api/v1/admin/login", body);
        var json = await ReadJsonAsync(response);
        return json.GetProperty("access_token").GetString()
               ?? throw new InvalidOperationException("admin login: в ответе нет access_token");
    }

    private static async Task<string> CreateServerAsync(HttpClient http, string token, string name)
    {
        var octet = DateTimeOffset.UtcNow.ToUnixTimeSeconds() % 40 + 100;
        var body = new
        {
            location = new
            {
                country_code = "NL",
                city = "Amsterdam",
                lat = "52.370216",
                lon = "4.895168",
                timezone = "Europe/Amsterdam",
            },
            name,
            advertised_host = "203.0.113.10",
            listen_port = 51820,
            public_key = DeviceKeyPair.Generate().PublicKeyBase64,
            address_pool_v4 = "10." + octet + ".0.0/24",
            mtu = 1420,
            keepalive_sec = 25,
            provider = "e2e",
            region = "e2e",
            reason = "клиентский E2E: временный сервер",
        };
        var json = await PostJsonAsync(http, "/api/v1/admin/servers", token, body);
        return json.GetProperty("id").GetString()
               ?? throw new InvalidOperationException("admin servers: в ответе нет id");
    }

    private static async Task SetOnlineAsync(HttpClient http, string token, string serverId)
    {
        var body = new { status = "online", reason = "клиентский E2E: сервер готов" };
        await PostJsonAsync(http, "/api/v1/admin/servers/" + serverId + "/maintenance", token, body);
    }

    private static async Task<JsonElement> PostJsonAsync(
        HttpClient http, string path, string? token, object payload)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonBody(payload),
        };
        if (token is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.SendAsync(request);
        return await ReadJsonAsync(response);
    }

    /// <summary>
    /// Тело JSON с точным media type <c>application/json</c>: API сверяет заголовок
    /// посимвольно, а <see cref="JsonContent"/> дописывает <c>; charset=utf-8</c> и
    /// получает 400 invalid_request.
    /// </summary>
    private static JsonContent JsonBody(object payload)
    {
        var content = JsonContent.Create(payload, options: JsonDefaults.Options);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                "admin: HTTP " + (int)response.StatusCode + " " + text);
        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.Clone();
    }

    private static string ReadSecret(string role)
    {
        var line = Console.In.ReadLine();
        if (string.IsNullOrEmpty(line))
            throw new InvalidOperationException("в stdin нет пароля " + role);
        return line;
    }

    private static async Task<int> RunAsync(
        Uri baseUrl, string email, Guid serverId, string stateDir, string outDir)
    {
        var password = ReadSecret("пользователя");
        Directory.CreateDirectory(stateDir);
        Directory.CreateDirectory(outDir);

        using var api = new ApiClient(baseUrl);
        var session = new SessionService(api, baseUrl, new SessionStore(stateDir));
        await session.LoginAsync(email, password, CancellationToken.None);

        var identityStore = new DeviceIdentityStore(stateDir);
        var devices = new DeviceService(api, session, identityStore, "e2e-pc");
        var device = await devices.EnsureRegisteredAsync(CancellationToken.None);
        Expect(device.Name == "e2e-pc", "имя устройства не e2e-pc: " + device.Name);

        var profiles = new ProfileService(api, session);
        var servers = await profiles.ListServersAsync(CancellationToken.None);
        Expect(servers.Any(s => s.Id == serverId), "сервер " + serverId + " не попал в каталог");

        var issued = await profiles.IssueAsync(device.Id, serverId, CancellationToken.None);
        Expect(issued.Status == "active", "профиль после выдачи в статусе " + issued.Status);

        var serverText = await profiles.FetchConfigAsync(device.Id, serverId, CancellationToken.None);
        var identity = identityStore.Get(DeviceIdentityStore.AccountKey(baseUrl, email));
        Expect(identity is not null, "локальная пара ключей устройства не найдена");
        // В DeviceIdentity поля называются PrivateKey/PublicKey, а не *Base64:
        // бриф писал имена по памяти о DeviceKeyPair, здесь берём реальный контракт.
        var composed = WireGuardConfig.Compose(serverText, identity!.PrivateKey, identity.PublicKey);
        Expect(composed.StartsWith("[Interface]\nPrivateKey = ", StringComparison.Ordinal),
            "PrivateKey не вставлен сразу после [Interface]");
        Expect(composed.Contains("Endpoint = 203.0.113.10:51820", StringComparison.Ordinal),
            "Endpoint не совпадает с адвертайзед-адресом сервера");

        var path = Path.Combine(outDir, ConfigExporter.DefaultFileName("e2e"));
        ConfigExporter.Write(path, composed);
        var bytes = await File.ReadAllBytesAsync(path);
        Expect(bytes.Length == Encoding.UTF8.GetByteCount(composed), "в файле лишние байты (BOM?)");
        Expect(bytes[0] == (byte)'[', "файл не начинается с [Interface]");
        Console.WriteLine("E2E_FILE=" + Path.GetFileName(path) + " bytes=" + bytes.Length);

        await profiles.RevokeAsync(device.Id, serverId, CancellationToken.None);
        var after = await profiles.ListAsync(device.Id, CancellationToken.None);
        Expect(after.Any(p => p.ServerId == serverId && p.Status == "revoked"),
            "отзыв не виден в списке профилей");

        var refused = false;
        try
        {
            await profiles.FetchConfigAsync(device.Id, serverId, CancellationToken.None);
        }
        catch (ApiException ex) when (ex.Code is "conflict" or "not_found" or "forbidden")
        {
            refused = true;
        }
        Expect(refused, "конфиг отозванного профиля всё ещё выдаётся");

        await devices.DeleteAsync(device.Id, CancellationToken.None);
        await session.LogoutAsync(CancellationToken.None);
        Console.WriteLine("E2E OK");
        return 0;
    }

    private static void Expect(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
