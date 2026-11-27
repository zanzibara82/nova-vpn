# Цикл E-1: Windows-клиент — менеджер доступа и `.conf` — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Выпустить Windows-клиент NovaVPN 0.1.0-preview: вход и регистрация, регистрация устройства с локальной парой X25519, каталог серверов, выдача и отзыв профиля, сборка готового `.conf` для официального WireGuard и честный статус без собственного туннеля.

**Architecture:** Три проекта .NET 10: `NovaVpn.Client.Core` (HTTP-клиент, DPAPI-хранилище, сессия с single-flight refresh, X25519, сборка конфига), `NovaVpn.Client.App` (WinForms-хост с WebView2, мост `postMessage`, системный диалог сохранения) и тесты. UI — локальные HTML/CSS/JS из дизайн-системы, отдаются через виртуальный origin `https://app.novavpn.local/`; слушающего TCP-порта нет, `AddHostObjectToScript` не используется. Секреты (refresh, приватные ключи) — только DPAPI `CurrentUser`; access-токен — только в памяти; текст конфига не попадает в JS и журнал.

**Tech Stack:** .NET 10 (SDK 10.0.204), WinForms, Microsoft.Web.WebView2 1.0.4370.26, BouncyCastle.Cryptography 2.7.0, System.Security.Cryptography.ProtectedData 10.0.0, xUnit 2.9.3, System.Text.Json. Стенд E2E — существующий Docker dev-стенд (PostgreSQL 17, Redis 7, API через `make run-dev`).

**Spec:** `docs/superpowers/specs/2026-11-22-novavpn-windows-client-design.md`

## Global Constraints

- Клиент — менеджер доступа, а не туннель: ни одного состояния «подключено», «защищено», «туннель активен». После сохранения — «Конфиг сохранён. Подключение выполняет WireGuard; этот клиент туннелем не управляет».
- Никаких секретов, токенов, приватных ключей и паролей в исходниках, журналах, argv и отчётах. Пароль не сохраняется и не журналируется; журналируется `account_id` из `/me`, не email.
- Refresh-токен и приватные ключи — только DPAPI `CurrentUser` с энтропиями `NovaVPN/session/v1` и `NovaVPN/devices/v1`. Access-токен — только в памяти. Полный текст `.conf` не попадает в JS, журнал, буфер обмена и на экран.
- WebView2: виртуальный origin `https://app.novavpn.local/`, `DenyCors`, только `postMessage`, без `AddHostObjectToScript` и без локального HTTP-сервера.
- CSP ровно: `default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'`.
- Мост: белый список команд; размер сообщения ≤ 64 КиБ; глубина JSON ≤ 8; неизвестная команда — `unknown_command`; ошибка аргументов — `bad_args`; ответы без токенов, ключей, пароля, текста конфига и `Authorization`.
- Адрес API — только origin: `https://` с любым хостом, `http://` только для `127.0.0.1`, `localhost`, `[::1]`; путь, userinfo, query, fragment запрещены; хвостовой `/` нормализуется. Редиректы не выполняются: `3xx` — ошибка `network`.
- Версии закреплены: WebView2 1.0.4370.26, BouncyCastle 2.7.0, ProtectedData 10.0.0, xunit 2.9.3, xunit.runner.visualstudio 2.8.2, Microsoft.NET.Test.Sdk 17.14.1. `Directory.Packages.props` + `packages.lock.json`, CI — `dotnet restore --locked-mode`.
- Версия продукта `0.1.0-preview`, окно 900×700, минимум 720×600, тёмная и светлая темы по `prefers-color-scheme`, контраст AA, статусы текстом.
- Интерфейс и прикладные сообщения — по-русски; коды стабильны и не переводятся.
- Неизмеренные величины не выдумываются: `latency_ms = null` → «не измерялось», `load = null` → «не измерялось», `capacity_mbps = null` → «не заявлена», `plan = null` → «активного плана нет», `traffic_quota_bytes = null` → «без квоты».
- Без сети и без узлового агента: E2E проверяет клиентский путь до конфига, но не handshake.
- Ветка цикла — `cycle/e1-windows-access-manager` от `main`; коммиты локальные. Push, merge и удаление ветки — только отдельной командой заказчика.
- После каждого прогона удалять свои временные каталоги и файлы; dev-стенд возвращать в исходное состояние.
- TDD: тест пишется до кода, падение проверяется, затем минимальная реализация. Критерий задачи — свежий прогон с прочитанным выводом.

### Решения, принятые при написании плана

1. **Windows-джоба CI.** Спецификация §10.1 перечисляет `publish` в задаче 1. Публиковать нечего, пока нет `NovaVpn.Client.App`. Задача 1 добавляет `restore --locked-mode` и `test`; шаг `publish` добавляется задачей 8, когда проект появляется и собирается, и проверяется документной задачей. Поведение не теряется.
2. **Код `storage_corrupted`.** Спецификация §4.1 требует сообщение о повреждённом хранилище, но §5 такого кода не перечисляет. Вводится клиентский код `storage_corrupted`; UI показывает «Хранилище повреждено или принадлежит другому пользователю» и предлагает войти заново. Файл не удаляется.
3. **Автоматическая регистрация устройства.** §3.2.3 требует «после входа» сверить устройство. Регистрация выполняется обработчиком `devices.list`; ошибка (`device_limit_reached`, `forbidden`) возвращается как ошибка команды. После явного `devices.delete` автосоздание подавляется до следующего входа или явного `devices.create`.
4. **Idempotency-Key устройства.** Ключ детерминирован от публичного ключа: `SHA-256("device-create\n" + public_key)` в hex. Повтор после сетевого сбоя и после перезапуска идёт с тем же ключом; новая пара — новый ключ. Для профиля ключ создаётся на намерение и живёт в памяти до известного исхода (2xx/4xx).
5. **`settings.set` при открытой сессии.** Менять адрес API разрешено только после выхода; попытка при активной сессии — `bad_args` «Сначала выйдите из аккаунта». UI блокирует поле, пока сессия открыта.
6. **Скриншоты.** Заглушка моста включается только по `?stub=1` и только при отсутствии `window.chrome.webview`; на экране виден баннер «Демонстрационные данные (заглушка моста)». Это тестовый стенд UI, а не рабочее приложение.
7. **Документы — задача 12.** §8.6 требует обновлять документацию в задаче, меняющей поведение, а §10 ставит документы последней задачей цикла. Противоречие решается в пользу §10: страница клиента описывает собранные экраны и снятые кадры, поэтому до задачи 9 она была бы ложной. Внутри цикла задача 12 — не «поздняя» правка, а обязательная часть поставки; строки `not-run` пишутся по фактическим журналам прогонов, а не по планам.

## Структура файлов

```
client/
  NovaVpn.Client.sln
  Directory.Build.props
  Directory.Packages.props
  src/NovaVpn.Client.Core/
    ClientVersion.cs
    Api/{ApiBaseUrl.cs, ApiClient.cs, ApiException.cs, ApiModels.cs, JsonDefaults.cs}
    Auth/SessionService.cs
    Storage/{DpapiFile.cs, SessionStore.cs, DeviceIdentityStore.cs, SettingsStore.cs}
    Devices/{DeviceKeyPair.cs, DeviceService.cs, DeviceIdentity.cs}
    Profiles/ProfileService.cs
    Config/{WireGuardConfig.cs, ConfigExporter.cs, ConfigException.cs}
    Diagnostics/{ClientLog.cs, DiagnosticRing.cs}
  src/NovaVpn.Client.App/
    NovaVpn.Client.App.csproj
    Program.cs
    Host/{MainForm.cs, AppServices.cs}
    Bridge/{BridgeRouter.cs, BridgeContracts.cs, IBridgeBackend.cs}
    Export/{FileSavePicker.cs}
    SelfTest/SelfTestRunner.cs
  tests/NovaVpn.Client.Core.Tests/
  tests/NovaVpn.Client.App.Tests/
  tests/NovaVpn.Client.E2E/
  ui/{index.html, app.css, app.js, help.html, fonts/}
  scripts/{serve-ui.mjs, e2e.sh}
  dist/                       (игнорируется git)
```

---

### Task 1: Каркас решения, централизованные версии, lock-файлы, Windows-джоба CI

**Files:**
- Create: `client/NovaVpn.Client.sln`, `client/Directory.Build.props`, `client/Directory.Packages.props`
- Create: `client/src/NovaVpn.Client.Core/NovaVpn.Client.Core.csproj`, `client/src/NovaVpn.Client.Core/ClientVersion.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/NovaVpn.Client.Core.Tests.csproj`, `client/tests/NovaVpn.Client.Core.Tests/ClientVersionTests.cs`
- Modify: `.gitignore`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: `NovaVpn.Client.Core.ClientVersion.Value` (string, `"0.1.0-preview"`); solution path `client/NovaVpn.Client.sln`; central versions for all later tasks.

- [ ] **Step 1: Создать ветку цикла, если работа идёт в основном дереве**

```bash
cd /c/Users/obogr/Desktop/AI/vpn
git switch -c cycle/e1-windows-access-manager
```

Если используется отдельный worktree SDD, ветку уже создал контроллер; шаг пропускается.

- [ ] **Step 2: Создать решение и проекты**

```bash
dotnet new sln -n NovaVpn.Client -o client
dotnet new classlib -n NovaVpn.Client.Core -o client/src/NovaVpn.Client.Core -f net10.0
dotnet new xunit -n NovaVpn.Client.Core.Tests -o client/tests/NovaVpn.Client.Core.Tests -f net10.0
dotnet sln client/NovaVpn.Client.sln add client/src/NovaVpn.Client.Core/NovaVpn.Client.Core.csproj
dotnet sln client/NovaVpn.Client.sln add client/tests/NovaVpn.Client.Core.Tests/NovaVpn.Client.Core.Tests.csproj
dotnet add client/tests/NovaVpn.Client.Core.Tests/NovaVpn.Client.Core.Tests.csproj reference client/src/NovaVpn.Client.Core/NovaVpn.Client.Core.csproj
rm client/src/NovaVpn.Client.Core/Class1.cs client/tests/NovaVpn.Client.Core.Tests/UnitTest1.cs
```

- [ ] **Step 3: Записать общие свойства и центральные версии**

`client/Directory.Build.props`:

```xml
<Project>
  <PropertyGroup>
    <Version>0.1.0-preview</Version>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <Deterministic>true</Deterministic>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
</Project>
```

`client/Directory.Packages.props`:

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Microsoft.NET.Test.Sdk" Version="17.14.1" />
    <PackageVersion Include="xunit" Version="2.9.3" />
    <PackageVersion Include="xunit.runner.visualstudio" Version="2.8.2" />
    <PackageVersion Include="Microsoft.Web.WebView2" Version="1.0.4370.26" />
    <PackageVersion Include="BouncyCastle.Cryptography" Version="2.7.0" />
    <PackageVersion Include="System.Security.Cryptography.ProtectedData" Version="10.0.0" />
  </ItemGroup>
</Project>
```

`client/src/NovaVpn.Client.Core/NovaVpn.Client.Core.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <RootNamespace>NovaVpn.Client.Core</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="BouncyCastle.Cryptography" />
    <PackageReference Include="System.Security.Cryptography.ProtectedData" />
  </ItemGroup>
</Project>
```

`client/tests/NovaVpn.Client.Core.Tests/NovaVpn.Client.Core.Tests.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" />
    <PackageReference Include="xunit" />
    <PackageReference Include="xunit.runner.visualstudio">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
    </PackageReference>
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="../../src/NovaVpn.Client.Core/NovaVpn.Client.Core.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 4: Написать падающий тест версии**

`client/tests/NovaVpn.Client.Core.Tests/ClientVersionTests.cs`:

```csharp
namespace NovaVpn.Client.Core.Tests;

public sealed class ClientVersionTests
{
    [Fact]
    public void Version_is_preview()
    {
        Assert.Equal("0.1.0-preview", ClientVersion.Value);
    }
}
```

- [ ] **Step 5: Убедиться, что тест не собирается**

Run: `dotnet test client/NovaVpn.Client.sln -c Debug`
Expected: ошибка компиляции `CS0103: Имя "ClientVersion" не существует в текущем контексте`.

- [ ] **Step 6: Добавить константу**

`client/src/NovaVpn.Client.Core/ClientVersion.cs`:

```csharp
namespace NovaVpn.Client.Core;

public static class ClientVersion
{
    public const string Value = "0.1.0-preview";
}
```

- [ ] **Step 7: Прогнать тест и зафиксировать lock-файлы**

```bash
dotnet test client/NovaVpn.Client.sln -c Debug
dotnet restore client/NovaVpn.Client.sln --force-evaluate
```

Expected: `Passed! - Failed: 0, Passed: 1`; рядом с каждым `.csproj` появился `packages.lock.json`. Повторный `dotnet restore client/NovaVpn.Client.sln --locked-mode` завершается кодом 0.

- [ ] **Step 8: Добавить клиентские каталоги в `.gitignore`**

В конец `.gitignore`:

```gitignore
client/**/bin/
client/**/obj/
client/**/TestResults/
client/**/*.user
client/.vs/
client/dist/
```

- [ ] **Step 9: Добавить Windows-джобу CI**

В `.github/workflows/ci.yml` после джобы `unit` (имя джобы сохранить в стиле файла):

```yaml
  windows-client:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 10.0.x
      - name: Restore (locked)
        run: dotnet restore client/NovaVpn.Client.sln --locked-mode
      - name: Test
        run: dotnet test client/NovaVpn.Client.sln -c Release --no-restore
```

`publish` добавляется задачей 8 вместе с окном приложения, когда проект уже собирается; `--selftest` в CI не запускается (в CI нет WebView2 Runtime и интерактивной сессии) и остаётся `not-run`.

- [ ] **Step 10: Проверить YAML и локальные ворота**

```bash
make actionlint
dotnet test client/NovaVpn.Client.sln -c Release
git status --short
```

Expected: `actionlint` — 0; тесты — `Failed: 0`; в статусе только новые клиентские файлы и правки `.gitignore`/CI.

- [ ] **Step 11: Коммит**

```bash
git add client .gitignore .github/workflows/ci.yml
git commit -m "feat(client): каркас .NET-решения с закреплёнными версиями и Windows-джобой"
```

---

### Task 2: Core HTTP-клиент — адрес API, конверт ошибки, модели, запрет редиректов, журнал

**Files:**
- Create: `client/src/NovaVpn.Client.Core/Api/ApiBaseUrl.cs`
- Create: `client/src/NovaVpn.Client.Core/Api/ApiException.cs`
- Create: `client/src/NovaVpn.Client.Core/Api/ApiModels.cs`
- Create: `client/src/NovaVpn.Client.Core/Api/JsonDefaults.cs`
- Create: `client/src/NovaVpn.Client.Core/Api/ApiClient.cs`
- Create: `client/src/NovaVpn.Client.Core/Diagnostics/ClientLog.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/ApiBaseUrlTests.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/ApiClientTests.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/Support/StubHandler.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/ClientLogTests.cs`
- Modify: `client/src/NovaVpn.Client.Core/NovaVpn.Client.Core.csproj` (InternalsVisibleTo)

**Interfaces:**
- Consumes: `ClientVersion.Value`.
- Produces:
  - `ApiBaseUrl.TryParse(string? input, out Uri baseUrl, out string error)` — нормализованный origin с хвостовым `/`.
  - `ApiException(string Code, int StatusCode, string Message, JsonElement? Details, string? RequestId, TimeSpan? RetryAfter)`.
  - `ApiClient(Uri baseUrl, HttpMessageHandler? handler = null, TimeSpan? timeout = null, IApiObserver? observer = null)` с методами:
    - `RegisterAsync(email, password, ct)` / `LoginAsync(email, password, ct)` → `Session`
    - `RefreshAsync(refreshToken, ct)` → `Session`; `LogoutAsync(refreshToken, ct)` → `Task`
    - `GetMeAsync(accessToken, ct)` → `MeView`
    - `ListDevicesAsync(accessToken, ct)` → `IReadOnlyList<DeviceView>`
    - `CreateDeviceAsync(accessToken, DeviceCreate body, string idempotencyKey, ct)` → `DeviceView`
    - `DeleteDeviceAsync(accessToken, Guid deviceId, ct)` → `Task`
    - `ListServersAsync(accessToken, ct)` → `IReadOnlyList<ServerView>`
    - `ListProfilesAsync(accessToken, Guid deviceId, ct)` → `IReadOnlyList<ProfileView>`
    - `IssueProfileAsync(accessToken, Guid deviceId, Guid serverId, string idempotencyKey, ct)` → `ProfileView`
    - `RevokeProfileAsync(accessToken, Guid deviceId, Guid serverId, ct)` → `Task`
    - `GetConfigTextAsync(accessToken, Guid deviceId, Guid serverId, ct)` → `string`
  - DTO: `Session`, `MeView`, `UserView`, `PlanView`, `DeviceUsage`, `DeviceView`, `DeviceCreate`, `ServerView`, `ProfileView`.
  - `ClientErrorCodes` с константами `Network`, `Timeout`, `BadArgs`, `UnknownCommand`, `StorageCorrupted`.
  - `JsonDefaults.Options` — snake_case, регистронезависимые имена, `MaxDepth = 8`.
  - `IApiObserver.OnRequestCompleted(ApiCall call)`; `ApiCall(string Method, string Path, int Status, string? RequestId, TimeSpan Duration)`.
  - `ClientLog(string directory, long maxBytes = 1_048_576)` с `Write(string line)`, ротация `client-YYYYMMDD.log` → `.1` → `.2`.

- [ ] **Step 1: Написать падающие тесты адреса API**

`client/tests/NovaVpn.Client.Core.Tests/ApiBaseUrlTests.cs`:

```csharp
using NovaVpn.Client.Core.Api;

namespace NovaVpn.Client.Core.Tests;

public sealed class ApiBaseUrlTests
{
    [Theory]
    [InlineData("https://api.novavpn.example", "https://api.novavpn.example/")]
    [InlineData("https://api.novavpn.example/", "https://api.novavpn.example/")]
    [InlineData("https://api.novavpn.example:8443/", "https://api.novavpn.example:8443/")]
    [InlineData("  http://127.0.0.1:8080  ", "http://127.0.0.1:8080/")]
    [InlineData("http://localhost:8080", "http://localhost:8080/")]
    [InlineData("http://[::1]:8080", "http://[::1]:8080/")]
    public void Accepts_origin_and_normalizes_slash(string input, string expected)
    {
        Assert.True(ApiBaseUrl.TryParse(input, out var uri, out var error), error);
        Assert.Equal(expected, uri.ToString());
    }

    [Theory]
    [InlineData("http://api.novavpn.example")]
    [InlineData("ftp://api.novavpn.example")]
    [InlineData("https://user:pass@api.novavpn.example")]
    [InlineData("https://api.novavpn.example/api")]
    [InlineData("https://api.novavpn.example/?x=1")]
    [InlineData("https://api.novavpn.example/#frag")]
    [InlineData("not a url")]
    [InlineData("")]
    public void Rejects_non_origin_or_insecure(string input)
    {
        Assert.False(ApiBaseUrl.TryParse(input, out _, out var error));
        Assert.NotEmpty(error);
    }
}
```

- [ ] **Step 2: Запустить и увидеть падение**

Run: `dotnet test client/NovaVpn.Client.sln --filter ApiBaseUrlTests`
Expected: ошибка компиляции `ApiBaseUrl`/`Api` не существует.

- [ ] **Step 3: Реализовать `ApiBaseUrl`**

`client/src/NovaVpn.Client.Core/Api/ApiBaseUrl.cs`:

```csharp
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
```

- [ ] **Step 4: Добавить DTO, JSON-настройки и исключение**

`client/src/NovaVpn.Client.Core/Api/JsonDefaults.cs`:

```csharp
using System.Text.Json;

namespace NovaVpn.Client.Core.Api;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
        MaxDepth = 8,
    };
}
```

`client/src/NovaVpn.Client.Core/Api/ApiModels.cs`:

```csharp
namespace NovaVpn.Client.Core.Api;

public sealed record Session(
    string AccessToken,
    string RefreshToken,
    string TokenType,
    DateTimeOffset AccessExpiresAt,
    DateTimeOffset RefreshExpiresAt);

public sealed record UserView(
    Guid Id,
    string Email,
    string? DisplayName,
    string Status,
    string Locale,
    DateTimeOffset CreatedAt);

public sealed record PlanView(string Slug, int DeviceLimit, long? TrafficQuotaBytes);

public sealed record DeviceUsage(int Live, int Limit);

public sealed record MeView(UserView User, PlanView? Plan, DeviceUsage Devices);

public sealed record DeviceView(
    Guid Id,
    string PublicKey,
    string Platform,
    string Name,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastSeenAt,
    DateTimeOffset? RevokedAt);

public sealed record DeviceCreate(string PublicKey, string Platform, string Name);

public sealed record ServerView(
    Guid Id,
    string Name,
    string CountryCode,
    string City,
    string Host,
    int Port,
    int Mtu,
    double Latitude,
    double Longitude,
    string Availability,
    int? LatencyMs,
    double? Load,
    int? CapacityMbps,
    string Provider,
    string Region);

public sealed record ProfileView(
    Guid Id,
    Guid DeviceId,
    Guid ServerId,
    string AddressV4,
    string Status,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? OverlapValidUntil,
    DateTimeOffset? RevokedAt);
```

`client/src/NovaVpn.Client.Core/Api/ApiException.cs`:

```csharp
using System.Text.Json;

namespace NovaVpn.Client.Core.Api;

public static class ClientErrorCodes
{
    public const string Network = "network";
    public const string Timeout = "timeout";
    public const string BadArgs = "bad_args";
    public const string UnknownCommand = "unknown_command";
    public const string StorageCorrupted = "storage_corrupted";
}

public sealed class ApiException : Exception
{
    public ApiException(string code, int statusCode, string message,
        JsonElement? details = null, string? requestId = null, TimeSpan? retryAfter = null)
        : base(message)
    {
        Code = code;
        StatusCode = statusCode;
        Details = details;
        RequestId = requestId;
        RetryAfter = retryAfter;
    }

    public string Code { get; }
    public int StatusCode { get; }
    public JsonElement? Details { get; }
    public string? RequestId { get; }
    public TimeSpan? RetryAfter { get; }

    public string? DetailString(string name) =>
        Details is { } d && d.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;
}
```

- [ ] **Step 5: Написать падающие тесты клиента**

`client/tests/NovaVpn.Client.Core.Tests/Support/StubHandler.cs`:

```csharp
using System.Net;
using System.Text;

namespace NovaVpn.Client.Core.Tests.Support;

internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, int, HttpResponseMessage> _respond;
    private int _count;

    public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : this((r, _) => respond(r)) { }

    public StubHandler(Func<HttpRequestMessage, int, HttpResponseMessage> respond) => _respond = respond;

    public List<(string Method, string Path, string? Auth, string? Idem)> Requests { get; } = new();

    public static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Requests.Add((
            request.Method.Method,
            request.RequestUri!.PathAndQuery,
            request.Headers.Authorization?.ToString(),
            request.Headers.TryGetValues("Idempotency-Key", out var v) ? v.Single() : null));
        return Task.FromResult(_respond(request, Requests.Count));
    }
}
```

`client/tests/NovaVpn.Client.Core.Tests/ApiClientTests.cs`:

```csharp
using System.Net;
using System.Text;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class ApiClientTests
{
    private static ApiClient Client(StubHandler handler) =>
        new(new Uri("https://api.example/"), handler);

    [Fact]
    public async Task Login_maps_error_envelope()
    {
        var handler = new StubHandler(_ => StubHandler.Json(HttpStatusCode.Unauthorized,
            """{"error":{"code":"invalid_credentials","message":"Неверный email или пароль","request_id":"9a1b2c3d4e5f6071"}}"""));
        using var api = Client(handler);

        var ex = await Assert.ThrowsAsync<ApiException>(() => api.LoginAsync("a@b.c", "0123456789", default));

        Assert.Equal("invalid_credentials", ex.Code);
        Assert.Equal(401, ex.StatusCode);
        Assert.Equal("9a1b2c3d4e5f6071", ex.RequestId);
        Assert.Equal("Неверный email или пароль", ex.Message);
    }

    [Fact]
    public async Task Register_parses_session()
    {
        var handler = new StubHandler(_ => StubHandler.Json(HttpStatusCode.Created,
            """{"access_token":"a","refresh_token":"r","token_type":"Bearer","access_expires_at":"2026-11-24T10:00:00Z","refresh_expires_at":"2026-12-24T10:00:00Z"}"""));
        using var api = Client(handler);

        var s = await api.RegisterAsync("a@b.c", "0123456789", default);

        Assert.Equal("a", s.AccessToken);
        Assert.Equal(DateTimeOffset.Parse("2026-12-24T10:00:00Z"), s.RefreshExpiresAt);
        Assert.Equal("/api/v1/auth/register", handler.Requests.Single().Path);
    }

    [Fact]
    public async Task Redirect_is_not_followed_and_becomes_network_error()
    {
        var handler = new StubHandler(_ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.Redirect);
            r.Headers.Location = new Uri("https://evil.example/");
            return r;
        });
        using var api = Client(handler);

        var ex = await Assert.ThrowsAsync<ApiException>(() => api.LoginAsync("a@b.c", "0123456789", default));

        Assert.Equal(ClientErrorCodes.Network, ex.Code);
        Assert.Single(handler.Requests);
        Assert.DoesNotContain("evil.example", handler.Requests[0].Path);
    }

    [Fact]
    public void Default_handler_disables_automatic_redirects()
    {
        Assert.False(ApiClient.CreateHandler().AllowAutoRedirect);
    }

    [Fact]
    public async Task Rate_limited_exposes_retry_after()
    {
        var handler = new StubHandler(_ =>
        {
            var r = StubHandler.Json((HttpStatusCode)429,
                """{"error":{"code":"rate_limited","message":"Слишком часто","request_id":"0000000000000001"}}""");
            r.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
            return r;
        });
        using var api = Client(handler);

        var ex = await Assert.ThrowsAsync<ApiException>(() => api.GetMeAsync("a", default));

        Assert.Equal("rate_limited", ex.Code);
        Assert.Equal(TimeSpan.FromSeconds(7), ex.RetryAfter);
    }

    [Fact]
    public async Task Nulls_are_kept_as_nulls()
    {
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/me" => StubHandler.Json(HttpStatusCode.OK,
                """{"user":{"id":"11111111-1111-4111-8111-111111111111","email":"a@b.c","display_name":null,"status":"active","locale":"ru","created_at":"2026-11-24T10:00:00Z"},"plan":null,"devices":{"live":0,"limit":0}}"""),
            "/api/v1/servers" => StubHandler.Json(HttpStatusCode.OK,
                """{"servers":[{"id":"22222222-2222-4222-8222-222222222222","name":"s","country_code":"DE","city":"Berlin","host":"203.0.113.1","port":51820,"mtu":1420,"latitude":52.52,"longitude":13.4,"availability":"unknown","latency_ms":null,"load":null,"capacity_mbps":null,"provider":"p","region":""}]}"""),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = Client(handler);

        var me = await api.GetMeAsync("a", default);
        var servers = await api.ListServersAsync("a", default);

        Assert.Null(me.Plan);
        Assert.Equal(0, me.Devices.Limit);
        Assert.Null(servers[0].LatencyMs);
        Assert.Null(servers[0].Load);
        Assert.Null(servers[0].CapacityMbps);
    }

    [Fact]
    public async Task Authenticated_calls_send_bearer_and_idempotency_key()
    {
        var handler = new StubHandler(_ => StubHandler.Json(HttpStatusCode.Created,
            """{"id":"33333333-3333-4333-8333-333333333333","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","platform":"windows","name":"pc","created_at":"2026-11-24T10:00:00Z","last_seen_at":null,"revoked_at":null}"""));
        using var api = Client(handler);

        await api.CreateDeviceAsync("acc", new DeviceCreate(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "windows", "pc"), "key-1", default);

        var r = handler.Requests.Single();
        Assert.Equal("Bearer acc", r.Auth);
        Assert.Equal("key-1", r.Idem);
    }

    [Fact]
    public async Task Config_is_returned_as_plain_text()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("[Interface]\nAddress = 10.0.0.2/32\n", Encoding.UTF8, "text/plain"),
        });
        using var api = Client(handler);

        var text = await api.GetConfigTextAsync("a", Guid.NewGuid(), Guid.NewGuid(), default);

        Assert.StartsWith("[Interface]", text);
    }

    [Fact]
    public void Base_lowercase_code_falls_back_by_status()
    {
        Assert.Equal("internal", ApiExceptionFactory.CodeForStatus(500));
        Assert.Equal("unauthenticated", ApiExceptionFactory.CodeForStatus(401));
        Assert.Equal("conflict", ApiExceptionFactory.CodeForStatus(409));
    }
}
```

- [ ] **Step 6: Убедиться, что тесты падают**

Run: `dotnet test client/NovaVpn.Client.sln --filter ApiClientTests`
Expected: ошибки компиляции `ApiClient`, `ApiExceptionFactory`.

- [ ] **Step 7: Реализовать `ApiClient` и фабрику ошибок**

`client/src/NovaVpn.Client.Core/Api/ApiClient.cs`:

```csharp
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace NovaVpn.Client.Core.Api;

public interface IApiObserver
{
    void OnRequestCompleted(ApiCall call);
}

public sealed record ApiCall(string Method, string Path, int Status, string? RequestId, TimeSpan Duration);

public static class ApiExceptionFactory
{
    public static string CodeForStatus(int status) => status switch
    {
        401 => "unauthenticated",
        403 => "forbidden",
        404 => "not_found",
        409 => "conflict",
        429 => "rate_limited",
        _ => "internal",
    };
}

public sealed class ApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly IApiObserver? _observer;

    public ApiClient(Uri baseUrl, HttpMessageHandler? handler = null,
        TimeSpan? timeout = null, IApiObserver? observer = null)
    {
        var h = handler ?? CreateHandler();
        _http = new HttpClient(h, disposeHandler: handler is null)
        {
            BaseAddress = baseUrl,
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
        };
        _observer = observer;
    }

    internal static HttpClientHandler CreateHandler() => new() { AllowAutoRedirect = false };

    public Task<Session> RegisterAsync(string email, string password, CancellationToken ct) =>
        SendAsync<Session>(HttpMethod.Post, "api/v1/auth/register",
            new { email, password }, null, null, ct);

    public Task<Session> LoginAsync(string email, string password, CancellationToken ct) =>
        SendAsync<Session>(HttpMethod.Post, "api/v1/auth/login",
            new { email, password }, null, null, ct);

    public Task<Session> RefreshAsync(string refreshToken, CancellationToken ct) =>
        SendAsync<Session>(HttpMethod.Post, "api/v1/auth/refresh",
            new { refresh_token = refreshToken }, null, null, ct);

    public Task LogoutAsync(string refreshToken, CancellationToken ct) =>
        SendAsync<object>(HttpMethod.Post, "api/v1/auth/logout",
            new { refresh_token = refreshToken }, null, null, ct, noContent: true);

    public Task<MeView> GetMeAsync(string accessToken, CancellationToken ct) =>
        SendAsync<MeView>(HttpMethod.Get, "api/v1/me", null, accessToken, null, ct);

    public async Task<IReadOnlyList<DeviceView>> ListDevicesAsync(string accessToken, CancellationToken ct)
    {
        var list = await SendAsync<DeviceListWire>(HttpMethod.Get, "api/v1/devices", null, accessToken, null, ct);
        return list.Devices;
    }

    public Task<DeviceView> CreateDeviceAsync(string accessToken, DeviceCreate body,
        string idempotencyKey, CancellationToken ct) =>
        SendAsync<DeviceView>(HttpMethod.Post, "api/v1/devices", body, accessToken, idempotencyKey, ct);

    public Task DeleteDeviceAsync(string accessToken, Guid deviceId, CancellationToken ct) =>
        SendAsync<object>(HttpMethod.Delete, $"api/v1/devices/{deviceId}", null, accessToken, null, ct, noContent: true);

    public async Task<IReadOnlyList<ServerView>> ListServersAsync(string accessToken, CancellationToken ct)
    {
        var list = await SendAsync<ServerListWire>(HttpMethod.Get, "api/v1/servers", null, accessToken, null, ct);
        return list.Servers;
    }

    public async Task<IReadOnlyList<ProfileView>> ListProfilesAsync(string accessToken,
        Guid deviceId, CancellationToken ct)
    {
        var list = await SendAsync<ProfileListWire>(HttpMethod.Get,
            $"api/v1/devices/{deviceId}/profiles", null, accessToken, null, ct);
        return list.Profiles;
    }

    public Task<ProfileView> IssueProfileAsync(string accessToken, Guid deviceId, Guid serverId,
        string idempotencyKey, CancellationToken ct) =>
        SendAsync<ProfileView>(HttpMethod.Post, $"api/v1/devices/{deviceId}/profiles",
            new { server_id = serverId }, accessToken, idempotencyKey, ct);

    public Task RevokeProfileAsync(string accessToken, Guid deviceId, Guid serverId, CancellationToken ct) =>
        SendAsync<object>(HttpMethod.Delete, $"api/v1/devices/{deviceId}/profiles/{serverId}",
            null, accessToken, null, ct, noContent: true);

    public async Task<string> GetConfigTextAsync(string accessToken, Guid deviceId, Guid serverId,
        CancellationToken ct) =>
        await SendAsync<string>(HttpMethod.Get,
            $"api/v1/devices/{deviceId}/profiles/{serverId}/config", null, accessToken, null, ct);

    public void Dispose() => _http.Dispose();

    private async Task<T> SendAsync<T>(HttpMethod method, string path, object? body,
        string? accessToken, string? idempotencyKey, CancellationToken ct, bool noContent = false)
    {
        using var req = new HttpRequestMessage(method, path);
        if (accessToken is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (idempotencyKey is not null)
            req.Headers.TryAddWithoutValidation("Idempotency-Key", idempotencyKey);
        if (body is not null)
            req.Content = JsonContent.Create(body, options: JsonDefaults.Options);

        var started = Stopwatch.StartNew();
        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ApiException(ClientErrorCodes.Timeout, 0, "Истекло время ожидания ответа API.");
        }
        catch (HttpRequestException)
        {
            throw new ApiException(ClientErrorCodes.Network, 0, "Нет связи с API.");
        }

        using (resp)
        {
            var status = (int)resp.StatusCode;
            if (status is >= 300 and < 400)
            {
                _observer?.OnRequestCompleted(new ApiCall(method.Method, path, status, null, started.Elapsed));
                throw new ApiException(ClientErrorCodes.Network, status,
                    "API перенаправляет запросы; переадресация запрещена.");
            }
            if (status is >= 200 and < 300)
            {
                var requestId = RequestId(resp, null);
                _observer?.OnRequestCompleted(new ApiCall(method.Method, path, status, requestId, started.Elapsed));
                if (noContent || status == 204) return default!;
                var text = await resp.Content.ReadAsStringAsync(ct);
                if (typeof(T) == typeof(string)) return (T)(object)text;
                return JsonSerializer.Deserialize<T>(text, JsonDefaults.Options)
                    ?? throw new ApiException("internal", status, "Пустой ответ API.", requestId: requestId);
            }

            var raw = await resp.Content.ReadAsStringAsync(ct);
            var ex = ParseError(resp, raw, status);
            _observer?.OnRequestCompleted(new ApiCall(method.Method, path, status, ex.RequestId, started.Elapsed));
            throw ex;
        }
    }

    private static ApiException ParseError(HttpResponseMessage resp, string raw, int status)
    {
        string? code = null, message = null, requestId = null;
        JsonElement? details = null;
        try
        {
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.TryGetProperty("error", out var err))
            {
                if (err.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String) code = c.GetString();
                if (err.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String) message = m.GetString();
                if (err.TryGetProperty("request_id", out var r) && r.ValueKind == JsonValueKind.String) requestId = r.GetString();
                if (err.TryGetProperty("details", out var d)) details = d.Clone();
            }
        }
        catch (JsonException) { }

        var retryAfter = resp.Headers.RetryAfter?.Delta;
        return new ApiException(
            code ?? ApiExceptionFactory.CodeForStatus(status),
            status,
            message ?? status switch
            {
                401 => "Сессия недействительна.",
                403 => "Действие запрещено.",
                404 => "Не найдено.",
                409 => "Конфликт состояния.",
                429 => "Слишком часто.",
                _ => "Внутренняя ошибка.",
            },
            details,
            RequestId(resp, requestId),
            retryAfter);
    }

    private static string? RequestId(HttpResponseMessage resp, string? bodyValue) =>
        bodyValue ?? (resp.Headers.TryGetValues("X-Request-Id", out var v) ? v.FirstOrDefault() : null);

    private sealed record DeviceListWire(IReadOnlyList<DeviceView> Devices);
    private sealed record ServerListWire(IReadOnlyList<ServerView> Servers);
    private sealed record ProfileListWire(IReadOnlyList<ProfileView> Profiles);
}
```

В `NovaVpn.Client.Core.csproj` добавить:

```xml
<ItemGroup>
  <InternalsVisibleTo Include="NovaVpn.Client.Core.Tests" />
</ItemGroup>
```

- [ ] **Step 8: Написать падающий тест журнала**

`client/tests/NovaVpn.Client.Core.Tests/ClientLogTests.cs`:

```csharp
using NovaVpn.Client.Core.Diagnostics;

namespace NovaVpn.Client.Core.Tests;

public sealed class ClientLogTests
{
    [Fact]
    public void Rotates_and_keeps_three_files()
    {
        using var dir = new TempDir();
        var log = new ClientLog(dir.Path, maxBytes: 200);
        for (var i = 0; i < 40; i++) log.Write($"event {i} {new string('x', 30)}");

        var files = Directory.GetFiles(dir.Path, "client-*.log*").OrderBy(p => p).ToList();
        Assert.Equal(3, files.Count);
        Assert.All(files, f => Assert.True(new FileInfo(f).Length <= 260));
    }

    [Fact]
    public void Lines_do_not_accept_arbitrary_fields()
    {
        using var dir = new TempDir();
        var log = new ClientLog(dir.Path);
        log.Write("GET /api/v1/me 401 req=9a1b2c3d4e5f6071 12ms");

        var text = File.ReadAllText(Directory.GetFiles(dir.Path).Single());
        Assert.Contains("GET /api/v1/me", text);
        Assert.DoesNotContain("Bearer ", text);
    }
}
```

`TempDir` — общий тестовый помощник, `client/tests/NovaVpn.Client.Core.Tests/Support/TempDir.cs`:

```csharp
namespace NovaVpn.Client.Core.Tests.Support;

internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "novavpn-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
```

- [ ] **Step 9: Реализовать журнал**

`client/src/NovaVpn.Client.Core/Diagnostics/ClientLog.cs`:

```csharp
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
```

- [ ] **Step 10: Прогнать тесты задачи**

```bash
dotnet test client/NovaVpn.Client.sln
make actionlint
```

Expected: `Failed: 0`; в выводе присутствуют `ApiBaseUrlTests` (14 тестов: 6 + 8), `ApiClientTests` (8), `ClientLogTests` (2).

- [ ] **Step 11: Коммит**

```bash
git add client
git commit -m "feat(client): HTTP-клиент API с конвертом ошибок и запретом редиректов"
```

---

### Task 3: DPAPI-хранилище, восстановление сессии и single-flight refresh

**Files:**
- Create: `client/src/NovaVpn.Client.Core/Storage/DpapiFile.cs`
- Create: `client/src/NovaVpn.Client.Core/Storage/SessionStore.cs`
- Create: `client/src/NovaVpn.Client.Core/Storage/SettingsStore.cs`
- Create: `client/src/NovaVpn.Client.Core/Auth/SessionService.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/Support/FakeClock.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/DpapiFileTests.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/SessionServiceTests.cs`
- Modify: `client/tests/NovaVpn.Client.Core.Tests/Support/StubHandler.cs` (читать тело запроса)

**Interfaces:**
- Consumes: `ApiClient`, `ApiException`, `Session`, `MeView`.
- Produces:
  - `DpapiFile(string path, string entropy)` с `byte[]? Read()`, `void Write(byte[] plain)`, `void Delete()`, `bool Exists`.
  - `StorageCorruptedException : Exception`.
  - `SessionStore(string rootDir)` с `StoredSession? Load()`, `void Save(StoredSession)`, `void Clear()`; запись `StoredSession(int Schema, Uri ApiBaseUrl, string Email, string RefreshToken, DateTimeOffset RefreshExpiresAt)`.
  - `SettingsStore(string rootDir)` с `ClientSettings Load()`, `void Save(ClientSettings)`; запись `ClientSettings(int Schema, Uri? ApiBaseUrl, int WindowWidth, int WindowHeight, Guid? SelectedDeviceId)`; значения по умолчанию `(1, null, 900, 700, null)`.
  - `SessionService(ApiClient api, Uri baseUrl, SessionStore store, TimeProvider? time = null)`; `SessionSnapshot? Current`; `string? StartupError`; `Uri BaseUrl`; `string? Email`; `Task<SessionSnapshot> LoginAsync(email, password, ct)`; `RegisterAsync`; `Task<bool> TryRestoreAsync(ct)`; `Task<MeView> GetMeAsync(ct)`; `Task<T> AuthorizedAsync<T>(Func<string, CancellationToken, Task<T>> call, ct)`; `Task LogoutAsync(ct)`; `void ClearLocal()`; `event Action? Changed`; `SessionSnapshot(Uri BaseUrl, string Email, string AccessToken, DateTimeOffset AccessExpiresAt)`.

- [ ] **Step 1: Написать падающие тесты DPAPI**

`client/tests/NovaVpn.Client.Core.Tests/DpapiFileTests.cs`:

```csharp
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class DpapiFileTests
{
    [Fact]
    public void Roundtrip_is_not_plaintext_on_disk()
    {
        using var dir = new TempDir();
        var file = new DpapiFile(Path.Combine(dir.Path, "session.dat"), "NovaVPN/session/v1");
        var plain = System.Text.Encoding.UTF8.GetBytes("secret-marker-123");

        file.Write(plain);

        Assert.True(file.Exists);
        Assert.DoesNotContain("secret-marker-123",
            System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(file.Path)));
        Assert.Equal(plain, file.Read());
    }

    [Fact]
    public void Corrupt_block_is_reported_and_file_is_kept()
    {
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "session.dat");
        File.WriteAllBytes(path, new byte[] { 1, 2, 3, 4, 5 });
        var file = new DpapiFile(path, "NovaVPN/session/v1");

        Assert.Throws<StorageCorruptedException>(() => file.Read());
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Missing_file_reads_as_null() 
    {
        using var dir = new TempDir();
        var file = new DpapiFile(Path.Combine(dir.Path, "session.dat"), "NovaVPN/session/v1");
        Assert.Null(file.Read());
    }
}
```

`DpapiFile` должен публично отдавать `Path` и `Exists` — добавьте свойства в интерфейс реализации.

- [ ] **Step 2: Запустить, увидеть падение**

Run: `dotnet test client/NovaVpn.Client.sln --filter DpapiFileTests`
Expected: `DpapiFile`/`StorageCorruptedException` не существуют.

- [ ] **Step 3: Реализовать `DpapiFile`**

`client/src/NovaVpn.Client.Core/Storage/DpapiFile.cs`:

```csharp
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
            return ProtectedData.Unprotect(raw, _entropy, DataProtectionScope.CurrentUser);
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
        var encrypted = ProtectedData.Protect(plain, _entropy, DataProtectionScope.CurrentUser);
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
```

- [ ] **Step 4: Написать падающие тесты сессии**

Сначала расширить `StubHandler` чтением тела:

```csharp
private sealed record Captured(string Method, string Path, string? Auth, string? Idem, string? Body);

public List<Captured> Requests { get; } = new();

protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
{
    var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
    Requests.Add((
        request.Method.Method,
        request.RequestUri!.PathAndQuery,
        request.Headers.Authorization?.ToString(),
        request.Headers.TryGetValues("Idempotency-Key", out var v) ? v.Single() : null,
        body));
    return _respond(request, Requests.Count);
}
```

Поля кортежа используются именами в тестах задач 2, 4, 5 — имена `Method/Path/Auth/Idem/Body` сохранить.

`client/tests/NovaVpn.Client.Core.Tests/Support/FakeClock.cs`:

```csharp
namespace NovaVpn.Client.Core.Tests.Support;

internal sealed class FakeClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
}
```

`SessionService` получает `TimeProvider? time = null` (по умолчанию `TimeProvider.System`); тест передаёт `FakeClock`.

`client/tests/NovaVpn.Client.Core.Tests/SessionServiceTests.cs`:

```csharp
using System.Net;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class SessionServiceTests
{
    private static readonly Uri Base = new("https://api.example/");
    private static readonly string MeJson =
        """{"user":{"id":"11111111-1111-4111-8111-111111111111","email":"a@b.c","display_name":null,"status":"active","locale":"ru","created_at":"2026-11-24T10:00:00Z"},"plan":null,"devices":{"live":0,"limit":0}}""";

    private static Session Session(string access, string refresh) => new(
        access, refresh, "Bearer",
        DateTimeOffset.Parse("2026-11-24T10:05:00Z"),
        DateTimeOffset.Parse("2026-12-24T10:00:00Z"));

    private static string ApiJson(Session s) => JsonSerializer.Serialize(new
    {
        access_token = s.AccessToken,
        refresh_token = s.RefreshToken,
        token_type = s.TokenType,
        access_expires_at = s.AccessExpiresAt,
        refresh_expires_at = s.RefreshExpiresAt,
    });

    [Fact]
    public async Task Authorized_call_refreshes_once_and_retries()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        var meCalls = 0;
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a1", "r1"))),
            "/api/v1/auth/refresh" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a2", "r2"))),
            "/api/v1/me" when req.Headers.Authorization!.Parameter == "a1" => MeUnauthorized(),
            "/api/v1/me" => SuccessMe(),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);
        await svc.LoginAsync("a@b.c", "0123456789", default);

        var me = await svc.AuthorizedAsync((t, c) => api.GetMeAsync(t, c), default);

        Assert.Equal("a@b.c", me.User.Email);
        Assert.Equal(1, handler.Requests.Count(r => r.Path == "/api/v1/auth/refresh"));
        Assert.Equal("r2", store.Load()!.RefreshToken);
        Assert.Equal(2, handler.Requests.Count(r => r.Path == "/api/v1/me"));
    }

    [Fact]
    public async Task Parallel_401_wait_for_one_refresh()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        var refreshCalls = 0;
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a1", "r1"))),
            "/api/v1/auth/refresh" => Interlocked.Increment(ref refreshCalls) == 1
                ? StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a2", "r2")))
                : Interlocked.Increment(ref refreshCalls) == 2
                    ? StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a3", "r3")))
                    : StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a4", "r4"))),
            "/api/v1/me" when req.Headers.Authorization!.Parameter == "a1" => MeUnauthorized(),
            "/api/v1/me" => SuccessMe(),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);
        await svc.LoginAsync("a@b.c", "0123456789", default);

        var results = await Task.WhenAll(Enumerable.Range(0, 3)
            .Select(_ => svc.AuthorizedAsync((t, c) => api.GetMeAsync(t, c), default)));

        Assert.All(results, m => Assert.Equal("a@b.c", m.User.Email));
        Assert.Equal(1, refreshCalls);
        Assert.Equal(1, handler.Requests.Count(r => r.Path == "/api/v1/auth/refresh"));
    }

    [Fact]
    public async Task Failed_refresh_clears_local_session()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a1", "r1"))),
            "/api/v1/me" => MeUnauthorized(),
            "/api/v1/auth/refresh" => StubHandler.Json(HttpStatusCode.Unauthorized,
                """{"error":{"code":"refresh_token_invalid","message":"Сессия недействительна","request_id":"0000000000000001"}}"""),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);
        await svc.LoginAsync("a@b.c", "0123456789", default);

        var ex = await Assert.ThrowsAsync<ApiException>(() =>
            svc.AuthorizedAsync((t, c) => api.GetMeAsync(t, c), default));

        Assert.Equal("refresh_token_invalid", ex.Code);
        Assert.Null(svc.Current);
        Assert.False(store.Exists);
    }

    [Fact]
    public async Task Logout_clears_locally_even_when_api_is_unreachable()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a1", "r1"))),
            "/api/v1/auth/logout" => throw new HttpRequestException("offline"),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);
        await svc.LoginAsync("a@b.c", "0123456789", default);

        await svc.LogoutAsync(default);

        Assert.Null(svc.Current);
        Assert.False(store.Exists);
    }

    [Fact]
    public async Task Corrupt_store_reports_message_and_keeps_file()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        File.WriteAllBytes(System.IO.Path.Combine(dir.Path, "session.dat"), new byte[] { 9, 9, 9 });
        using var api = new ApiClient(Base, new StubHandler(_ => StubHandler.Json(HttpStatusCode.OK, "{}")));
        var svc = new SessionService(api, Base, store);

        var restored = await svc.TryRestoreAsync(default);

        Assert.False(restored);
        Assert.Contains("Хранилище повреждено", svc.StartupError);
        Assert.True(store.Exists);
    }

    [Fact]
    public async Task Restore_refreshes_and_returns_signed_in_state()
    {
        using var dir = new TempDir();
        var store = new SessionStore(dir.Path);
        store.Save(new StoredSession(1, Base, "a@b.c", "r1",
            DateTimeOffset.Parse("2026-12-24T10:00:00Z")));
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/refresh" => StubHandler.Json(HttpStatusCode.OK, ApiJson(Session("a2", "r2"))),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        using var api = new ApiClient(Base, handler);
        var svc = new SessionService(api, Base, store);

        Assert.True(await svc.TryRestoreAsync(default));
        Assert.Equal("a@b.c", svc.Current!.Email);
        Assert.Equal("r2", store.Load()!.RefreshToken);
    }

    private static HttpResponseMessage MeUnauthorized() => StubHandler.Json(HttpStatusCode.Unauthorized,
        """{"error":{"code":"unauthenticated","message":"Требуется вход","request_id":"0000000000000002"}}""");

    private static HttpResponseMessage SuccessMe() => StubHandler.Json(HttpStatusCode.OK, MeJson);
}
```

`StubHandler` должен поддерживать бросок исключения из фабрики — `SendAsync` уже пробрасывает; тест `Logout` ловит `HttpRequestException` внутри `ApiClient` и превращает в `ApiException(network)`, затем `LogoutAsync` его глотает.

- [ ] **Step 5: Запустить, увидеть падение**

Run: `dotnet test client/NovaVpn.Client.sln --filter SessionServiceTests`
Expected: `SessionService`, `SessionStore`, `StoredSession` не существуют.

- [ ] **Step 6: Реализовать хранилища и сессию**

`client/src/NovaVpn.Client.Core/Storage/SessionStore.cs`:

```csharp
using System.Text.Json;
using NovaVpn.Client.Core.Api;

namespace NovaVpn.Client.Core.Storage;

public sealed record StoredSession(
    int Schema,
    Uri ApiBaseUrl,
    string Email,
    string RefreshToken,
    DateTimeOffset RefreshExpiresAt);

public sealed class SessionStore
{
    private const int CurrentSchema = 1;
    private readonly DpapiFile _file;

    public SessionStore(string rootDir)
        : this(new DpapiFile(Path.Combine(rootDir, "session.dat"), "NovaVPN/session/v1")) { }

    internal SessionStore(DpapiFile file) => _file = file;

    public bool Exists => _file.Exists;
    public string Path => _file.Path;

    public StoredSession? Load()
    {
        var plain = _file.Read();
        if (plain is null) return null;
        StoredSession? stored;
        try
        {
            stored = JsonSerializer.Deserialize<StoredSession>(plain, JsonDefaults.Options);
        }
        catch (JsonException ex)
        {
            throw new StorageCorruptedException(_file.Path, ex);
        }
        if (stored is null || stored.Schema != CurrentSchema)
            throw new StorageCorruptedException(_file.Path,
                new InvalidDataException("Неизвестная схема session.dat"));
        return stored;
    }

    public void Save(StoredSession session)
    {
        if (session.Schema != CurrentSchema)
            throw new ArgumentException("Схема записи должна быть 1.", nameof(session));
        _file.Write(JsonSerializer.SerializeToUtf8Bytes(session, JsonDefaults.Options));
    }

    public void Clear() => _file.Delete();
}
```

`client/src/NovaVpn.Client.Core/Storage/SettingsStore.cs`:

```csharp
using System.Text.Json;
using NovaVpn.Client.Core.Api;

namespace NovaVpn.Client.Core.Storage;

public sealed record ClientSettings(
    int Schema,
    Uri? ApiBaseUrl,
    int WindowWidth,
    int WindowHeight,
    Guid? SelectedDeviceId)
{
    public static ClientSettings Default => new(1, null, 900, 700, null);
}

public sealed class SettingsStore
{
    private const int CurrentSchema = 1;
    private readonly string _path;

    public SettingsStore(string rootDir) => _path = Path.Combine(rootDir, "settings.json");

    public ClientSettings Load()
    {
        if (!File.Exists(_path)) return ClientSettings.Default;
        try
        {
            var s = JsonSerializer.Deserialize<ClientSettings>(File.ReadAllBytes(_path), JsonDefaults.Options);
            return s is { Schema: CurrentSchema } ? s : ClientSettings.Default;
        }
        catch (JsonException)
        {
            return ClientSettings.Default;
        }
    }

    public void Save(ClientSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var tmp = _path + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllBytes(tmp, JsonSerializer.SerializeToUtf8Bytes(settings, JsonDefaults.Options));
        if (File.Exists(_path)) File.Replace(tmp, _path, null);
        else File.Move(tmp, _path);
    }
}
```

`client/src/NovaVpn.Client.Core/Auth/SessionService.cs`:

```csharp
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Storage;

namespace NovaVpn.Client.Core.Auth;

public sealed record SessionSnapshot(
    Uri BaseUrl,
    string Email,
    string AccessToken,
    DateTimeOffset AccessExpiresAt);

public sealed class SessionService
{
    private readonly ApiClient _api;
    private readonly Uri _baseUrl;
    private readonly SessionStore _store;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private string? _access;
    private string? _refresh;
    private SessionSnapshot? _current;

    public SessionService(ApiClient api, Uri baseUrl, SessionStore store, TimeProvider? time = null)
    {
        _api = api;
        _baseUrl = baseUrl;
        _store = store;
        _time = time ?? TimeProvider.System;
    }

    public SessionSnapshot? Current => _current;
    public Uri BaseUrl => _baseUrl;
    public string? Email => _current?.Email;
    public string? StartupError { get; private set; }
    public event Action? Changed;

    public async Task<SessionSnapshot> LoginAsync(string email, string password, CancellationToken ct)
    {
        ValidateCredentials(email, password);
        return Apply(await _api.LoginAsync(email.Trim(), password, ct));
    }

    public async Task<SessionSnapshot> RegisterAsync(string email, string password, CancellationToken ct)
    {
        ValidateCredentials(email, password);
        return Apply(await _api.RegisterAsync(email.Trim(), password, ct));
    }

    public async Task<MeView> GetMeAsync(CancellationToken ct) =>
        await AuthorizedAsync((t, c) => _api.GetMeAsync(t, c), ct);

    public async Task<bool> TryRestoreAsync(CancellationToken ct)
    {
        StartupError = null;
        StoredSession? stored;
        try
        {
            stored = _store.Load();
        }
        catch (StorageCorruptedException)
        {
            StartupError = "Хранилище повреждено или принадлежит другому пользователю. Войдите заново.";
            return false;
        }
        if (stored is null || stored.ApiBaseUrl != _baseUrl) return false;
        if (stored.RefreshExpiresAt <= _time.GetUtcNow())
        {
            _store.Clear();
            return false;
        }
        _refresh = stored.RefreshToken;
        try
        {
            Apply(await _api.RefreshAsync(stored.RefreshToken, ct));
            return true;
        }
        catch (ApiException ex) when (ex.Code is "refresh_token_invalid" or "account_locked")
        {
            ClearLocal();
            return false;
        }
    }

    public async Task<T> AuthorizedAsync<T>(
        Func<string, CancellationToken, Task<T>> call, CancellationToken ct)
    {
        var used = _access ?? throw new ApiException("unauthenticated", 401, "Сессия не открыта.");
        try
        {
            return await call(used, ct);
        }
        catch (ApiException ex) when (ex.StatusCode == 401)
        {
            var fresh = await RefreshOnceAsync(used, ct);
            return await call(fresh, ct);
        }
    }

    public async Task LogoutAsync(CancellationToken ct)
    {
        var refresh = _refresh;
        try
        {
            if (refresh is not null) await _api.LogoutAsync(refresh, ct);
        }
        catch (ApiException) { }
        finally
        {
            ClearLocal();
        }
    }

    public void ClearLocal()
    {
        _store.Clear();
        _access = null;
        _refresh = null;
        _current = null;
        Changed?.Invoke();
    }

    private async Task<string> RefreshOnceAsync(string usedAccess, CancellationToken ct)
    {
        await _refreshGate.WaitAsync(ct);
        try
        {
            if (_access is not null && _access != usedAccess) return _access;
            if (_refresh is null)
            {
                ClearLocal();
                throw new ApiException("refresh_token_invalid", 401, "Сессия недействительна.");
            }
            Session session;
            try
            {
                session = await _api.RefreshAsync(_refresh, ct);
            }
            catch (ApiException ex) when (ex.Code is "refresh_token_invalid" or "account_locked")
            {
                ClearLocal();
                throw;
            }
            Apply(session);
            return session.AccessToken;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private SessionSnapshot Apply(Session session)
    {
        // Новый refresh фиксируется на диске до того, как им разрешено пользоваться в памяти.
        _store.Save(new StoredSession(1, _baseUrl, _current?.Email ?? "", session.RefreshToken,
            session.RefreshExpiresAt));
        _access = session.AccessToken;
        _refresh = session.RefreshToken;
        _current = new SessionSnapshot(_baseUrl, _current?.Email ?? "", session.AccessToken,
            session.AccessExpiresAt);
        Changed?.Invoke();
        return _current;
    }

    private static void ValidateCredentials(string email, string password)
    {
        var trimmed = (email ?? "").Trim();
        if (trimmed.Length is 0 or > 254)
            throw new ApiException("bad_args", 0, "Проверьте email.");
        if ((password ?? "").Length is < 10 or > 1024)
            throw new ApiException("bad_args", 0, "Пароль должен быть от 10 до 1024 символов.");
    }
}
```

Проблема: `Apply` при первом входе сохраняет email пустым. Исправьте сигнатуру: `Apply(Session session, string? email = null)`, а `LoginAsync` вызывает `Apply(await ..., email.Trim())`; `TryRestore` — `Apply(session, stored.Email)`; `RefreshOnceAsync` — `Apply(session, _current?.Email)`. Запишите именно так, чтобы `session.dat` всегда содержал email.

`StoredSession` при восстановлении сравнивает `Uri` — `Uri.Equals` учитывает хост/схему/порт и хвостовой `/`. Нормализованный адрес из `ApiBaseUrl` совпадает.

- [ ] **Step 7: Прогнать тесты**

```bash
dotnet test client/NovaVpn.Client.sln --filter "DpapiFileTests|SessionServiceTests"
```

Expected: `Failed: 0`; `DpapiFileTests` 3, `SessionServiceTests` 6.

- [ ] **Step 8: Коммит**

```bash
git add client
git commit -m "feat(client): DPAPI-хранилище сессии и single-flight refresh"
```

---

### Task 4: Пара X25519, идентичность устройства и регистрация

**Files:**
- Create: `client/src/NovaVpn.Client.Core/Devices/DeviceKeyPair.cs`
- Create: `client/src/NovaVpn.Client.Core/Devices/DeviceIdentity.cs`
- Create: `client/src/NovaVpn.Client.Core/Storage/DeviceIdentityStore.cs`
- Create: `client/src/NovaVpn.Client.Core/Devices/DeviceService.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/DeviceKeyPairTests.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/DeviceServiceTests.cs`
- Modify: `client/tests/NovaVpn.Client.Core.Tests/Support/StubHandler.cs` (тело уже добавлено в задаче 3)

**Interfaces:**
- Consumes: `SessionService`, `ApiClient`, `ApiException`, `DeviceView`, `DeviceCreate`.
- Produces:
  - `DeviceKeyPair.Generate()`; `DeviceKeyPair.FromPrivate(string)`; свойства `PrivateKeyBase64`, `PublicKeyBase64`; `static string PublicFromPrivate(string)`.
  - `DeviceIdentity(Uri ApiBaseUrl, string Email, Guid? DeviceId, string PublicKey, string PrivateKey, string Name, DateTimeOffset CreatedAt)`.
  - `DeviceIdentityStore(string rootDir)` с `DeviceIdentity? Get(string key)`, `void Put(string key, DeviceIdentity)`, `void Remove(string key)`, `static string AccountKey(Uri, string email)`.
  - `DeviceService(ApiClient api, SessionService session, DeviceIdentityStore store, string? hostName = null)` с `DeviceIdentity? CurrentIdentity`, `Task<DeviceView> EnsureRegisteredAsync(ct)`, `Task<DeviceView> CreateAsync(string name, ct)`, `Task DeleteAsync(Guid deviceId, ct)`, `Task SuppressAutoCreateAsync()`. Имя хоста по умолчанию — `Environment.MachineName`; приложение передаёт своё (см. задачу 8).
  - `DeviceService.IdempotencyKeyFor(string publicKey)`.

- [ ] **Step 1: Написать падающий тест RFC 7748**

`client/tests/NovaVpn.Client.Core.Tests/DeviceKeyPairTests.cs`:

```csharp
using NovaVpn.Client.Core.Devices;

namespace NovaVpn.Client.Core.Tests;

public sealed class DeviceKeyPairTests
{
    [Fact]
    public void Public_key_matches_rfc7748_vector()
    {
        var alicePrivate = Convert.FromHexString(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var expectedPublic = Convert.FromHexString(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        var pair = DeviceKeyPair.FromPrivate(Convert.ToBase64String(alicePrivate));

        Assert.Equal(Convert.ToBase64String(expectedPublic), pair.PublicKeyBase64);
    }

    [Fact]
    public void Generated_keys_have_wireguard_shape()
    {
        var pair = DeviceKeyPair.Generate();

        Assert.Equal(44, pair.PrivateKeyBase64.Length);
        Assert.Equal(44, pair.PublicKeyBase64.Length);
        Assert.EndsWith("=", pair.PublicKeyBase64);
        Assert.Equal(32, Convert.FromBase64String(pair.PrivateKeyBase64).Length);
        Assert.Equal(32, Convert.FromBase64String(pair.PublicKeyBase64).Length);
    }

    [Fact]
    public void Two_pairs_are_different()
    {
        Assert.NotEqual(DeviceKeyPair.Generate().PublicKeyBase64,
            DeviceKeyPair.Generate().PublicKeyBase64);
    }
}
```

- [ ] **Step 2: Запустить, увидеть падение**

Run: `dotnet test client/NovaVpn.Client.sln --filter DeviceKeyPairTests`
Expected: `DeviceKeyPair` не существует.

- [ ] **Step 3: Реализовать пару**

`client/src/NovaVpn.Client.Core/Devices/DeviceKeyPair.cs`:

```csharp
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
```

- [ ] **Step 4: Написать падающие тесты хранилища идентичности**

`client/tests/NovaVpn.Client.Core.Tests/DeviceIdentityStoreTests.cs`:

```csharp
using NovaVpn.Client.Core.Devices;
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class DeviceIdentityStoreTests
{
    private static readonly Uri Base = new("https://api.example/");

    [Fact]
    public void Roundtrip_is_bound_to_api_and_email()
    {
        using var dir = new TempDir();
        var store = new DeviceIdentityStore(dir.Path);
        var key = DeviceIdentityStore.AccountKey(Base, "a@b.c");
        var id = new DeviceIdentity(Base, "a@b.c", Guid.NewGuid(),
            "pub", "priv", "pc", DateTimeOffset.Parse("2026-11-24T10:00:00Z"));

        store.Put(key, id);

        var loaded = new DeviceIdentityStore(dir.Path).Get(key);
        Assert.Equal(id, loaded);
        Assert.NotEqual(key, DeviceIdentityStore.AccountKey(new Uri("https://other.example/"), "a@b.c"));
        Assert.NotEqual(key, DeviceIdentityStore.AccountKey(Base, "x@b.c"));
    }

    [Fact]
    public void Remove_deletes_only_that_record()
    {
        using var dir = new TempDir();
        var store = new DeviceIdentityStore(dir.Path);
        var k1 = DeviceIdentityStore.AccountKey(Base, "a@b.c");
        var k2 = DeviceIdentityStore.AccountKey(Base, "c@d.e");
        store.Put(k1, new DeviceIdentity(Base, "a@b.c", null, "p1", "s1", "pc", DateTimeOffset.UtcNow));
        store.Put(k2, new DeviceIdentity(Base, "c@d.e", null, "p2", "s2", "pc", DateTimeOffset.UtcNow));

        store.Remove(k1);

        Assert.Null(store.Get(k1));
        Assert.NotNull(store.Get(k2));
    }
}
```

- [ ] **Step 5: Реализовать модель и хранилище**

`client/src/NovaVpn.Client.Core/Devices/DeviceIdentity.cs`:

```csharp
namespace NovaVpn.Client.Core.Devices;

public sealed record DeviceIdentity(
    Uri ApiBaseUrl,
    string Email,
    Guid? DeviceId,
    string PublicKey,
    string PrivateKey,
    string Name,
    DateTimeOffset CreatedAt);
```

`client/src/NovaVpn.Client.Core/Storage/DeviceIdentityStore.cs`:

```csharp
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Devices;

namespace NovaVpn.Client.Core.Storage;

public sealed class DeviceIdentityStore
{
    private const int CurrentSchema = 1;
    private readonly DpapiFile _file;
    private readonly object _gate = new();

    public DeviceIdentityStore(string rootDir)
        : this(new DpapiFile(Path.Combine(rootDir, "devices.dat"), "NovaVPN/devices/v1")) { }

    internal DeviceIdentityStore(DpapiFile file) => _file = file;

    public static string AccountKey(Uri baseUrl, string email)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(
            baseUrl.GetLeftPart(UriPartial.Authority) + "\n" + email.Trim()));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public DeviceIdentity? Get(string key) => Read().GetValueOrDefault(key);

    public void Put(string key, DeviceIdentity identity)
    {
        lock (_gate)
        {
            var all = Read();
            all[key] = identity;
            Write(all);
        }
    }

    public void Remove(string key)
    {
        lock (_gate)
        {
            var all = Read();
            if (!all.Remove(key)) return;
            if (all.Count == 0) _file.Delete();
            else Write(all);
        }
    }

    private Dictionary<string, DeviceIdentity> Read()
    {
        var plain = _file.Read();
        if (plain is null) return new(StringComparer.Ordinal);
        try
        {
            var doc = JsonSerializer.Deserialize<DeviceFile>(plain, JsonDefaults.Options);
            if (doc is null || doc.Schema != CurrentSchema) throw new InvalidDataException("schema");
            return new Dictionary<string, DeviceIdentity>(doc.Records, StringComparer.Ordinal);
        }
        catch (JsonException ex)
        {
            throw new StorageCorruptedException(_file.Path, ex);
        }
    }

    private void Write(Dictionary<string, DeviceIdentity> records) =>
        _file.Write(JsonSerializer.SerializeToUtf8Bytes(
            new DeviceFile(CurrentSchema, records), JsonDefaults.Options));

    private sealed record DeviceFile(int Schema, Dictionary<string, DeviceIdentity> Records);
}
```

- [ ] **Step 6: Написать падающие тесты сервиса устройства**

`client/tests/NovaVpn.Client.Core.Tests/DeviceServiceTests.cs`:

```csharp
using System.Net;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Devices;
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class DeviceServiceTests
{
    private static readonly Uri Base = new("https://api.example/");
    private static readonly Guid UserId = Guid.Parse("11111111-1111-4111-8111-111111111111");

    private static HttpResponseMessage Session() => StubHandler.Json(HttpStatusCode.OK,
        """{"access_token":"a1","refresh_token":"r1","token_type":"Bearer","access_expires_at":"2026-11-24T10:05:00Z","refresh_expires_at":"2026-12-24T10:00:00Z"}""");

    private static string DeviceJson(Guid id, string publicKey, string? revokedAt = null) =>
        JsonSerializer.Serialize(new
        {
            id,
            public_key = publicKey,
            platform = "windows",
            name = "pc",
            created_at = "2026-11-24T10:00:00Z",
            last_seen_at = (string?)null,
            revoked_at = revokedAt,
        });

    private static HttpResponseMessage List(params object[] devices) =>
        StubHandler.Json(HttpStatusCode.OK, JsonSerializer.Serialize(new { devices }));

    private static HttpResponseMessage Error(HttpStatusCode status, string code) =>
        StubHandler.Json(status,
            $$"""{"error":{"code":"{{code}}","message":"m","request_id":"0000000000000001"}}""");

    private sealed record Env(StubHandler Handler, ApiClient Api, SessionService Session,
        DeviceIdentityStore Store, DeviceService Devices, string AccountKey);

    private static async Task<Env> CreateAsync(TempDir dir, Func<string, HttpResponseMessage> onPost)
    {
        var currentKey = "";
        var handler = new StubHandler(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => Session(),
            "/api/v1/auth/refresh" => Session(),
            "/api/v1/me" => StubHandler.Json(HttpStatusCode.OK,
                $$"""{"user":{"id":"{{UserId}}","email":"a@b.c","display_name":null,"status":"active","locale":"ru","created_at":"2026-11-24T10:00:00Z"},"plan":{"slug":"internal-default","device_limit":3,"traffic_quota_bytes":null},"devices":{"live":0,"limit":3}}"""),
            "/api/v1/devices" when req.Method == HttpMethod.Post => onPost(currentKey),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });
        var store = new SessionStore(dir.Path);
        var identities = new DeviceIdentityStore(dir.Path);
        var api = new ApiClient(Base, handler);
        var session = new SessionService(api, Base, store);
        await session.LoginAsync("a@b.c", "0123456789", default);
        var devices = new DeviceService(api, session, identities);
        return new Env(handler, api, session, identities, devices,
            DeviceIdentityStore.AccountKey(Base, "a@b.c"));
    }

    [Fact]
    public async Task First_registration_saves_pair_before_post_and_fills_device_id()
    {
        using var dir = new TempDir();
        Guid? createdId = null;
        string? postedKey = null;
        var env = await CreateAsync(dir, body =>
        {
            using var doc = JsonDocument.Parse(body);
            postedKey = doc.RootElement.GetProperty("public_key").GetString();
            createdId = Guid.NewGuid();
            return StubHandler.Json(HttpStatusCode.Created, DeviceJson(createdId.Value, postedKey!));
        });
        // Перехватить список: пустой до регистрации.
        env.Handler.SetResponder(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/devices" when req.Method == HttpMethod.Get => List(),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });

        var device = await env.Devices.EnsureRegisteredAsync(default);

        Assert.Equal(createdId, device.Id);
        var stored = env.Store.Get(env.AccountKey)!;
        Assert.Equal(createdId, stored.DeviceId);
        Assert.Equal(postedKey, stored.PublicKey);
        Assert.Null(env.Store.Get(env.AccountKey)!.DeviceId is null ? null : "filled");
    }

    [Fact]
    public async Task Existing_live_device_is_reused_without_post()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, _ => throw new InvalidOperationException("POST must not happen"));
        var liveId = Guid.NewGuid();
        var pair = DeviceKeyPair.Generate();
        env.Store.Put(env.AccountKey, new DeviceIdentity(Base, "a@b.c", null,
            pair.PublicKeyBase64, pair.PrivateKeyBase64, "pc", DateTimeOffset.UtcNow));
        env.Handler.SetResponder(req => req.RequestUri!.AbsolutePath == "/api/v1/devices"
            ? List(new { id = liveId, public_key = pair.PublicKeyBase64, platform = "windows", name = "pc",
                created_at = "2026-11-24T10:00:00Z", last_seen_at = (string?)null, revoked_at = (string?)null })
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        var device = await env.Devices.EnsureRegisteredAsync(default);

        Assert.Equal(liveId, device.Id);
        Assert.Equal(liveId, env.Store.Get(env.AccountKey)!.DeviceId);
        Assert.DoesNotContain(env.Handler.Requests, r => r.Method == "POST");
    }

    [Fact]
    public async Task Revoked_key_is_replaced_by_new_pair()
    {
        using var dir = new TempDir();
        string? postedKey = null;
        var env = await CreateAsync(dir, body =>
        {
            using var doc = JsonDocument.Parse(body);
            postedKey = doc.RootElement.GetProperty("public_key").GetString();
            return StubHandler.Json(HttpStatusCode.Created, DeviceJson(Guid.NewGuid(), postedKey!));
        });
        var oldPair = DeviceKeyPair.Generate();
        env.Store.Put(env.AccountKey, new DeviceIdentity(Base, "a@b.c", Guid.NewGuid(),
            oldPair.PublicKeyBase64, oldPair.PrivateKeyBase64, "pc", DateTimeOffset.UtcNow));
        env.Handler.SetResponder(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/devices" when req.Method == HttpMethod.Get => List(new
            {
                id = Guid.NewGuid(), public_key = oldPair.PublicKeyBase64, platform = "windows",
                name = "pc", created_at = "2026-11-24T10:00:00Z",
                last_seen_at = (string?)null, revoked_at = "2026-11-24T11:00:00Z",
            }),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });

        await env.Devices.EnsureRegisteredAsync(default);

        Assert.NotNull(postedKey);
        Assert.NotEqual(oldPair.PublicKeyBase64, postedKey);
        Assert.Equal(postedKey, env.Store.Get(env.AccountKey)!.PublicKey);
    }

    [Fact]
    public async Task Duplicate_device_is_reconciled_with_live_list()
    {
        using var dir = new TempDir();
        string? postedKey = null;
        var deviceId = Guid.NewGuid();
        var env = await CreateAsync(dir, body =>
        {
            using var doc = JsonDocument.Parse(body);
            postedKey = doc.RootElement.GetProperty("public_key").GetString();
            return Error(HttpStatusCode.Conflict, "duplicate_device");
        });
        env.Handler.SetResponder(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/devices" when req.Method == HttpMethod.Get => List(new
            {
                id = deviceId, public_key = postedKey, platform = "windows", name = "pc",
                created_at = "2026-11-24T10:00:00Z", last_seen_at = (string?)null,
                revoked_at = (string?)null,
            }),
            _ => StubHandler.Json(HttpStatusCode.NotFound, "{}"),
        });

        var device = await env.Devices.EnsureRegisteredAsync(default);

        Assert.Equal(deviceId, device.Id);
    }

    [Fact]
    public async Task Limit_error_is_propagated()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, _ => Error(HttpStatusCode.Conflict, "device_limit_reached"));
        env.Handler.SetResponder(req => req.RequestUri!.AbsolutePath == "/api/v1/devices"
            && req.Method == HttpMethod.Get ? List() : env.Handler.Last!);

        var ex = await Assert.ThrowsAsync<ApiException>(() => env.Devices.EnsureRegisteredAsync(default));

        Assert.Equal("device_limit_reached", ex.Code);
    }

    [Fact]
    public async Task Delete_removes_local_pair_and_treats_404_as_gone()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, _ => Error(HttpStatusCode.Conflict, "device_limit_reached"));
        var deviceId = Guid.NewGuid();
        env.Store.Put(env.AccountKey, new DeviceIdentity(Base, "a@b.c", deviceId,
            "pub", "priv", "pc", DateTimeOffset.UtcNow));
        env.Handler.SetResponder(req => req.RequestUri!.AbsolutePath.StartsWith("/api/v1/devices/")
            ? StubHandler.Json(HttpStatusCode.NotFound, "{}")
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        await env.Devices.DeleteAsync(deviceId, default);

        Assert.Null(env.Store.Get(env.AccountKey));
    }

    [Fact]
    public async Task Idempotency_key_depends_on_public_key()
    {
        Assert.Equal(DeviceService.IdempotencyKeyFor("A"), DeviceService.IdempotencyKeyFor("A"));
        Assert.NotEqual(DeviceService.IdempotencyKeyFor("A"), DeviceService.IdempotencyKeyFor("B"));
    }
}
```

`StubHandler` дополняется методом `SetResponder(Func<HttpRequestMessage, HttpResponseMessage>)` и свойством `Last` (последний ответ) — реализуйте их, сохранив конструктор из задачи 2. `onPost` в `CreateAsync` больше не нужен после `SetResponder`; оставьте его только для тестов регистрации. В тестах, где `SetResponder` меняет ответы, GET `/api/v1/devices` должен отвечать списком; обработчик `POST` остаётся из первого responder.

- [ ] **Step 7: Реализовать `DeviceService`**

`client/src/NovaVpn.Client.Core/Devices/DeviceService.cs`:

```csharp
using System.Security.Cryptography;
using System.Text;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Storage;

namespace NovaVpn.Client.Core.Devices;

public sealed class DeviceService
{
    private readonly ApiClient _api;
    private readonly SessionService _session;
    private readonly DeviceIdentityStore _store;
    private readonly string _hostName;
    private bool _autoCreateSuppressed;

    public DeviceService(ApiClient api, SessionService session, DeviceIdentityStore store, string? hostName = null)
    {
        _api = api;
        _session = session;
        _store = store;
        _hostName = string.IsNullOrWhiteSpace(hostName) ? Environment.MachineName : hostName;
    }

    public DeviceIdentity? CurrentIdentity =>
        _session is { BaseUrl: var b, Email: { } e } ? _store.Get(DeviceIdentityStore.AccountKey(b, e)) : null;

    public static string IdempotencyKeyFor(string publicKey) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("device-create\n" + publicKey)))
            .ToLowerInvariant();

    public async Task<DeviceView> EnsureRegisteredAsync(CancellationToken ct)
    {
        if (_autoCreateSuppressed)
            throw new ApiException("bad_args", 0, "Устройство не создано: выберите «Создать устройство».");
        var (baseUrl, email) = Location();
        var accountKey = DeviceIdentityStore.AccountKey(baseUrl, email);
        var identity = _store.Get(accountKey);
        var devices = await ListWireAsync(ct);

        if (identity is not null)
        {
            var live = devices.FirstOrDefault(d => d.PublicKey == identity.PublicKey && d.RevokedAt is null);
            if (live is not null)
            {
                if (identity.DeviceId != live.Id) _store.Put(accountKey, identity with { DeviceId = live.Id });
                return live;
            }
            if (devices.Any(d => d.PublicKey == identity.PublicKey))
                identity = NewIdentity(baseUrl, email); // сохранённый ключ отозван: занять его нельзя
        }

        identity ??= NewIdentity(baseUrl, email);
        return await RegisterAsync(identity, accountKey, retryDuplicate: true, ct);
    }

    public async Task<DeviceView> CreateAsync(string name, CancellationToken ct)
    {
        var (baseUrl, email) = Location();
        var accountKey = DeviceIdentityStore.AccountKey(baseUrl, email);
        var current = _store.Get(accountKey);
        if (current?.DeviceId is Guid oldId)
            await DeleteAsync(oldId, ct);
        _autoCreateSuppressed = false;
        var identity = NewIdentity(baseUrl, email, name);
        return await RegisterAsync(identity, accountKey, retryDuplicate: false, ct);
    }

    public async Task DeleteAsync(Guid deviceId, CancellationToken ct)
    {
        var (baseUrl, email) = Location();
        var accountKey = DeviceIdentityStore.AccountKey(baseUrl, email);
        try
        {
            await _session.AuthorizedAsync((t, c) => _api.DeleteDeviceAsync(t, deviceId, c), ct);
        }
        catch (ApiException ex) when (ex.StatusCode == 404)
        {
            // Для «забыть устройство» отсутствие на сервере — уже достигнутый результат.
        }
        var current = _store.Get(accountKey);
        if (current?.DeviceId is null || current.DeviceId == deviceId) _store.Remove(accountKey);
        _autoCreateSuppressed = true;
    }

    public Task SuppressAutoCreateAsync()
    {
        _autoCreateSuppressed = true;
        return Task.CompletedTask;
    }

    private async Task<DeviceView> RegisterAsync(DeviceIdentity identity, string accountKey,
        bool retryDuplicate, CancellationToken ct)
    {
        _store.Put(accountKey, identity); // до запроса: повтор после сети идёт с той же парой
        var body = new DeviceCreate(identity.PublicKey, "windows", identity.Name);
        var idem = IdempotencyKeyFor(identity.PublicKey);
        try
        {
            var device = await _session.AuthorizedAsync(
                (t, c) => _api.CreateDeviceAsync(t, body, idem, c), ct);
            _store.Put(accountKey, identity with { DeviceId = device.Id });
            return device;
        }
        catch (ApiException ex) when (ex.Code == "duplicate_device" && retryDuplicate)
        {
            var devices = await ListWireAsync(ct);
            var live = devices.FirstOrDefault(d => d.PublicKey == identity.PublicKey && d.RevokedAt is null);
            if (live is not null)
            {
                _store.Put(accountKey, identity with { DeviceId = live.Id });
                return live;
            }
            var fresh = NewIdentity(identity.ApiBaseUrl, identity.Email, identity.Name);
            return await RegisterAsync(fresh, accountKey, retryDuplicate: false, ct);
        }
    }

    private Task<IReadOnlyList<DeviceView>> ListWireAsync(CancellationToken ct) =>
        _session.AuthorizedAsync((t, c) => _api.ListDevicesAsync(t, c), ct);

    private (Uri BaseUrl, string Email) Location()
    {
        if (_session.Current is null || _session.Email is null)
            throw new ApiException("unauthenticated", 401, "Сессия не открыта.");
        return (_session.BaseUrl, _session.Email);
    }

    private DeviceIdentity NewIdentity(Uri baseUrl, string email, string? name = null)
    {
        var pair = DeviceKeyPair.Generate();
        return new DeviceIdentity(baseUrl, email, null, pair.PublicKeyBase64, pair.PrivateKeyBase64,
            NormalizeName(name ?? _hostName), DateTimeOffset.UtcNow);
    }

    private static string NormalizeName(string name)
    {
        var trimmed = name.Trim();
        if (trimmed.Length == 0) return "Windows";
        return trimmed.Length <= 64 ? trimmed : trimmed[..64];
    }
}
```

- [ ] **Step 8: Прогнать тесты задачи**

```bash
dotnet test client/NovaVpn.Client.sln --filter "DeviceKeyPairTests|DeviceIdentityStoreTests|DeviceServiceTests"
```

Expected: `Failed: 0`. Если тест дубликата падает из-за порядка запросов, исправляйте тест (GET после POST), а не уберите проверку.

- [ ] **Step 9: Коммит**

```bash
git add client
git commit -m "feat(client): X25519-пара, идентичность устройства и регистрация"
```

---

### Task 5: Сборка WireGuard-конфига и экспорт файла

**Files:**
- Create: `client/src/NovaVpn.Client.Core/Config/ConfigException.cs`
- Create: `client/src/NovaVpn.Client.Core/Config/WireGuardConfig.cs`
- Create: `client/src/NovaVpn.Client.Core/Config/ConfigExporter.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/WireGuardConfigTests.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/ConfigExporterTests.cs`

**Interfaces:**
- Consumes: `DeviceKeyPair`, `ConfigException`.
- Produces:
  - `WireGuardConfig.Compose(string serverText, string privateKeyBase64, string expectedPublicKey)` → `string`; бросает `ConfigException`.
  - `ConfigExporter.DefaultFileName(string serverName)`; `ConfigExporter.Write(string path, string text)`.
  - `ConfigException(string message)`.

- [ ] **Step 1: Написать падающие тесты композиции**

`client/tests/NovaVpn.Client.Core.Tests/WireGuardConfigTests.cs`:

```csharp
using System.Text;
using NovaVpn.Client.Core.Config;
using NovaVpn.Client.Core.Devices;

namespace NovaVpn.Client.Core.Tests;

public sealed class WireGuardConfigTests
{
    private static readonly DeviceKeyPair Pair = DeviceKeyPair.Generate();

    private static string ServerText(string publicKey = "") =>
        "[Interface]\n" +
        "Address = 10.66.0.2/32\n" +
        "DNS = 10.66.0.1\n" +
        "MTU = 1420\n" +
        "\n" +
        "[Peer]\n" +
        $"PublicKey = {(publicKey.Length == 0 ? DeviceKeyPair.Generate().PublicKeyBase64 : publicKey)}\n" +
        "AllowedIPs = 0.0.0.0/0, ::/0\n" +
        "Endpoint = 203.0.113.1:51820\n" +
        "PersistentKeepalive = 25\n";

    [Fact]
    public void Inserts_private_key_after_interface_and_preserves_tail()
    {
        var text = ServerText();

        var composed = WireGuardConfig.Compose(text, Pair.PrivateKeyBase64, Pair.PublicKeyBase64);

        Assert.StartsWith("[Interface]\nPrivateKey = " + Pair.PrivateKeyBase64 + "\nAddress = 10.66.0.2/32\n",
            composed);
        var serverTail = text["[Interface]\n".Length..];
        Assert.Contains(serverTail, composed);
        Assert.EndsWith("PersistentKeepalive = 25\n", composed);
        Assert.DoesNotContain("\r", composed);
        Assert.DoesNotContain("\uFEFF", composed);
        Assert.Equal(Encoding.UTF8.GetByteCount(composed),
            new UTF8Encoding(false).GetByteCount(composed));
    }

    [Fact]
    public void Rejects_wrong_public_key()
    {
        var ex = Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(ServerText(), Pair.PrivateKeyBase64,
                DeviceKeyPair.Generate().PublicKeyBase64));
        Assert.Contains("публичн", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_invalid_private_key()
    {
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(ServerText(), "not-base64", Pair.PublicKeyBase64));
    }

    [Theory]
    [InlineData("\r\n")]
    public void Rejects_crlf(string newline)
    {
        var text = ServerText().Replace("\n", newline);
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(text, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_nul_and_bom()
    {
        Assert.Throws<ConfigException>(() => WireGuardConfig.Compose(
            ServerText().Replace("MTU = 1420", "MTU = 142\0"), Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
        Assert.Throws<ConfigException>(() => WireGuardConfig.Compose(
            "\uFEFF" + ServerText(), Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_missing_final_lf()
    {
        var text = ServerText().TrimEnd('\n');
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(text, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_duplicate_sections_and_existing_private_key()
    {
        var duplicate = ServerText().Replace("[Peer]", "[Interface]\n[Peer]");
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(duplicate, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));

        var withKey = ServerText().Replace("[Interface]\n",
            "[Interface]\nPrivateKey = " + Pair.PrivateKeyBase64 + "\n");
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(withKey, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_unknown_section_and_malformed_line()
    {
        Assert.Throws<ConfigException>(() => WireGuardConfig.Compose(
            ServerText().Replace("[Peer]", "[Peer]\n[Extra]"), Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
        Assert.Throws<ConfigException>(() => WireGuardConfig.Compose(
            ServerText().Replace("MTU = 1420", "MTU=1420"), Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }

    [Fact]
    public void Rejects_missing_peer()
    {
        var text = ServerText().Split("[Peer]")[0];
        Assert.Throws<ConfigException>(() =>
            WireGuardConfig.Compose(text, Pair.PrivateKeyBase64, Pair.PublicKeyBase64));
    }
}
```

NUL внутри строки записывается escape-последовательностью `\0` и остаётся частью литерала; хвостовых символов после закрывающей кавычки быть не должно.

- [ ] **Step 2: Запустить, увидеть падение**

Run: `dotnet test client/NovaVpn.Client.sln --filter WireGuardConfigTests`
Expected: `WireGuardConfig`/`ConfigException` не существуют.

- [ ] **Step 3: Реализовать сборку**

`client/src/NovaVpn.Client.Core/Config/ConfigException.cs`:

```csharp
namespace NovaVpn.Client.Core.Config;

public sealed class ConfigException : Exception
{
    public ConfigException(string message) : base(message) { }
}
```

`client/src/NovaVpn.Client.Core/Config/WireGuardConfig.cs`:

```csharp
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
```

- [ ] **Step 4: Написать падающие тесты экспорта**

`client/tests/NovaVpn.Client.Core.Tests/ConfigExporterTests.cs`:

```csharp
using System.Text;
using NovaVpn.Client.Core.Config;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class ConfigExporterTests
{
    [Theory]
    [InlineData("Berlin 1", "NovaVPN-Berlin1.conf")]
    [InlineData("ams-01_nl", "NovaVPN-ams-01_nl.conf")]
    [InlineData("../../etc/passwd", "NovaVPN-....etcpasswd.conf")]
    [InlineData("Москва", "NovaVPN-server.conf")]
    [InlineData("", "NovaVPN-server.conf")]
    public void Default_name_is_sanitized(string server, string expected)
    {
        Assert.Equal(expected, ConfigExporter.DefaultFileName(server));
    }

    [Fact]
    public void Write_uses_utf8_without_bom_and_overwrites()
    {
        using var dir = new TempDir();
        var path = Path.Combine(dir.Path, "NovaVPN-x.conf");
        File.WriteAllText(path, "old");

        ConfigExporter.Write(path, "[Interface]\nPrivateKey = x\n");

        var bytes = File.ReadAllBytes(path);
        Assert.False(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF);
        Assert.Equal("[Interface]\nPrivateKey = x\n", Encoding.UTF8.GetString(bytes));
    }
}
```

- [ ] **Step 5: Реализовать экспорт**

`client/src/NovaVpn.Client.Core/Config/ConfigExporter.cs`:

```csharp
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
```

- [ ] **Step 6: Прогнать тесты задачи**

```bash
dotnet test client/NovaVpn.Client.sln --filter "WireGuardConfigTests|ConfigExporterTests"
```

Expected: `Failed: 0`. В `Rejects_nul_and_bom` убедитесь, что NUL-строка составлена корректно.

- [ ] **Step 7: Коммит**

```bash
git add client
git commit -m "feat(client): структурная сборка WireGuard-конфига и экспорт без BOM"
```

---

### Task 6: Каталог, выдача, отзыв и получение текста профиля

**Files:**
- Create: `client/src/NovaVpn.Client.Core/Profiles/ProfileService.cs`
- Create: `client/tests/NovaVpn.Client.Core.Tests/ProfileServiceTests.cs`

**Interfaces:**
- Consumes: `ApiClient`, `SessionService`, `ApiException`, `ServerView`, `ProfileView`.
- Produces: `ProfileService(ApiClient api, SessionService session)` с `Task<IReadOnlyList<ServerView>> ListServersAsync(ct)`, `Task<IReadOnlyList<ProfileView>> ListAsync(Guid deviceId, ct)`, `Task<ProfileView> IssueAsync(Guid deviceId, Guid serverId, ct)`, `Task RevokeAsync(Guid deviceId, Guid serverId, ct)`, `Task<string> FetchConfigAsync(Guid deviceId, Guid serverId, ct)`.

- [ ] **Step 1: Написать падающие тесты**

`client/tests/NovaVpn.Client.Core.Tests/ProfileServiceTests.cs`:

```csharp
using System.Net;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Profiles;
using NovaVpn.Client.Core.Storage;
using NovaVpn.Client.Core.Tests.Support;

namespace NovaVpn.Client.Core.Tests;

public sealed class ProfileServiceTests
{
    private static readonly Uri Base = new("https://api.example/");
    private static readonly Guid DeviceId = Guid.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly Guid ServerId = Guid.Parse("33333333-3333-4333-8333-333333333333");

    private static HttpResponseMessage Session() => StubHandler.Json(HttpStatusCode.OK,
        """{"access_token":"a1","refresh_token":"r1","token_type":"Bearer","access_expires_at":"2026-11-24T10:05:00Z","refresh_expires_at":"2026-12-24T10:00:00Z"}""");

    private static string ServerJson(string availability = "available", bool measured = false) =>
        JsonSerializer.Serialize(new
        {
            id = ServerId, name = "ams-1", country_code = "NL", city = "Amsterdam",
            host = "203.0.113.1", port = 51820, mtu = 1420, latitude = 52.37, longitude = 4.89,
            availability,
            latency_ms = measured ? 24 : (int?)null,
            load = measured ? 0.4 : (double?)null,
            capacity_mbps = measured ? 1000 : (int?)null,
            provider = "demo", region = "eu-west",
        });

    private static string ProfileJson(string status = "active", string? revokedAt = null) =>
        JsonSerializer.Serialize(new
        {
            id = Guid.NewGuid(), device_id = DeviceId, server_id = ServerId,
            address_v4 = "10.66.0.2", status,
            issued_at = "2026-11-24T10:00:00Z",
            expires_at = "2026-12-24T10:00:00Z",
            overlap_valid_until = (string?)null,
            revoked_at = revokedAt,
        });

    private sealed record Env(StubHandler Handler, ApiClient Api, SessionService Session,
        ProfileService Profiles);

    private static async Task<Env> CreateAsync(TempDir dir, Func<HttpRequestMessage, int, HttpResponseMessage> respond)
    {
        var handler = new StubHandler((req, n) => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => Session(),
            _ => respond(req, n),
        });
        var api = new ApiClient(Base, handler);
        var session = new SessionService(api, Base, new SessionStore(dir.Path));
        await session.LoginAsync("a@b.c", "0123456789", default);
        return new Env(handler, api, session, new ProfileService(api, session));
    }

    [Fact]
    public async Task Catalog_keeps_nulls_and_availability_literal()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, (req, _) => req.RequestUri!.AbsolutePath == "/api/v1/servers"
            ? StubHandler.Json(HttpStatusCode.OK, $$"""{"servers":[{{ServerJson("unknown")}}]}""")
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        var servers = await env.Profiles.ListServersAsync(default);

        var s = Assert.Single(servers);
        Assert.Equal("unknown", s.Availability);
        Assert.Null(s.LatencyMs);
        Assert.Null(s.Load);
        Assert.Null(s.CapacityMbps);
    }

    [Fact]
    public async Task Issue_reuses_key_after_server_error_and_new_key_after_success()
    {
        using var dir = new TempDir();
        var issueCalls = 0;
        var env = await CreateAsync(dir, (req, _) =>
        {
            if (req.Method != HttpMethod.Post) return StubHandler.Json(HttpStatusCode.NotFound, "{}");
            issueCalls++;
            return issueCalls == 1
                ? StubHandler.Json(HttpStatusCode.InternalServerError,
                    """{"error":{"code":"internal","message":"m","request_id":"0000000000000003"}}""")
                : StubHandler.Json(HttpStatusCode.Created, ProfileJson());
        });

        await Assert.ThrowsAsync<ApiException>(() => env.Profiles.IssueAsync(DeviceId, ServerId, default));
        var first = await env.Profiles.IssueAsync(DeviceId, ServerId, default);
        var second = await env.Profiles.IssueAsync(DeviceId, ServerId, default);

        var keys = env.Handler.Requests.Where(r => r.Method == "POST" && r.Path.EndsWith("/profiles"))
            .Select(r => r.Idem).ToList();
        Assert.Equal(3, keys.Count);
        Assert.NotNull(keys[0]);
        Assert.Equal(keys[0], keys[1]);
        Assert.NotEqual(keys[1], keys[2]);
        Assert.Equal("active", first.Status);
        Assert.Equal("active", second.Status);
    }

    [Fact]
    public async Task Issue_drops_key_after_conflict()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, (req, _) => req.Method == HttpMethod.Post
            ? StubHandler.Json(HttpStatusCode.Conflict,
                """{"error":{"code":"conflict","message":"m","details":{"reason":"pool_exhausted"},"request_id":"0000000000000004"}}""")
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        await Assert.ThrowsAsync<ApiException>(() => env.Profiles.IssueAsync(DeviceId, ServerId, default));
        await Assert.ThrowsAsync<ApiException>(() => env.Profiles.IssueAsync(DeviceId, ServerId, default));

        var keys = env.Handler.Requests
            .Where(r => r.Method == "POST" && r.Path.EndsWith("/profiles"))
            .Select(r => r.Idem).ToList();
        Assert.Equal(2, keys.Count);
        Assert.NotEqual(keys[0], keys[1]);
    }

    [Fact]
    public async Task Issue_keeps_key_when_operation_is_in_progress()
    {
        using var dir = new TempDir();
        var calls = 0;
        var env = await CreateAsync(dir, (req, _) =>
        {
            calls++;
            return calls == 1
                ? StubHandler.Json(HttpStatusCode.Conflict,
                    """{"error":{"code":"idempotency_key_in_progress","message":"m","request_id":"0000000000000005"}}""")
                : StubHandler.Json(HttpStatusCode.Created, ProfileJson());
        });

        await Assert.ThrowsAsync<ApiException>(() => env.Profiles.IssueAsync(DeviceId, ServerId, default));
        await env.Profiles.IssueAsync(DeviceId, ServerId, default);

        var keys = env.Handler.Requests
            .Where(r => r.Method == "POST" && r.Path.EndsWith("/profiles"))
            .Select(r => r.Idem).ToList();
        Assert.Equal(2, keys.Count);
        Assert.Equal(keys[0], keys[1]);
    }

    [Fact]
    public async Task Profiles_list_shows_statuses_literally()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, (req, _) => req.RequestUri!.AbsolutePath.Contains("/profiles")
            ? StubHandler.Json(HttpStatusCode.OK,
                $$"""{"profiles":[{{ProfileJson("revoked", "2026-11-24T11:00:00Z")}},{{ProfileJson("superseded")}}]}""")
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        var profiles = await env.Profiles.ListAsync(DeviceId, default);

        Assert.Equal(new[] { "revoked", "superseded" }, profiles.Select(p => p.Status));
        Assert.Equal("2026-11-24T11:00:00Z", profiles[0].RevokedAt!.Value.ToUniversalTime()
            .ToString("yyyy-MM-ddTHH:mm:ssZ"));
    }

    [Fact]
    public async Task Revoke_conflict_reports_actual_status()
    {
        using var dir = new TempDir();
        var env = await CreateAsync(dir, (req, _) => req.Method == HttpMethod.Delete
            ? StubHandler.Json(HttpStatusCode.Conflict,
                """{"error":{"code":"conflict","message":"m","details":{"status":"revoked"},"request_id":"0000000000000006"}}""")
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        var ex = await Assert.ThrowsAsync<ApiException>(() => env.Profiles.RevokeAsync(DeviceId, ServerId, default));

        Assert.Equal("conflict", ex.Code);
        Assert.Contains("revoked", ex.Message);
        Assert.Equal("revoked", ex.DetailString("status"));
    }

    [Fact]
    public async Task Config_returns_text_and_uses_expected_path()
    {
        using var dir = new TempDir();
        const string config = "[Interface]\nAddress = 10.66.0.2/32\n";
        var env = await CreateAsync(dir, (req, _) => req.RequestUri!.AbsolutePath.EndsWith("/config")
            ? StubHandler.Text(HttpStatusCode.OK, config)
            : StubHandler.Json(HttpStatusCode.NotFound, "{}"));

        var text = await env.Profiles.FetchConfigAsync(DeviceId, ServerId, default);

        Assert.Equal(config, text);
        Assert.Contains(env.Handler.Requests, r => r.Path ==
            $"/api/v1/devices/{DeviceId}/profiles/{ServerId}/config");
    }
}
```

`StubHandler` из задачи 2 уже объявляет обе перегрузки конструктора — простую и с номером запроса (`int` начинается с 1, простая делегирует в неё), поэтому `new StubHandler((req, n) => …)` работает без правок; не добавляйте эту перегрузку повторно. Здесь добавьте только фабрику `Text(HttpStatusCode, string)` с `StringContent(..., Encoding.UTF8, "text/plain")`. Существующие тесты не меняются.

- [ ] **Step 2: Запустить, увидеть падение**

Run: `dotnet test client/NovaVpn.Client.sln --filter ProfileServiceTests`
Expected: `ProfileService` не существует.

- [ ] **Step 3: Реализовать сервис**

`client/src/NovaVpn.Client.Core/Profiles/ProfileService.cs`:

```csharp
using System.Collections.Concurrent;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;

namespace NovaVpn.Client.Core.Profiles;

public sealed class ProfileService
{
    private readonly ApiClient _api;
    private readonly SessionService _session;
    private readonly ConcurrentDictionary<string, string> _issueKeys = new(StringComparer.Ordinal);

    public ProfileService(ApiClient api, SessionService session)
    {
        _api = api;
        _session = session;
    }

    public Task<IReadOnlyList<ServerView>> ListServersAsync(CancellationToken ct) =>
        _session.AuthorizedAsync((t, c) => _api.ListServersAsync(t, c), ct);

    public Task<IReadOnlyList<ProfileView>> ListAsync(Guid deviceId, CancellationToken ct) =>
        _session.AuthorizedAsync((t, c) => _api.ListProfilesAsync(t, deviceId, c), ct);

    public async Task<ProfileView> IssueAsync(Guid deviceId, Guid serverId, CancellationToken ct)
    {
        var intent = $"{deviceId:N}:{serverId:N}";
        var key = _issueKeys.GetOrAdd(intent, _ => Guid.NewGuid().ToString("N"));
        try
        {
            var profile = await _session.AuthorizedAsync(
                (t, c) => _api.IssueProfileAsync(t, deviceId, serverId, key, c), ct);
            _issueKeys.TryRemove(intent, out _);
            return profile;
        }
        catch (ApiException ex) when (!IsTransient(ex))
        {
            _issueKeys.TryRemove(intent, out _);
            throw;
        }
    }

    public async Task RevokeAsync(Guid deviceId, Guid serverId, CancellationToken ct)
    {
        try
        {
            await _session.AuthorizedAsync(async (t, c) =>
            {
                await _api.RevokeProfileAsync(t, deviceId, serverId, c);
                return true;
            }, ct);
        }
        catch (ApiException ex) when (ex.Code == "conflict" && ex.DetailString("status") is { } status)
        {
            throw new ApiException("conflict", ex.StatusCode,
                $"Профиль уже в состоянии «{status}».", ex.Details, ex.RequestId, ex.RetryAfter);
        }
    }

    public Task<string> FetchConfigAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        _session.AuthorizedAsync((t, c) => _api.GetConfigTextAsync(t, deviceId, serverId, c), ct);

    private static bool IsTransient(ApiException ex) =>
        ex.Code is ClientErrorCodes.Network or ClientErrorCodes.Timeout or "idempotency_key_in_progress"
        || ex.StatusCode >= 500;
}
```

- [ ] **Step 4: Прогнать тесты задачи**

```bash
dotnet test client/NovaVpn.Client.sln --filter ProfileServiceTests
```

Expected: `Failed: 0`, 7 тестов.

- [ ] **Step 5: Коммит**

```bash
git add client
git commit -m "feat(client): каталог, выдача и отзыв профиля с ключом намерения"
```

---

### Task 7: Контракты моста, кольцо диагностики и роутер команд

> **Принято при исполнении** (коммиты `cdbd3eb`, `024da7e`; решения контроллера в журнале SDD):
> - белый список и диспетчер — один экземплярный словарь `Dictionary<string, Func<JsonElement, CancellationToken, Task<object?>>>` с `StringComparer.Ordinal`, проверка команды через `TryGetValue`; отдельного `HashSet` и недостижимой ветки `_ =>` нет;
> - `DiagnosticRing` использует `Trim(string,int)` и `TrimOptional(string?,int)`;
> - тестовый литерал oversized-сообщения — `$$$"""...{{{huge}}}"}}"""`;
> - `StorageCorruptedException` ловится отдельно и отдаётся кодом `storage_corrupted`; общий `catch (Exception ex)` пишет в кольцо `internal:{имя типа}`;
> - ранние отказы `bad_args` (размер, корень, `id`) пишутся в кольцо; имя устройства обрезается до проверки длины.

**Files:**
- Create: `client/src/NovaVpn.Client.App/NovaVpn.Client.App.csproj`
- Create: `client/src/NovaVpn.Client.App/Bridge/BridgeContracts.cs`
- Create: `client/src/NovaVpn.Client.App/Bridge/IBridgeBackend.cs`
- Create: `client/src/NovaVpn.Client.App/Bridge/BridgeRouter.cs`
- Create: `client/src/NovaVpn.Client.Core/Diagnostics/DiagnosticRing.cs`
- Create: `client/tests/NovaVpn.Client.App.Tests/NovaVpn.Client.App.Tests.csproj`
- Create: `client/tests/NovaVpn.Client.App.Tests/FakeBackend.cs`
- Create: `client/tests/NovaVpn.Client.App.Tests/BridgeRouterTests.cs`
- Modify: `client/NovaVpn.Client.sln`

**Interfaces:**
- Consumes: `ApiException`, `ClientErrorCodes`, `MeView`, `DeviceView`, `ServerView`, `ProfileView`, `ClientLog`, `JsonDefaults`.
- Produces:
  - `AppInfoView(string Version, string Platform, string WebView, string Mode)`;
  - `SettingsView(string? ApiBaseUrl, int WindowWidth, int WindowHeight)`;
  - `SessionStateView(bool SignedIn, string? Email, string? ApiBaseUrl, string? StartupError)`;
  - `DevicesView(IReadOnlyList<DeviceView> Devices, Guid? CurrentDeviceId)`;
  - `ExportResult(bool Saved, bool Cancelled, string? FileName, DateTimeOffset? SavedAt)`;
  - `DiagnosticsView(string Version, IReadOnlyList<DiagnosticEvent> Events)`;
  - `IBridgeBackend` (17 методов, см. код);
  - `DiagnosticRing(int capacity = 50)` с `Add(string command, string code, string? requestId)`, `IReadOnlyList<DiagnosticEvent> Snapshot()`, `void Clear()`;
  - `BridgeRouter(IBridgeBackend backend, DiagnosticRing ring, ClientLog? log = null)` с `Task<string> HandleAsync(string json, CancellationToken ct)`.

- [ ] **Step 1: Создать проект приложения и тестовый проект**

`client/src/NovaVpn.Client.App/NovaVpn.Client.App.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Library</OutputType>
    <TargetFramework>net10.0-windows</TargetFramework>
    <UseWindowsForms>true</UseWindowsForms>
    <RootNamespace>NovaVpn.Client.App</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Web.WebView2" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="../NovaVpn.Client.Core/NovaVpn.Client.Core.csproj" />
  </ItemGroup>
  <ItemGroup>
    <Content Include="../../ui/**/*" Link="ui/%(RecursiveDir)%(Filename)%(Extension)"
             CopyToOutputDirectory="PreserveNewest" />
  </ItemGroup>
</Project>
```

`OutputType` станет `WinExe` в задаче 8, когда появится `Program.cs`; сейчас это библиотека, чтобы решения и тестов собирались без точки входа.

`client/tests/NovaVpn.Client.App.Tests/NovaVpn.Client.App.Tests.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0-windows</TargetFramework>
    <UseWindowsForms>true</UseWindowsForms>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" />
    <PackageReference Include="xunit" />
    <PackageReference Include="xunit.runner.visualstudio">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
    </PackageReference>
  </ItemGroup>
  <ItemGroup>
    <Using Include="Xunit" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="../../src/NovaVpn.Client.App/NovaVpn.Client.App.csproj" />
  </ItemGroup>
</Project>
```

```bash
dotnet sln client/NovaVpn.Client.sln add --solution-folder src client/src/NovaVpn.Client.App/NovaVpn.Client.App.csproj
dotnet sln client/NovaVpn.Client.sln add --solution-folder tests client/tests/NovaVpn.Client.App.Tests/NovaVpn.Client.App.Tests.csproj
dotnet restore client/NovaVpn.Client.sln --force-evaluate
```

- [ ] **Step 2: Написать кольцо диагностики и падающий тест роутера**

`client/src/NovaVpn.Client.Core/Diagnostics/DiagnosticRing.cs`:

```csharp
namespace NovaVpn.Client.Core.Diagnostics;

public sealed record DiagnosticEvent(DateTimeOffset Time, string Command, string Code, string? RequestId);

public sealed class DiagnosticRing
{
    private readonly int _capacity;
    private readonly Queue<DiagnosticEvent> _events = new();
    private readonly object _gate = new();

    public DiagnosticRing(int capacity = 50)
    {
        if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
    }

    public void Add(string command, string code, string? requestId)
    {
        lock (_gate)
        {
            _events.Enqueue(new DiagnosticEvent(DateTimeOffset.UtcNow, Trim(command, 64),
                Trim(code, 64), TrimOptional(requestId, 64)));
            while (_events.Count > _capacity) _events.Dequeue();
        }
    }

    public IReadOnlyList<DiagnosticEvent> Snapshot()
    {
        lock (_gate) return _events.ToArray();
    }

    public void Clear()
    {
        lock (_gate) _events.Clear();
    }

    private static string Trim(string value, int max) =>
        value.Length <= max ? value : value[..max];

    private static string? TrimOptional(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
```

`client/tests/NovaVpn.Client.App.Tests/FakeBackend.cs`:

```csharp
using NovaVpn.Client.App.Bridge;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Diagnostics;

namespace NovaVpn.Client.App.Tests;

internal class FakeBackend : IBridgeBackend
{
    public static readonly Guid DeviceId = Guid.Parse("22222222-2222-4222-8222-222222222222");
    public static readonly Guid ServerId = Guid.Parse("33333333-3333-4333-8333-333333333333");
    public DiagnosticRing Ring { get; } = new();
    public AppInfoView LastAppInfo { get; } = new("0.1.0-preview", "windows", "120.0.0", "preview");
    public bool ExportCancelled { get; set; }

    public Task<AppInfoView> GetAppInfoAsync(CancellationToken ct) => Task.FromResult(LastAppInfo);
    public SettingsView GetSettings() => new("https://api.example/", 900, 700);
    public Task<SettingsView> SetSettingsAsync(string apiBaseUrl, CancellationToken ct) =>
        Task.FromResult(new SettingsView(apiBaseUrl, 900, 700));
    public Task<SessionStateView> GetSessionStateAsync(CancellationToken ct) =>
        Task.FromResult(new SessionStateView(true, "a@b.c", "https://api.example/", null));

    public Task<MeView> GetAccountAsync(CancellationToken ct) =>
        Task.FromResult(Me("a@b.c"));

    public Task<MeView> LoginAsync(string email, string password, CancellationToken ct) =>
        Task.FromResult(Me(email));

    public Task<MeView> RegisterAsync(string email, string password, CancellationToken ct) =>
        Task.FromResult(Me(email));

    public Task LogoutAsync(CancellationToken ct) => Task.CompletedTask;

    public Task<DevicesView> ListDevicesAsync(CancellationToken ct) =>
        Task.FromResult(new DevicesView(new[] { Device() }, DeviceId));

    public Task<DeviceView> CreateDeviceAsync(string name, CancellationToken ct) => Task.FromResult(Device());
    public Task DeleteDeviceAsync(Guid deviceId, CancellationToken ct) => Task.CompletedTask;

    public Task<IReadOnlyList<ServerView>> ListServersAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<ServerView>>(new[] { Server() });

    public Task<IReadOnlyList<ProfileView>> ListProfilesAsync(Guid deviceId, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<ProfileView>>(new[] { Profile() });

    public virtual Task<ProfileView> IssueProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        Task.FromResult(Profile());

    public Task RevokeProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) => Task.CompletedTask;

    public Task<ExportResult> ExportProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        Task.FromResult(ExportCancelled
            ? new ExportResult(false, true, null, null)
            : new ExportResult(true, false, "NovaVPN-ams-1.conf", DateTimeOffset.Parse("2026-11-24T12:00:00Z")));

    public Task<DiagnosticsView> GetDiagnosticsAsync(CancellationToken ct) =>
        Task.FromResult(new DiagnosticsView("0.1.0-preview", Ring.Snapshot()));

    private static MeView Me(string email) => new(
        new UserView(Guid.NewGuid(), email, null, "active", "ru",
            DateTimeOffset.Parse("2026-11-24T10:00:00Z")),
        new PlanView("internal-default", 3, null),
        new DeviceUsage(1, 3));

    private static DeviceView Device() => new(DeviceId,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "windows", "pc",
        DateTimeOffset.Parse("2026-11-24T10:00:00Z"), null, null);

    private static ServerView Server() => new(ServerId, "ams-1", "NL", "Amsterdam",
        "203.0.113.1", 51820, 1420, 52.37, 4.89, "available", null, null, null, "demo", "eu-west");

    private static ProfileView Profile() => new(Guid.NewGuid(), DeviceId, ServerId, "10.66.0.2",
        "active", DateTimeOffset.Parse("2026-11-24T10:00:00Z"),
        DateTimeOffset.Parse("2026-12-24T10:00:00Z"), null, null);
}
```

`client/tests/NovaVpn.Client.App.Tests/BridgeRouterTests.cs`:

```csharp
using System.Text.Json;
using NovaVpn.Client.App.Bridge;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Diagnostics;

namespace NovaVpn.Client.App.Tests;

public sealed class BridgeRouterTests
{
    private static (BridgeRouter Router, FakeBackend Backend) Create()
    {
        var backend = new FakeBackend();
        return (new BridgeRouter(backend, backend.Ring), backend);
    }

    private static string Req(string command, string? args = null, string id = "r1") =>
        args is null
            ? $$"""{"id":"{{id}}","command":"{{command}}"}"""
            : $$"""{"id":"{{id}}","command":"{{command}}","args":{{args}}}""";

    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public async Task Whitelisted_command_returns_data_with_id()
    {
        var (router, _) = Create();

        var doc = Parse(await router.HandleAsync(Req("servers.list"), default));

        Assert.True(doc.GetProperty("ok").GetBoolean());
        Assert.Equal("r1", doc.GetProperty("id").GetString());
        Assert.Equal("available", doc.GetProperty("data")[0].GetProperty("availability").GetString());
    }

    [Fact]
    public async Task Unknown_command_is_rejected()
    {
        var (router, _) = Create();

        var doc = Parse(await router.HandleAsync(Req("devices.rotate"), default));

        Assert.False(doc.GetProperty("ok").GetBoolean());
        Assert.Equal("unknown_command", doc.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Malformed_json_and_deep_json_are_bad_args()
    {
        var (router, _) = Create();

        var malformed = Parse(await router.HandleAsync("{", default));
        var deep = Parse(await router.HandleAsync(
            """{"id":"x","command":"app.info","args":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}}}""", default));

        Assert.Equal("bad_args", malformed.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("bad_args", deep.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Oversized_message_is_bad_args()
    {
        var (router, _) = Create();
        var huge = new string('x', 70 * 1024);

        var doc = Parse(await router.HandleAsync(
            $$$"""{"id":"x","command":"device.create","args":{"name":"{{{huge}}}"}}""", default));

        Assert.Equal("bad_args", doc.GetProperty("error").GetProperty("code").GetString());
    }

    [Theory]
    [InlineData("devices.delete", "{}")]
    [InlineData("devices.delete", """{"device_id":"not-a-guid"}""")]
    [InlineData("profiles.issue", """{"device_id":"22222222-2222-4222-8222-222222222222"}""")]
    [InlineData("auth.login", """{"email":"a@b.c","password":"short"}""")]
    [InlineData("settings.set", """{"api_base_url":42}""")]
    [InlineData("devices.create", """{"name":""}""")]
    public async Task Invalid_args_are_rejected(string command, string args)
    {
        var (router, _) = Create();

        var doc = Parse(await router.HandleAsync(Req(command, args), default));

        Assert.Equal("bad_args", doc.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Api_error_keeps_code_and_request_id()
    {
        var failing = new ThrowingBackend
        {
            Failure = new ApiException("server_not_available", 409, "server says",
                requestId: "9a1b2c3d4e5f6071"),
        };
        var r = new BridgeRouter(failing, new DiagnosticRing());

        var doc = Parse(await r.HandleAsync(Req("profiles.issue",
            """{"device_id":"22222222-2222-4222-8222-222222222222","server_id":"33333333-3333-4333-8333-333333333333"}"""),
            default));

        Assert.Equal("server_not_available", doc.GetProperty("error").GetProperty("code").GetString());
        Assert.Equal("9a1b2c3d4e5f6071", doc.GetProperty("error").GetProperty("request_id").GetString());
        Assert.DoesNotContain("server says", doc.ToString());
    }

    [Fact]
    public async Task Export_cancel_is_a_result_not_an_error()
    {
        var (router, backend) = Create();
        backend.ExportCancelled = true;

        var doc = Parse(await router.HandleAsync(Req("profiles.export",
            """{"device_id":"22222222-2222-4222-8222-222222222222","server_id":"33333333-3333-4333-8333-333333333333"}"""),
            default));

        Assert.True(doc.GetProperty("ok").GetBoolean());
        Assert.True(doc.GetProperty("data").GetProperty("cancelled").GetBoolean());
        Assert.False(doc.GetProperty("data").GetProperty("saved").GetBoolean());
    }

    [Fact]
    public async Task All_responses_are_free_of_secret_markers()
    {
        var (router, _) = Create();
        var args = """{"device_id":"22222222-2222-4222-8222-222222222222","server_id":"33333333-3333-4333-8333-333333333333"}""";
        var calls = new[]
        {
            Req("app.info"), Req("settings.get"), Req("settings.set", """{"api_base_url":"https://api.example/"}"""),
            Req("session.state"), Req("account.get"),
            Req("auth.login", """{"email":"a@b.c","password":"0123456789"}"""),
            Req("auth.register", """{"email":"a@b.c","password":"0123456789"}"""),
            Req("auth.logout"), Req("devices.list"), Req("devices.create", """{"name":"pc"}"""),
            Req("devices.delete", args), Req("servers.list"), Req("profiles.list", args),
            Req("profiles.issue", args), Req("profiles.revoke", args), Req("profiles.export", args),
            Req("diagnostics.get"),
        };

        var responses = new List<string>();
        foreach (var call in calls) responses.Add(await router.HandleAsync(call, default));

        foreach (var json in responses)
        {
            Assert.DoesNotContain("eyJ", json);
            Assert.DoesNotContain("PrivateKey", json);
            Assert.DoesNotContain("private_key", json);
            Assert.DoesNotContain("refresh_token", json);
            Assert.DoesNotContain("access_token", json);
            Assert.DoesNotContain("password", json);
            Assert.DoesNotContain("Authorization", json);
        }
    }

    [Fact]
    public async Task Diagnostics_records_command_and_code()
    {
        var (router, backend) = Create();

        await router.HandleAsync(Req("app.info"), default);
        await router.HandleAsync(Req("nope"), default);

        var events = backend.Ring.Snapshot();
        Assert.Equal(2, events.Count);
        Assert.Equal(("app.info", "ok"), (events[0].Command, events[0].Code));
        Assert.Equal("unknown_command", events[1].Code);
    }

    private sealed class ThrowingBackend : FakeBackend
    {
        public Exception? Failure { get; init; }

        public override Task<ProfileView> IssueProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
            Failure is ApiException api
                ? Task.FromException<ProfileView>(api)
                : Failure is not null
                    ? Task.FromException<ProfileView>(Failure)
                    : base.IssueProfileAsync(deviceId, serverId, ct);
    }
}
```

Строка глубокого JSON синтаксически корректна: корень и вложенные объекты `args → a → … → g` дают девять уровней, а лимит — восемь, поэтому `bad_args` обязан прийти от проверки глубины, а не от синтаксиса. Если поменять строку на невалидную, тест продолжит быть зелёным по коду, но перестанет проверять именно лимит глубины.

- [ ] **Step 3: Запустить, увидеть падение**

Run: `dotnet test client/NovaVpn.Client.sln --filter BridgeRouterTests`
Expected: проекты не собираются — нет `BridgeRouter`, `IBridgeBackend`, `FakeBackend` не реализует интерфейс.

- [ ] **Step 4: Реализовать контракты**

`client/src/NovaVpn.Client.App/Bridge/BridgeContracts.cs`:

```csharp
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Diagnostics;

namespace NovaVpn.Client.App.Bridge;

public sealed record AppInfoView(string Version, string Platform, string WebView, string Mode);

public sealed record SettingsView(string? ApiBaseUrl, int WindowWidth, int WindowHeight);

public sealed record SessionStateView(bool SignedIn, string? Email, string? ApiBaseUrl, string? StartupError);

public sealed record DevicesView(IReadOnlyList<DeviceView> Devices, Guid? CurrentDeviceId);

public sealed record ExportResult(bool Saved, bool Cancelled, string? FileName, DateTimeOffset? SavedAt);

public sealed record DiagnosticsView(string Version, IReadOnlyList<DiagnosticEvent> Events);
```

`client/src/NovaVpn.Client.App/Bridge/IBridgeBackend.cs`:

```csharp
using NovaVpn.Client.Core.Api;

namespace NovaVpn.Client.App.Bridge;

public interface IBridgeBackend
{
    Task<AppInfoView> GetAppInfoAsync(CancellationToken ct);
    SettingsView GetSettings();
    Task<SettingsView> SetSettingsAsync(string apiBaseUrl, CancellationToken ct);
    Task<SessionStateView> GetSessionStateAsync(CancellationToken ct);
    Task<MeView> GetAccountAsync(CancellationToken ct);
    Task<MeView> LoginAsync(string email, string password, CancellationToken ct);
    Task<MeView> RegisterAsync(string email, string password, CancellationToken ct);
    Task LogoutAsync(CancellationToken ct);
    Task<DevicesView> ListDevicesAsync(CancellationToken ct);
    Task<DeviceView> CreateDeviceAsync(string name, CancellationToken ct);
    Task DeleteDeviceAsync(Guid deviceId, CancellationToken ct);
    Task<IReadOnlyList<ServerView>> ListServersAsync(CancellationToken ct);
    Task<IReadOnlyList<ProfileView>> ListProfilesAsync(Guid deviceId, CancellationToken ct);
    Task<ProfileView> IssueProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct);
    Task RevokeProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct);
    Task<ExportResult> ExportProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct);
    Task<DiagnosticsView> GetDiagnosticsAsync(CancellationToken ct);
}
```

- [ ] **Step 5: Реализовать роутер**

`client/src/NovaVpn.Client.App/Bridge/BridgeRouter.cs`:

```csharp
using System.Text;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Diagnostics;

namespace NovaVpn.Client.App.Bridge;

public sealed class BridgeRouter
{
    public const int MaxMessageBytes = 64 * 1024;
    public const int MaxDepth = 8;

    private static readonly HashSet<string> Commands = new(StringComparer.Ordinal)
    {
        "app.info", "settings.get", "settings.set", "session.state", "account.get",
        "auth.login", "auth.register", "auth.logout",
        "devices.list", "devices.create", "devices.delete",
        "servers.list", "profiles.list", "profiles.issue", "profiles.revoke", "profiles.export",
        "diagnostics.get",
    };

    private readonly IBridgeBackend _backend;
    private readonly DiagnosticRing _ring;
    private readonly ClientLog? _log;

    public BridgeRouter(IBridgeBackend backend, DiagnosticRing ring, ClientLog? log = null)
    {
        _backend = backend;
        _ring = ring;
        _log = log;
    }

    public async Task<string> HandleAsync(string json, CancellationToken ct)
    {
        if (Encoding.UTF8.GetByteCount(json) > MaxMessageBytes)
            return Fail(null, "bad_args", "Сообщение слишком велико.", null, "oversized");

        string? id = null;
        string command = "unknown";
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = MaxDepth });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return Fail(null, "bad_args", "Ожидался объект запроса.", null, command);

            id = OptionalId(root);
            if (id is null)
                return Fail(null, "bad_args", "В запросе нет корректного id.", null, command);

            command = root.TryGetProperty("command", out var c) && c.ValueKind == JsonValueKind.String
                ? c.GetString() ?? ""
                : "";
            if (!Commands.Contains(command))
            {
                _ring.Add(command, ClientErrorCodes.UnknownCommand, null);
                return Fail(id, ClientErrorCodes.UnknownCommand, "Неизвестная команда.", null, command);
            }

            var args = root.TryGetProperty("args", out var a) && a.ValueKind == JsonValueKind.Object
                ? a
                : default;
            var data = await DispatchAsync(command, args, ct);
            _ring.Add(command, "ok", null);
            return JsonSerializer.Serialize(new BridgeOk(id, true, data), JsonDefaults.Options);
        }
        catch (CommandArgumentException ex)
        {
            _ring.Add(command, ClientErrorCodes.BadArgs, null);
            return Fail(id, ClientErrorCodes.BadArgs, ex.Message, null, command);
        }
        catch (ApiException ex)
        {
            _ring.Add(command, ex.Code, ex.RequestId);
            return Fail(id, ex.Code, MessageFor(ex), ex.RequestId, command);
        }
        catch (JsonException)
        {
            _ring.Add(command, ClientErrorCodes.BadArgs, null);
            return Fail(id, ClientErrorCodes.BadArgs, "Некорректный JSON.", null, command);
        }
        catch (OperationCanceledException)
        {
            _ring.Add(command, "network", null);
            return Fail(id, ClientErrorCodes.Network, "Операция прервана.", null, command);
        }
        catch (Exception)
        {
            _ring.Add(command, "internal", null);
            return Fail(id, "internal", "Внутренняя ошибка клиента.", null, command);
        }
    }

    private Task<object?> DispatchAsync(string command, JsonElement args, CancellationToken ct) =>
        command switch
        {
            "app.info" => AsObject(_backend.GetAppInfoAsync(ct)),
            "settings.get" => Task.FromResult<object?>(_backend.GetSettings()),
            "settings.set" => AsObject(_backend.SetSettingsAsync(
                RequireString(args, "api_base_url", 1, 2048), ct)),
            "session.state" => AsObject(_backend.GetSessionStateAsync(ct)),
            "account.get" => AsObject(_backend.GetAccountAsync(ct)),
            "auth.login" => AsObject(_backend.LoginAsync(
                RequireString(args, "email", 1, 254),
                RequireString(args, "password", 10, 1024), ct)),
            "auth.register" => AsObject(_backend.RegisterAsync(
                RequireString(args, "email", 1, 254),
                RequireString(args, "password", 10, 1024), ct)),
            "auth.logout" => AsEmpty(_backend.LogoutAsync(ct)),
            "devices.list" => AsObject(_backend.ListDevicesAsync(ct)),
            "devices.create" => AsObject(_backend.CreateDeviceAsync(
                RequireString(args, "name", 1, 64).Trim(), ct)),
            "devices.delete" => AsEmpty(_backend.DeleteDeviceAsync(
                RequireGuid(args, "device_id"), ct)),
            "servers.list" => AsObject(_backend.ListServersAsync(ct)),
            "profiles.list" => AsObject(_backend.ListProfilesAsync(
                RequireGuid(args, "device_id"), ct)),
            "profiles.issue" => AsObject(_backend.IssueProfileAsync(
                RequireGuid(args, "device_id"), RequireGuid(args, "server_id"), ct)),
            "profiles.revoke" => AsEmpty(_backend.RevokeProfileAsync(
                RequireGuid(args, "device_id"), RequireGuid(args, "server_id"), ct)),
            "profiles.export" => AsObject(_backend.ExportProfileAsync(
                RequireGuid(args, "device_id"), RequireGuid(args, "server_id"), ct)),
            "diagnostics.get" => AsObject(_backend.GetDiagnosticsAsync(ct)),
            _ => throw new CommandArgumentException("Неизвестная команда."),
        };

    private static async Task<object?> AsObject<T>(Task<T> task) => await task;
    private static async Task<object?> AsEmpty(Task task) { await task; return null; }

    private static string? OptionalId(JsonElement root)
    {
        if (!root.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String) return null;
        var value = id.GetString() ?? "";
        return value.Length is > 0 and <= 64 ? value : null;
    }

    private static string RequireString(JsonElement args, string name, int min, int max)
    {
        if (args.ValueKind != JsonValueKind.Object
            || !args.TryGetProperty(name, out var p)
            || p.ValueKind != JsonValueKind.String)
            throw new CommandArgumentException($"Поле {name} обязательно.");
        var value = p.GetString() ?? "";
        if (value.Length < min || value.Length > max)
            throw new CommandArgumentException($"Поле {name} имеет недопустимую длину.");
        return value;
    }

    private static Guid RequireGuid(JsonElement args, string name)
    {
        var raw = RequireString(args, name, 36, 36);
        return Guid.TryParse(raw, out var value)
            ? value
            : throw new CommandArgumentException($"Поле {name} должно быть UUID.");
    }

    private string Fail(string? id, string code, string message, string? requestId, string command)
    {
        _log?.Write($"{DateTimeOffset.UtcNow:O} {command} {code} {requestId ?? "-"}");
        return JsonSerializer.Serialize(new BridgeFail(id, false, null,
            new BridgeError(code, message, requestId)), JsonDefaults.Options);
    }

    private static string MessageFor(ApiException ex)
    {
        if (ex.StatusCode == 0 && ex.Code is ClientErrorCodes.BadArgs or ClientErrorCodes.Network
            or ClientErrorCodes.Timeout or ClientErrorCodes.StorageCorrupted)
            return ex.Message;

        return ex.Code switch
        {
            "invalid_request" => "Проверьте введённые данные.",
            "unauthenticated" => "Сессия истекла. Войдите заново.",
            "invalid_credentials" => "Неверный email или пароль.",
            "refresh_token_invalid" => "Сессия недействительна. Войдите заново.",
            "email_taken" => "Этот email уже зарегистрирован.",
            "account_locked" => "Аккаунт заблокирован администратором.",
            "forbidden" => "Действие запрещено: нет активного плана или устройство отозвано.",
            "not_found" => "Не найдено.",
            "conflict" => ConflictMessage(ex),
            "device_limit_reached" => "Достигнут лимит устройств. Отзовите другое устройство.",
            "duplicate_device" => "Устройство уже зарегистрировано.",
            "idempotency_key_conflict" => "Операция изменилась, начните заново.",
            "idempotency_key_in_progress" => "Операция уже выполняется. Повторите через несколько секунд.",
            "server_not_available" => "Сервер сейчас не принимает новые профили.",
            "rate_limited" => ex.RetryAfter is { } r
                ? $"Слишком часто. Повторите через {Math.Ceiling(r.TotalSeconds)} с."
                : "Слишком часто. Повторите позже.",
            "internal" => "Внутренняя ошибка API.",
            "network" => "Нет связи с API.",
            "timeout" => "Истекло время ожидания ответа API.",
            "storage_corrupted" => "Хранилище повреждено или принадлежит другому пользователю. Войдите заново.",
            _ => "Ошибка операции.",
        };
    }

    private static string ConflictMessage(ApiException ex) =>
        (ex.DetailString("reason"), ex.DetailString("status")) switch
        {
            ("pool_exhausted", _) => "На этом сервере не осталось свободных адресов.",
            ("address_race", _) => "Выдача не состоялась из-за параллельного запроса, повторите.",
            (_, { } status) => $"Профиль уже в состоянии «{status}».",
            _ => "Конфликт состояния.",
        };

    private sealed record BridgeOk(string Id, bool Ok, object? Data);
    private sealed record BridgeFail(string? Id, bool Ok, object? Data, BridgeError Error);
    private sealed record BridgeError(string Code, string Message, string? RequestId);

    private sealed class CommandArgumentException(string message) : Exception(message);
}
```

`CommandArgumentException` использует первичный конструктор C# 12; целевая платформа — .NET 10, ограничений нет.

- [ ] **Step 6: Прогнать тесты**

```bash
dotnet test client/NovaVpn.Client.sln --filter BridgeRouterTests
```

Expected: `Failed: 0`. Если тест глубины падает, сверьте вложенность литерала: она должна давать ровно девять уровней при лимите восемь.

- [ ] **Step 7: Коммит**

```bash
git add client
git commit -m "feat(client): контракты моста и белый список команд без секретов"
```

---

### Task 8: Сервисный слой приложения, экспорт, окно и WebView2

> **Принято при исполнении** (решение контроллера в журнале SDD):
> - в `Microsoft.Web.WebView2` 1.0.4370.26 нет события `ConsoleMessageReceived` и типа `CoreWebView2ConsoleMessageLevel`; консольные ошибки снимаются событиями DevTools-протокола (`Runtime.enable`, приёмники `Runtime.consoleAPICalled` с `type == "error"` и `Runtime.exceptionThrown`), предел 20 записей и обрезка 300 символов сохраняются;
> - в `AppServices.cs` нужен `using NovaVpn.Client.Core;` — там объявлена `ClientVersion`;
> - после `dotnet restore ... -r win-x64 --force-evaluate` повторяется `dotnet restore client/NovaVpn.Client.sln --locked-mode`, чтобы шаг CI не сломался от RID-секций lock-файлов;
> - `ExportProfileAsync` сверяет известную локальную личность с `deviceId` сразу, отдаёт `conflict` по состоянию профиля до получения конфигра и до пикера, а личность требует непосредственно перед получением конфига — этого требует тест про неактивный профиль, который не вызывает `devices.list`;
> - в `client/Directory.Build.props` объявлен `<RuntimeIdentifiers>win-x64</RuntimeIdentifiers>`: без него restore в режиме locked без RID расходится с RID-секциями lock-файлов (NU1004) и ломает шаг CI;
> - фактические имена WebView2 — событие `DevToolsProtocolEventReceived` у приёмника и свойство `ParameterObjectAsJson` у аргументов;
> - `Program.cs` освобождает `AppServices` через `try/finally` и `DisposeAsync` (синхронный `using` даёт CS8418), а `MainForm.Silent` помечен `[DesignerSerializationVisibility(Hidden)]` из-за анализатора WFO1000 при `TreatWarningsAsErrors`;
> - в блоке тестов брифа восемь `[Fact]`, а не семь: весь набор 92 + 8 = 100.
>
> **Правки после ревью задачи 8** (решения контроллера в журнале SDD, раунд 1):
> - `MainForm.OnLoadAsync` ловит не три типа исключений, а любое: `OperationCanceledException` при закрытии окна гасится молча, `WebView2RuntimeNotFoundException` даёт текст про рантайм, `ApiException` — «Не удалось восстановить сессию», `IOException` и `UnauthorizedAccessException` — отказы данных, остальное — общий русский текст; во всех случаях заполняется `StartupFailure`, чтобы самопроверка задачи 10 получила отказ, а не падение .NET;
> - `new AppServices(...)` в `Program.cs` стоит внутри защищённого участка: отказ каталога данных показывается сообщением, а не необработанным исключением;
> - размер окна сохраняется из `RestoreBounds` для развёрнутого и свёрнутого окна;
> - журнал один на каталог (`AppServices.Log`), запись из наблюдателя API и из `BridgeRouter.Fail` не может подменить результат вызова;
> - `InitializeAsync` сбрасывает `StartupError` в начале;
> - девятый тест `Export_of_foreign_device_is_rejected_without_picker_or_config` закрепляет отказ чужому устройству; ожидание набора — 101.

**Files:**
- Create: `client/src/NovaVpn.Client.App/Host/AppServices.cs`
- Create: `client/src/NovaVpn.Client.App/Export/FileSavePicker.cs`
- Create: `client/src/NovaVpn.Client.App/Host/MainForm.cs`
- Create: `client/src/NovaVpn.Client.App/Program.cs`
- Create: `client/tests/NovaVpn.Client.App.Tests/TestSupport.cs`
- Create: `client/tests/NovaVpn.Client.App.Tests/AppServicesTests.cs`
- Modify: `client/src/NovaVpn.Client.App/NovaVpn.Client.App.csproj` (`OutputType=WinExe`, `InternalsVisibleTo`)
- Modify: `.github/workflows/ci.yml` (шаг publish)
- Modify: `client/**/packages.lock.json` (restore с RID)

**Interfaces:**
- Consumes: `IBridgeBackend`, `BridgeRouter`, `DiagnosticRing`, `ApiClient`, `SessionService`, `DeviceService`, `ProfileService`, `WireGuardConfig`, `ConfigExporter`, stores, `ClientLog`.
- Produces:
  - `IFileSavePicker` с `string? Ask(string suggestedFileName, string warning)`; `FileSavePicker : IFileSavePicker`.
  - `AppServices : IBridgeBackend, IAsyncDisposable`; публичные конструктор `(string dataDir, IFileSavePicker picker)`, `string DataDir`, `ClientSettings Settings`, `string? StartupError`, `string WebViewVersion { get; set; }`, `Task InitializeAsync(ct)`, `void SaveWindowSize(int w, int h)`; внутренний конструктор `(string dataDir, IFileSavePicker picker, HttpMessageHandler? apiHandler, TimeProvider? time, string hostName, string webViewVersion)`.
  - `MainForm(AppServices services)` с `internal bool Silent { get; init; }`, `internal TaskCompletionSource<CoreWebView2> Ready`, `internal Exception? StartupFailure`, `internal IReadOnlyList<string> ConsoleErrors`; `Program.Main`.

- [ ] **Step 1: Написать тестовую обвязку**

`client/tests/NovaVpn.Client.App.Tests/TestSupport.cs`:

```csharp
using System.Net;
using System.Text;

namespace NovaVpn.Client.App.Tests;

internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "novavpn-app-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); }
        catch (IOException) { }
    }
}

internal sealed record CapturedRequest(string Method, string Path,
    string? IdempotencyKey, string? Body);

internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, string?, int, HttpResponseMessage> _respond;
    private int _count;

    public StubHandler(Func<HttpRequestMessage, string?, int, HttpResponseMessage> respond) => _respond = respond;

    public List<CapturedRequest> Requests { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken ct)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        _count++;
        Requests.Add(new CapturedRequest(request.Method.Method, request.RequestUri!.PathAndQuery,
            request.Headers.TryGetValues("Idempotency-Key", out var v) ? v.Single() : null, body));
        return _respond(request, body, _count);
    }

    public static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Text(HttpStatusCode status, string text) =>
        new(status) { Content = new StringContent(text, Encoding.UTF8, "text/plain") };
}
```

- [ ] **Step 2: Написать падающие тесты сервисного слоя**

`client/tests/NovaVpn.Client.App.Tests/AppServicesTests.cs`:

```csharp
using System.Net;
using System.Text.Json;
using NovaVpn.Client.App.Export;
using NovaVpn.Client.App.Host;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Storage;
using static NovaVpn.Client.App.Tests.StubHandler;

namespace NovaVpn.Client.App.Tests;

public sealed class AppServicesTests
{
    private static readonly Uri Base = new("https://api.example/");
    private static readonly Guid DeviceId = Guid.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly Guid ServerId = Guid.Parse("33333333-3333-4333-8333-333333333333");
    private const string Password = "0123456789";
    private const string Warning =
        "В файле приватный ключ. Это секрет; не пересылайте файл и не храните его в общих папках.";

    private const string SessionJson =
        """{"access_token":"a1","refresh_token":"r1","token_type":"Bearer","access_expires_at":"2026-11-24T10:05:00Z","refresh_expires_at":"2026-12-24T10:00:00Z"}""";

    private static readonly string MeJson = JsonSerializer.Serialize(new
    {
        user = new { id = Guid.NewGuid(), email = "a@b.c", display_name = (string?)null,
            status = "active", locale = "ru", created_at = "2026-11-24T10:00:00Z" },
        plan = new { slug = "internal-default", device_limit = 3, traffic_quota_bytes = (long?)null },
        devices = new { live = 1, limit = 3 },
    });

    private static string ServerJson() => JsonSerializer.Serialize(new
    {
        id = ServerId, name = "ams-1", country_code = "NL", city = "Amsterdam",
        host = "203.0.113.1", port = 51820, mtu = 1420, latitude = 52.37, longitude = 4.89,
        availability = "available", latency_ms = (int?)null, load = (double?)null,
        capacity_mbps = (int?)null, provider = "demo", region = "eu-west",
    });

    private static string ProfileJson(string status = "active") => JsonSerializer.Serialize(new
    {
        id = Guid.NewGuid(), device_id = DeviceId, server_id = ServerId, address_v4 = "10.66.0.2",
        status, issued_at = "2026-11-24T10:00:00Z", expires_at = "2026-12-24T10:00:00Z",
        overlap_valid_until = (string?)null, revoked_at = (string?)null,
    });

    private static string DeviceJson(string publicKey) => JsonSerializer.Serialize(new
    {
        id = DeviceId, public_key = publicKey, platform = "windows", name = "test-pc",
        created_at = "2026-11-24T10:00:00Z", last_seen_at = (string?)null, revoked_at = (string?)null,
    });

    private const string ConfigText =
        "[Interface]\nAddress = 10.66.0.2/32\nDNS = 10.66.0.1\nMTU = 1420\n\n[Peer]\n" +
        "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
        "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.1:51820\nPersistentKeepalive = 25\n";

    private sealed class FakePicker : IFileSavePicker
    {
        public string? NextPath { get; set; }
        public string? ReceivedWarning { get; private set; }
        public string? SuggestedName { get; private set; }
        public int Calls { get; private set; }

        public string? Ask(string suggestedFileName, string warning)
        {
            Calls++;
            SuggestedName = suggestedFileName;
            ReceivedWarning = warning;
            return NextPath;
        }
    }

    private sealed class Env : IAsyncDisposable
    {
        public Env(StubHandler handler)
        {
            Dir = new TempDir();
            Handler = handler;
            Services = new AppServices(Dir.Path, Picker, handler, TimeProvider.System,
                "test-pc", "120.0.0.0");
        }

        public TempDir Dir { get; }
        public StubHandler Handler { get; }
        public FakePicker Picker { get; } = new();
        public AppServices Services { get; }

        public async ValueTask DisposeAsync()
        {
            await Services.DisposeAsync();
            Dir.Dispose();
        }
    }

    private static async Task<Env> SignedInAsync(
        Func<HttpRequestMessage, string?, int, HttpResponseMessage> extra)
    {
        var env = new Env(new StubHandler((req, body, n) => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => Json(HttpStatusCode.OK, SessionJson),
            "/api/v1/me" => Json(HttpStatusCode.OK, MeJson),
            _ => extra(req, body, n),
        }));
        await env.Services.SetSettingsAsync(Base.ToString(), default);
        await env.Services.LoginAsync("a@b.c", Password, default);
        return env;
    }

    private static Func<HttpRequestMessage, string?, int, HttpResponseMessage> WithRegisteredDevice()
    {
        var gets = 0;
        string? publicKey = null;

        HttpResponseMessage Create(string? body)
        {
            using var doc = JsonDocument.Parse(body!);
            publicKey = doc.RootElement.GetProperty("public_key").GetString();
            return Json(HttpStatusCode.Created, DeviceJson(publicKey!));
        }

        return (req, body, _) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path == "/api/v1/devices" && req.Method == HttpMethod.Get)
                return Json(HttpStatusCode.OK, ++gets == 1
                    ? """{"devices":[]}"""
                    : $$"""{"devices":[{{DeviceJson(publicKey!)}}]}""");
            if (path == "/api/v1/devices" && req.Method == HttpMethod.Post) return Create(body);
            if (path == "/api/v1/servers")
                return Json(HttpStatusCode.OK, $$"""{"servers":[{{ServerJson()}}]}""");
            if (path == $"/api/v1/devices/{DeviceId}/profiles")
                return Json(HttpStatusCode.OK, $$"""{"profiles":[{{ProfileJson()}}]}""");
            if (path == $"/api/v1/devices/{DeviceId}/profiles/{ServerId}/config")
                return Text(HttpStatusCode.OK, ConfigText);
            return Json(HttpStatusCode.NotFound,
                """{"error":{"code":"not_found","message":"m","request_id":"0000000000000001"}}""");
        };
    }

    [Fact]
    public async Task First_launch_has_no_api_url_and_no_session()
    {
        await using var env = new Env(new StubHandler((_, _, _) =>
            Json(HttpStatusCode.InternalServerError, "{}")));

        var state = await env.Services.GetSessionStateAsync(default);

        Assert.False(state.SignedIn);
        Assert.Null(state.ApiBaseUrl);
        Assert.Null(env.Services.GetSettings().ApiBaseUrl);
        Assert.Null(state.StartupError);
    }

    [Fact]
    public async Task Settings_reject_invalid_origin_and_changes_while_signed_in()
    {
        await using var env = new Env(new StubHandler((req, _, _) => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/login" => Json(HttpStatusCode.OK, SessionJson),
            "/api/v1/me" => Json(HttpStatusCode.OK, MeJson),
            _ => Json(HttpStatusCode.NotFound, "{}"),
        }));

        var insecure = await Assert.ThrowsAsync<ApiException>(() =>
            env.Services.SetSettingsAsync("http://example.com/", default));
        var withPath = await Assert.ThrowsAsync<ApiException>(() =>
            env.Services.SetSettingsAsync("https://api.example/v1", default));
        Assert.Equal("bad_args", insecure.Code);
        Assert.Equal("bad_args", withPath.Code);

        await env.Services.SetSettingsAsync(Base.ToString(), default);
        await env.Services.LoginAsync("a@b.c", Password, default);
        var change = await Assert.ThrowsAsync<ApiException>(() =>
            env.Services.SetSettingsAsync("https://other.example/", default));

        Assert.Equal("bad_args", change.Code);
        Assert.Contains("выйдите", change.Message);
        Assert.Equal(Base.ToString(), env.Services.GetSettings().ApiBaseUrl);
    }

    [Fact]
    public async Task Login_and_logout_manage_session_store()
    {
        await using var env = await SignedInAsync((_, _, _) => Json(HttpStatusCode.NotFound, "{}"));
        var store = new SessionStore(env.Dir.Path);

        var signedIn = await env.Services.GetSessionStateAsync(default);
        Assert.True(signedIn.SignedIn);
        Assert.Equal("a@b.c", signedIn.Email);
        Assert.True(store.Exists);

        await env.Services.LogoutAsync(default);

        var signedOut = await env.Services.GetSessionStateAsync(default);
        Assert.False(signedOut.SignedIn);
        Assert.False(store.Exists);
    }

    [Fact]
    public async Task Corrupt_session_store_is_reported_and_kept()
    {
        await using var env = new Env(new StubHandler((_, _, _) => Json(HttpStatusCode.NotFound, "{}")));
        await env.Services.SetSettingsAsync(Base.ToString(), default);
        File.WriteAllBytes(Path.Combine(env.Dir.Path, "session.dat"), new byte[] { 1, 2, 3 });

        await env.Services.InitializeAsync(default);

        var state = await env.Services.GetSessionStateAsync(default);
        Assert.False(state.SignedIn);
        Assert.Contains("Хранилище повреждено", state.StartupError);
        Assert.True(File.Exists(Path.Combine(env.Dir.Path, "session.dat")));
    }

    [Fact]
    public async Task Devices_list_auto_registers_current_device()
    {
        string? postedName = null;
        var inner = WithRegisteredDevice();
        await using var env = await SignedInAsync((req, body, n) =>
        {
            if (req.RequestUri!.AbsolutePath == "/api/v1/devices" && req.Method == HttpMethod.Post)
                postedName = JsonDocument.Parse(body!).RootElement.GetProperty("name").GetString();
            return inner(req, body, n);
        });

        var devices = await env.Services.ListDevicesAsync(default);

        Assert.Equal(DeviceId, devices.CurrentDeviceId);
        Assert.Single(devices.Devices);
        Assert.Equal("test-pc", postedName);
        Assert.Contains(env.Handler.Requests, r => r.Method == "POST" && r.IdempotencyKey is not null);
    }

    [Fact]
    public async Task Export_cancel_warns_and_writes_nothing()
    {
        await using var env = await SignedInAsync(WithRegisteredDevice());
        await env.Services.ListDevicesAsync(default);
        env.Picker.NextPath = null;

        var result = await env.Services.ExportProfileAsync(DeviceId, ServerId, default);

        Assert.True(result.Cancelled);
        Assert.False(result.Saved);
        Assert.Equal(Warning, env.Picker.ReceivedWarning);
        Assert.Equal("NovaVPN-ams-1.conf", env.Picker.SuggestedName);
    }

    [Fact]
    public async Task Export_writes_conf_with_key_and_keeps_text_out_of_result_and_log()
    {
        await using var env = await SignedInAsync(WithRegisteredDevice());
        await env.Services.ListDevicesAsync(default);
        var target = Path.Combine(env.Dir.Path, "out.conf");
        env.Picker.NextPath = target;

        var result = await env.Services.ExportProfileAsync(DeviceId, ServerId, default);

        Assert.True(result.Saved);
        Assert.False(result.Cancelled);
        Assert.Equal("out.conf", result.FileName);
        Assert.NotNull(result.SavedAt);
        var text = File.ReadAllText(target);
        Assert.StartsWith("[Interface]\nPrivateKey = ", text);
        Assert.EndsWith("PersistentKeepalive = 25\n", text);
        Assert.DoesNotContain("PrivateKey", JsonSerializer.Serialize(result));

        var logs = Directory.Exists(Path.Combine(env.Dir.Path, "logs"))
            ? string.Join("\n", Directory.GetFiles(Path.Combine(env.Dir.Path, "logs"))
                .Select(File.ReadAllText))
            : "";
        Assert.DoesNotContain("PrivateKey", logs);
        Assert.DoesNotContain(Password, logs);
        Assert.DoesNotContain("a@b.c", logs);
        Assert.DoesNotContain("eyJ", logs);
    }

    [Fact]
    public async Task Export_of_non_active_profile_is_conflict_and_never_opens_picker()
    {
        await using var env = await SignedInAsync((req, body, n) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path == "/api/v1/devices" && req.Method == HttpMethod.Get)
                return Json(HttpStatusCode.OK,
                    $$"""{"devices":[{{DeviceJson("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")}}]}""");
            if (path == "/api/v1/servers")
                return Json(HttpStatusCode.OK, $$"""{"servers":[{{ServerJson()}}]}""");
            if (path == $"/api/v1/devices/{DeviceId}/profiles")
                return Json(HttpStatusCode.OK, $$"""{"profiles":[{{ProfileJson("revoked")}}]}""");
            return Json(HttpStatusCode.NotFound, "{}");
        });
        env.Picker.NextPath = Path.Combine(env.Dir.Path, "never.conf");

        var ex = await Assert.ThrowsAsync<ApiException>(() =>
            env.Services.ExportProfileAsync(DeviceId, ServerId, default));

        Assert.Equal("conflict", ex.Code);
        Assert.Equal(0, env.Picker.Calls);
        Assert.False(File.Exists(Path.Combine(env.Dir.Path, "never.conf")));
        Assert.DoesNotContain(env.Handler.Requests, r => r.Path.EndsWith("/config"));
    }
}
```

Обработчики выше сравнивают `AbsolutePath` через `if`, а не `switch`, потому что путь содержит переменные `DeviceId`/`ServerId`: строковые шаблоны `switch` допускают только константы.

- [ ] **Step 3: Запустить, увидеть падение**

Run: `dotnet test client/NovaVpn.Client.sln --filter AppServicesTests`
Expected: `AppServices`, `IFileSavePicker` не существуют.

- [ ] **Step 4: Реализовать выбор файла**

`client/src/NovaVpn.Client.App/Export/FileSavePicker.cs`:

```csharp
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
```

- [ ] **Step 5: Реализовать `AppServices`**

`client/src/NovaVpn.Client.App/Host/AppServices.cs`:

```csharp
using System.Text.Json;
using NovaVpn.Client.App.Bridge;
using NovaVpn.Client.App.Export;
using NovaVpn.Client.Core;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Config;
using NovaVpn.Client.Core.Devices;
using NovaVpn.Client.Core.Diagnostics;
using NovaVpn.Client.Core.Profiles;
using NovaVpn.Client.Core.Storage;

namespace NovaVpn.Client.App.Host;

public sealed class AppServices : IBridgeBackend, IAsyncDisposable
{
    public const string ExportWarning =
        "В файле приватный ключ. Это секрет; не пересылайте файл и не храните его в общих папках.";

    private readonly IFileSavePicker _picker;
    private readonly HttpMessageHandler? _apiHandler;
    private readonly TimeProvider _time;
    private readonly string _hostName;
    private readonly ClientLog _log;
    private readonly SettingsStore _settingsStore;
    private readonly SessionStore _sessionStore;
    private readonly DeviceIdentityStore _identityStore;
    private ApiClient? _api;
    private SessionService? _session;
    private DeviceService? _devices;
    private ProfileService? _profiles;

    public AppServices(string dataDir, IFileSavePicker picker)
        : this(dataDir, picker, null, TimeProvider.System, Environment.MachineName, "не запущен") { }

    internal AppServices(string dataDir, IFileSavePicker picker, HttpMessageHandler? apiHandler,
        TimeProvider? time, string hostName, string webViewVersion)
    {
        DataDir = dataDir;
        _picker = picker;
        _apiHandler = apiHandler;
        _time = time ?? TimeProvider.System;
        _hostName = hostName;
        WebViewVersion = webViewVersion;
        Directory.CreateDirectory(dataDir);
        _log = new ClientLog(Path.Combine(dataDir, "logs"));
        _settingsStore = new SettingsStore(dataDir);
        _sessionStore = new SessionStore(dataDir);
        _identityStore = new DeviceIdentityStore(dataDir);
        Settings = _settingsStore.Load();
    }

    public string DataDir { get; }
    public ClientSettings Settings { get; private set; }
    public string? StartupError { get; private set; }
    public string WebViewVersion { get; set; }
    public DiagnosticRing Ring { get; } = new();

    public async Task InitializeAsync(CancellationToken ct)
    {
        if (Settings.ApiBaseUrl is null) return;
        Build(Settings.ApiBaseUrl);
        try
        {
            await _session!.TryRestoreAsync(ct);
        }
        catch (ApiException ex) when (ex.Code is ClientErrorCodes.Network or ClientErrorCodes.Timeout)
        {
            StartupError = "Нет связи с API.";
        }
        StartupError = _session!.StartupError ?? StartupError;
    }

    public Task<AppInfoView> GetAppInfoAsync(CancellationToken ct) =>
        Task.FromResult(new AppInfoView(ClientVersion.Value, "windows", WebViewVersion, "preview"));

    public SettingsView GetSettings() =>
        new(Settings.ApiBaseUrl?.ToString(), Settings.WindowWidth, Settings.WindowHeight);

    public async Task<SettingsView> SetSettingsAsync(string apiBaseUrl, CancellationToken ct)
    {
        if (_session?.Current is not null)
            throw new ApiException(ClientErrorCodes.BadArgs, 0, "Сначала выйдите из аккаунта.");
        if (!ApiBaseUrl.TryParse(apiBaseUrl, out var url, out var error))
            throw new ApiException(ClientErrorCodes.BadArgs, 0, error);

        Settings = Settings with { ApiBaseUrl = url };
        _settingsStore.Save(Settings);
        Build(url);
        StartupError = null;
        return await Task.FromResult(GetSettings());
    }

    public Task<SessionStateView> GetSessionStateAsync(CancellationToken ct) =>
        Task.FromResult(new SessionStateView(
            _session?.Current is not null,
            _session?.Current?.Email,
            Settings.ApiBaseUrl?.ToString(),
            StartupError));

    public Task<MeView> GetAccountAsync(CancellationToken ct) =>
        RequireSession().GetMeAsync(ct);

    public async Task<MeView> LoginAsync(string email, string password, CancellationToken ct)
    {
        var session = RequireSession();
        await session.LoginAsync(email, password, ct);
        var me = await session.GetMeAsync(ct);
        StartupError = null;
        ResetDevices();
        return me;
    }

    public async Task<MeView> RegisterAsync(string email, string password, CancellationToken ct)
    {
        var session = RequireSession();
        await session.RegisterAsync(email, password, ct);
        var me = await session.GetMeAsync(ct);
        StartupError = null;
        ResetDevices();
        return me;
    }

    public async Task LogoutAsync(CancellationToken ct)
    {
        var session = _session;
        if (session is null) return;
        await session.LogoutAsync(ct);
        ResetDevices();
    }

    public async Task<DevicesView> ListDevicesAsync(CancellationToken ct)
    {
        var session = RequireSession();
        var devices = _devices!;
        var current = await devices.EnsureRegisteredAsync(ct);
        var all = await session.AuthorizedAsync((t, c) => _api!.ListDevicesAsync(t, c), ct);
        return new DevicesView(all, current.Id);
    }

    public Task<DeviceView> CreateDeviceAsync(string name, CancellationToken ct) =>
        RequireDevices().CreateAsync(name, ct);

    public Task DeleteDeviceAsync(Guid deviceId, CancellationToken ct) =>
        RequireDevices().DeleteAsync(deviceId, ct);

    public Task<IReadOnlyList<ServerView>> ListServersAsync(CancellationToken ct) =>
        RequireProfiles().ListServersAsync(ct);

    public Task<IReadOnlyList<ProfileView>> ListProfilesAsync(Guid deviceId, CancellationToken ct) =>
        RequireProfiles().ListAsync(deviceId, ct);

    public Task<ProfileView> IssueProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        RequireProfiles().IssueAsync(deviceId, serverId, ct);

    public Task RevokeProfileAsync(Guid deviceId, Guid serverId, CancellationToken ct) =>
        RequireProfiles().RevokeAsync(deviceId, serverId, ct);

    public async Task<ExportResult> ExportProfileAsync(Guid deviceId, Guid serverId,
        CancellationToken ct)
    {
        var profiles = RequireProfiles();
        var identity = RequireDevices().CurrentIdentity
            ?? throw new ApiException(ClientErrorCodes.BadArgs, 0, "Сначала зарегистрируйте устройство.");
        if (identity.DeviceId != deviceId)
            throw new ApiException(ClientErrorCodes.BadArgs, 0,
                "Выбранное устройство не является текущим на этой установке.");

        var servers = await profiles.ListServersAsync(ct);
        var server = servers.FirstOrDefault(s => s.Id == serverId)
            ?? throw new ApiException("not_found", 404, "Сервер не найден.");
        var list = await profiles.ListAsync(deviceId, ct);
        var profile = list.FirstOrDefault(p => p.ServerId == serverId)
            ?? throw new ApiException("not_found", 404, "Профиль не выдан.");
        if (profile.Status != "active")
            throw new ApiException("conflict", 409, $"Профиль в состоянии «{profile.Status}».",
                StatusDetails(profile.Status));

        var serverText = await profiles.FetchConfigAsync(deviceId, serverId, ct);
        var composed = WireGuardConfig.Compose(serverText, identity.PrivateKey, identity.PublicKey);
        var suggested = ConfigExporter.DefaultFileName(server.Name);
        var path = _picker.Ask(suggested, ExportWarning);
        if (path is null) return new ExportResult(false, true, null, null);

        ConfigExporter.Write(path, composed);
        return new ExportResult(true, false, Path.GetFileName(path), _time.GetUtcNow());
    }

    public Task<DiagnosticsView> GetDiagnosticsAsync(CancellationToken ct) =>
        Task.FromResult(new DiagnosticsView(ClientVersion.Value, Ring.Snapshot()));

    public void SaveWindowSize(int width, int height)
    {
        Settings = Settings with { WindowWidth = width, WindowHeight = height };
        try { _settingsStore.Save(Settings); }
        catch (IOException) { }
    }

    public ValueTask DisposeAsync()
    {
        _api?.Dispose();
        return ValueTask.CompletedTask;
    }

    private void Build(Uri baseUrl)
    {
        _api?.Dispose();
        _api = new ApiClient(baseUrl, _apiHandler, observer: new LogObserver(_log));
        _session = new SessionService(_api, baseUrl, _sessionStore, _time);
        ResetDevices();
    }

    private void ResetDevices()
    {
        _devices = _api is null || _session is null
            ? null
            : new DeviceService(_api, _session, _identityStore, _hostName);
        _profiles = _api is null || _session is null
            ? null
            : new ProfileService(_api, _session);
    }

    private SessionService RequireSession() =>
        _session ?? throw new ApiException(ClientErrorCodes.BadArgs, 0, "Сначала укажите адрес API.");

    private DeviceService RequireDevices()
    {
        RequireSession();
        return _devices ?? throw new ApiException("unauthenticated", 401, "Сессия не открыта.");
    }

    private ProfileService RequireProfiles()
    {
        RequireSession();
        return _profiles ?? throw new ApiException("unauthenticated", 401, "Сессия не открыта.");
    }

    private static JsonElement StatusDetails(string status)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(new { status }));
        return doc.RootElement.Clone();
    }

    private sealed class LogObserver(ClientLog log) : IApiObserver
    {
        public void OnRequestCompleted(ApiCall call) =>
            log.Write($"{DateTimeOffset.UtcNow:O} {call.Method} {call.Path} {call.Status} " +
                      $"{call.RequestId ?? "-"} {call.Duration.TotalMilliseconds:F0}ms");
    }
}
```

`_hostName` уходит в `DeviceService`: тест `Devices_list_auto_registers` проверяет, что `name` в теле POST равен `test-pc`. Если поле перестанет использоваться после любой правки этого кода, конструктор `DeviceService` перестанет его принимать и тест упадёт по имени устройства — мёртвое поле не спрячется.

- [ ] **Step 6: Прогнать тесты сервисного слоя**

```bash
dotnet test client/NovaVpn.Client.sln --filter AppServicesTests
```

Expected: `Failed: 0`, 7 тестов.

- [ ] **Step 7: Переключить проект в WinExe и добавить окно**

В `NovaVpn.Client.App.csproj` заменить `<OutputType>Library</OutputType>` на `<OutputType>WinExe</OutputType>` и добавить:

```xml
<ItemGroup>
  <InternalsVisibleTo Include="NovaVpn.Client.App.Tests" />
</ItemGroup>
```

`client/src/NovaVpn.Client.App/Host/MainForm.cs`:

```csharp
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using NovaVpn.Client.App.Bridge;
using NovaVpn.Client.Core;
using NovaVpn.Client.Core.Diagnostics;

namespace NovaVpn.Client.App.Host;

public sealed class MainForm : Form
{
    private const string Origin = "https://app.novavpn.local";
    private readonly AppServices _services;
    private readonly WebView2 _webView = new() { Dock = DockStyle.Fill };
    private readonly BridgeRouter _router;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<string> _consoleErrors = new();

    internal IReadOnlyList<string> ConsoleErrors => _consoleErrors;
    internal CoreWebView2? Core => _webView.CoreWebView2;
    internal TaskCompletionSource<CoreWebView2> Ready { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Exception? StartupFailure { get; private set; }
    internal bool Silent { get; init; }

    public MainForm(AppServices services)
    {
        _services = services;
        _router = new BridgeRouter(services, services.Ring,
            new ClientLog(Path.Combine(services.DataDir, "logs")));
        Text = $"NovaVPN {ClientVersion.Value}";
        Width = Math.Max(services.Settings.WindowWidth, 720);
        Height = Math.Max(services.Settings.WindowHeight, 600);
        MinimumSize = new Size(720, 600);
        StartPosition = FormStartPosition.CenterScreen;
        Controls.Add(_webView);
        Load += OnLoadAsync;
        FormClosing += OnFormClosing;
    }

    private async void OnLoadAsync(object? sender, EventArgs e)
    {
        try
        {
            await _services.InitializeAsync(_shutdown.Token);
            var uiDir = Path.Combine(AppContext.BaseDirectory, "ui");
            if (!File.Exists(Path.Combine(uiDir, "index.html")))
            {
                Fail("Не найдены файлы интерфейса (ui/index.html).");
                return;
            }

            var userData = Path.Combine(_services.DataDir, "webview");
            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: userData);
            await _webView.EnsureCoreWebView2Async(environment);
            var core = _webView.CoreWebView2;
            _services.WebViewVersion = CoreWebView2Environment.GetAvailableBrowserVersionString() ?? "неизвестна";

            core.Settings.IsWebMessageEnabled = true;
            core.Settings.AreHostObjectsAllowed = false;
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;

            core.SetVirtualHostNameToFolderMapping("app.novavpn.local", uiDir,
                CoreWebView2HostResourceAccessKind.DenyCors);
            core.NavigationStarting += OnNavigationStarting;
            core.NewWindowRequested += OnNewWindowRequested;
            core.WebMessageReceived += OnWebMessageReceived;
            await AttachConsoleCaptureAsync(core);
            core.Navigate(Origin + "/index.html");
            Ready.TrySetResult(core);
        }
        catch (Exception ex) when (ex is WebView2RuntimeNotFoundException or InvalidOperationException
                                       or IOException)
        {
            Fail(
                "Не найден WebView2 Runtime. Установите его и запустите NovaVPN снова.\n" +
                "https://developer.microsoft.com/microsoft-edge/webview2/",
                ex);
        }
    }

    private void Fail(string message, Exception? error = null)
    {
        StartupFailure = error ?? new InvalidOperationException(message);
        if (Silent)
        {
            Ready.TrySetException(StartupFailure);
            Console.Error.WriteLine("nova: " + message);
        }
        else
        {
            MessageBox.Show(message, "NovaVPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        Close();
    }

    private void OnNavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (!e.Uri.StartsWith(Origin + "/", StringComparison.Ordinal))
            e.Cancel = true;
    }

    private void OnNewWindowRequested(object? sender, CoreWebView2NewWindowRequestedEventArgs e)
    {
        e.Handled = true;
        if (!Uri.TryCreate(e.Uri, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            return;
        try
        {
            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception)
        {
            // Внешний браузер недоступен; ссылка останется в справке текстом.
        }
    }

    private async void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        string json;
        try { json = e.WebMessageAsJson; }
        catch (InvalidOperationException) { return; }

        await _gate.WaitAsync();
        try
        {
            var response = await _router.HandleAsync(json, _shutdown.Token);
            _webView.CoreWebView2?.PostWebMessageAsJson(response);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
        {
            // Окно закрывается: ответить уже некому.
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task AttachConsoleCaptureAsync(CoreWebView2 core)
    {
        // В этой версии пакета нет события ConsoleMessageReceived:
        // консольные ошибки снимаются событиями DevTools-протокола.
        var runtime = core.GetDevToolsProtocolEventReceiver("Runtime.consoleAPICalled");
        runtime.Received += (_, e) =>
        {
            using var doc = JsonDocument.Parse(e.WebMessageAsJson);
            if (doc.RootElement.TryGetProperty("type", out var type) &&
                type.ValueKind == JsonValueKind.String && type.GetString() == "error")
                AddConsoleError(DescribeConsoleEvent(doc.RootElement));
        };
        var exceptions = core.GetDevToolsProtocolEventReceiver("Runtime.exceptionThrown");
        exceptions.Received += (_, e) =>
        {
            using var doc = JsonDocument.Parse(e.WebMessageAsJson);
            AddConsoleError(DescribeConsoleEvent(doc.RootElement));
        };
        await core.CallDevToolsProtocolMethodAsync("Runtime.enable", "{}");
    }

    private static string DescribeConsoleEvent(JsonElement root)
    {
        if (root.TryGetProperty("exceptionDetails", out var details) &&
            details.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String)
            return text.GetString()!;
        if (root.TryGetProperty("args", out var args) && args.ValueKind == JsonValueKind.Array)
        {
            var parts = new List<string>();
            foreach (var arg in args.EnumerateArray())
            {
                if (arg.TryGetProperty("value", out var value)) parts.Add(value.ToString());
                else if (arg.TryGetProperty("description", out var d) && d.ValueKind == JsonValueKind.String)
                    parts.Add(d.GetString()!);
            }
            if (parts.Count > 0) return string.Join(' ', parts);
        }
        return root.GetRawText();
    }

    private void AddConsoleError(string message)
    {
        var line = message.Length > 300 ? message[..300] : message;
        if (_consoleErrors.Count < 20) _consoleErrors.Add(line);
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        _shutdown.Cancel();
        _services.SaveWindowSize(Width, Height);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _shutdown.Dispose();
            _gate.Dispose();
            _webView.Dispose();
        }
        base.Dispose(disposing);
    }
}
```

Роутер получает кольцо из `AppServices.Ring`, поэтому `diagnostics.get` видит те же команды, что выполнял мост.

`client/src/NovaVpn.Client.App/Program.cs`:

```csharp
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
        using var services = new AppServices(dataDir, new FileSavePicker());
        using var form = new MainForm(services);
        Application.Run(form);
    }
}
```

- [ ] **Step 8: Собрать, прогнать все тесты, добавить publish в CI**

```bash
dotnet restore client/NovaVpn.Client.sln -r win-x64 --force-evaluate
dotnet build client/NovaVpn.Client.sln -c Release
dotnet test client/NovaVpn.Client.sln -c Release --no-build
dotnet publish client/src/NovaVpn.Client.App -c Release -r win-x64 --self-contained false -o client/dist/win-x64
```

Expected: сборка — 0 ошибок; тесты — `Failed: 0`; publish создаёт `client/dist/win-x64/NovaVpn.Client.App.exe` и каталог `ui/`.

В `.github/workflows/ci.yml` в джобу `windows-client` после шага Test:

```yaml
      - name: Publish
        run: >
          dotnet publish client/src/NovaVpn.Client.App -c Release -r win-x64
          --self-contained false -p:RestoreLockedMode=true -o client/dist/win-x64
```

```bash
make actionlint
```

- [ ] **Step 9: Коммит**

```bash
git add client .github/workflows/ci.yml
git commit -m "feat(client): сервисный слой, экспорт .conf и окно WebView2"
```

---

### Task 9: Экраны, стили, шрифты и заглушка моста

> **Правка после реализации задачи 9** (решение контроллера в журнале SDD):
> - в блоке `app.js` брифа вызов после успешного входа — `renderAll()`, а не `renderHome()`: функции `renderHome` в брифе нет, вызов давал `ReferenceError` сразу после входа и ломал главный экран и требование «консоль без error»; исполнитель заменил ровно одну строку;
> - браузерная проверка Step 10 выполнена на заглушке через Playwright MCP: ширины 1440/900/720/360 без горизонтального вылета, сценарии входа, каталога, выдачи и экспорта; кадры сняты в светлой теме, тёмную снимать в задаче 12.
>
> **Правки после ревью задачи 9** (решения контроллера в журнале SDD, раунд 1):
> - контрактный тест дополняется фактом `Styles_use_only_local_fonts_and_assets`: читает `app.css`, требует ровно 8 `@font-face`, все `url("fonts/…")` указывают на существующие файлы, запрещает `http://`, `https://` и `@import` — внешний шрифт больше не проходит зелёным;
> - разбор команд расширяется до `(?:attempt|bridge\.send)\(\s*["']([a-z0-9._]+)["']` и `case\s+["']([a-z0-9._]+)["']\s*:` — подчёркивания, цифры и одинарные кавычки больше не слепые зоны;
> - белый список в тесте сверяется с ключами словаря `BridgeRouter.cs`, прочитанного из дерева; расхождение роутера и теста краснеет;
> - проверки inline-кода и `style=` принимают оба вида кавычек;
> - новый факт `Page_loads_local_script_and_styles` закрепляет `<link rel="stylesheet" href="app.css">` и `<script src="app.js" defer>`;
> - `help.html` говорит «Туннель не поднимает…», и эта фраза проверяется в `Honest_wording_is_present`;
> - в `app.js` ветка отказа `account.get` сбрасывает `session`, `me`, `devices` и `currentDeviceId` до показа экрана входа;
> - `serve-ui.mjs` отвечает 400 на некорректный процент в URL вместо падения процесса;
> - лицензия JetBrains Mono берётся из upstream-репозитория JetBrains, а не копия лицензии Inter; тест требует слово `JetBrains` в файле;
> - ожидание набора — 69 + 40 = 109.

**Files:**
- Create: `client/ui/index.html`
- Create: `client/ui/app.css`
- Create: `client/ui/app.js`
- Create: `client/ui/help.html`
- Create: `client/ui/fonts/*.woff2` (восемь файлов)
- Create: `client/ui/fonts/OFL-Inter.txt`
- Create: `client/ui/fonts/OFL-JetBrainsMono.txt`
- Create: `client/scripts/serve-ui.mjs`
- Create: `client/tests/NovaVpn.Client.App.Tests/UiContractTests.cs`

**Interfaces:**
- Consumes: команды моста из задачи 7 в snake_case: `app.info {version, platform, web_view, mode}`, `settings.get/set {api_base_url, window_width, window_height}`, `session.state {signed_in, email, api_base_url, startup_error}`, `account.get`, `auth.login/register {email, password}` → `MeView {user, plan, devices}`, `auth.logout`, `devices.list {devices, current_device_id}`, `devices.create {name}`, `devices.delete {device_id}`, `servers.list`, `profiles.list {device_id}`, `profiles.issue {device_id, server_id}` → `ProfileView`, `profiles.revoke {device_id, server_id}`, `profiles.export {device_id, server_id}` → `{saved, cancelled, file_name, saved_at}`, `diagnostics.get {version, events}`. Ошибка: `{ok:false, id, error:{code, message, request_id}}`.
- Produces: каталог `client/ui/` копируется в выход приложения правилом `Content` из задачи 7; `serve-ui.mjs` — временный статический сервер только для проверки; `UiContractTests` — статический контракт страниц (CSP, запрет inline-кода и сетевых API, белый список команд, шрифты).

- [ ] **Step 1: Написать падающие тесты контракта страниц**

`client/tests/NovaVpn.Client.App.Tests/UiContractTests.cs`:

```csharp
using System.Text.RegularExpressions;

namespace NovaVpn.Client.App.Tests;

public sealed class UiContractTests
{
    private const string Csp =
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; " +
        "img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'";

    private static readonly string UiDir = FindUi();

    private static string FindUi()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "client", "ui");
            if (File.Exists(Path.Combine(candidate, "index.html"))) return candidate;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Каталог client/ui не найден выше каталога тестов.");
    }

    private static string Read(string name) => File.ReadAllText(Path.Combine(UiDir, name));

    [Theory]
    [InlineData("index.html")]
    [InlineData("help.html")]
    public void Page_declares_exact_csp_and_no_inline_code(string name)
    {
        var html = Read(name);

        Assert.Contains($"content=\"{Csp}\"", html);
        Assert.DoesNotMatch(@"<script(?![^>]*\ssrc=)", html);
        Assert.DoesNotMatch(@"<style", html);
        Assert.DoesNotMatch(@"\sstyle=""", html);
        Assert.DoesNotMatch(@"\son[a-z]+=""", html);
        Assert.DoesNotMatch(@"<(?:script|link)[^>]+https?://", html);
    }

    [Fact]
    public void Scripts_avoid_html_injection_storage_and_network()
    {
        var js = Read("app.js");

        foreach (var banned in new[]
                 {
                     "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                     "eval(", "new Function", "fetch(", "XMLHttpRequest", "WebSocket",
                     "localStorage", "sessionStorage", "navigator.clipboard", "import(",
                 })
            Assert.DoesNotContain(banned, js);
    }

    [Fact]
    public void Every_command_in_script_is_whitelisted()
    {
        var js = Read("app.js");
        var whitelist = new HashSet<string>(StringComparer.Ordinal)
        {
            "app.info", "settings.get", "settings.set", "session.state", "account.get",
            "auth.login", "auth.register", "auth.logout",
            "devices.list", "devices.create", "devices.delete",
            "servers.list", "profiles.list", "profiles.issue", "profiles.revoke",
            "profiles.export", "diagnostics.get",
        };

        var attempted = Regex.Matches(js, "attempt\\(\"([a-z.]+)\"")
            .Select(m => m.Groups[1].Value);
        var stubCases = Regex.Matches(js, "case \"([a-z.]+)\":")
            .Select(m => m.Groups[1].Value);
        var used = attempted.Concat(stubCases).ToHashSet(StringComparer.Ordinal);

        Assert.Subset(whitelist, used);
        Assert.Contains("account.get", used);
        Assert.Contains("auth.register", used);
        Assert.Contains("profiles.export", used);
    }

    [Fact]
    public void Honest_wording_is_present()
    {
        var js = Read("app.js");
        var html = Read("index.html");

        Assert.Contains("не измерялось", js);
        Assert.Contains("не заявлена", js);
        Assert.Contains("без квоты", js);
        Assert.Contains("активного плана нет", js);
        Assert.Contains("Демонстрационные данные (заглушка моста)", html);
        Assert.Contains("туннель не поднимает", html);
    }

    [Fact]
    public void Fonts_and_licenses_are_packed_locally()
    {
        var fonts = new[]
        {
            "inter-latin-400-normal.woff2", "inter-cyrillic-400-normal.woff2",
            "inter-latin-500-normal.woff2", "inter-cyrillic-500-normal.woff2",
            "inter-latin-600-normal.woff2", "inter-cyrillic-600-normal.woff2",
            "jetbrains-mono-latin-400-normal.woff2", "jetbrains-mono-cyrillic-400-normal.woff2",
        };

        foreach (var font in fonts)
        {
            var file = new FileInfo(Path.Combine(UiDir, "fonts", font));
            Assert.True(file.Exists, $"нет шрифта {font}");
            Assert.True(file.Length > 5000, $"шрифт {font} подозрительно мал");
        }

        Assert.Contains("SIL OPEN FONT LICENSE",
            File.ReadAllText(Path.Combine(UiDir, "fonts", "OFL-Inter.txt")));
        Assert.Contains("SIL OPEN FONT LICENSE",
            File.ReadAllText(Path.Combine(UiDir, "fonts", "OFL-JetBrainsMono.txt")));
        Assert.Contains("wireguard.com/install", Read("help.html"));
        Assert.Contains("rel=\"noopener\"", Read("help.html"));
    }
}
```

- [ ] **Step 2: Убедиться, что тесты красные**

```bash
dotnet test client/NovaVpn.Client.sln --filter UiContractTests
```

Expected: падение с `DirectoryNotFoundException`/`InvalidOperationException` — `client/ui` ещё нет. Это красное состояние теста, а не ошибка настройки.

- [ ] **Step 3: Скачать шрифты и лицензии в `client/ui/fonts`**

```bash
mkdir -p client/ui/fonts
inter=https://cdn.jsdelivr.net/npm/@fontsource/inter@5.2.5/files
jbm=https://cdn.jsdelivr.net/npm/@fontsource/jetbrains-mono@5.2.5/files
for weight in 400 500 600; do
  for subset in latin cyrillic; do
    curl -fsSL "$inter/inter-$subset-$weight-normal.woff2" \
      -o "client/ui/fonts/inter-$subset-$weight-normal.woff2"
  done
done
for subset in latin cyrillic; do
  curl -fsSL "$jbm/jetbrains-mono-$subset-400-normal.woff2" \
    -o "client/ui/fonts/jetbrains-mono-$subset-400-normal.woff2"
done
curl -fsSL https://cdn.jsdelivr.net/npm/@fontsource/inter@5.2.5/LICENSE \
  -o client/ui/fonts/OFL-Inter.txt
curl -fsSL https://cdn.jsdelivr.net/npm/@fontsource/jetbrains-mono@5.2.5/LICENSE \
  -o client/ui/fonts/OFL-JetBrainsMono.txt
find client/ui/fonts -type f -printf '%f %s\n' | sort
```

Expected: десять файлов; каждый `.woff2` больше 5000 байт, лицензии — больше 1000. Если `curl` вернул ошибку, проверьте имя файла в пакете: Fontsource 5.2.5 публикует именно `inter-<subset>-<weight>-normal.woff2`. Не подменяйте файлы заглушками — тест ловит размер.

- [ ] **Step 4: Добавить временный статический сервер для проверки UI**

`client/scripts/serve-ui.mjs`:

```js
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve, sep } from "node:path";

const root = resolve(process.argv[2] ?? "client/ui");
const port = Number(process.argv[3] ?? 4173);
const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

createServer(async (request, response) => {
  const path = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  const file = normalize(join(root, path === "/" ? "index.html" : path));
  if (!file.startsWith(root + sep)) {
    response.writeHead(403);
    response.end("forbidden");
    return;
  }
  try {
    const body = await readFile(file);
    response.writeHead(200, { "content-type": types[extname(file)] ?? "application/octet-stream" });
    response.end(body);
  } catch {
    response.writeHead(404);
    response.end("not found");
  }
}).listen(port, "127.0.0.1", () => {
  console.log(`ui: http://127.0.0.1:${port}/?stub=1`);
});
```

Сервер нужен только для ручной и браузерной проверки; в продукт он не входит и приложение его не запускает. Удалять не нужно: им же снимаются кадры для инструкции в задаче 12.

- [ ] **Step 5: Написать `index.html`**

`client/ui/index.html` — разметка без inline-кода: вся логика в `app.js`, все стили в `app.css`.

```html
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NovaVPN — менеджер доступа</title>
<link rel="icon" href="data:,">
<link rel="stylesheet" href="app.css">
<script src="app.js" defer></script>
</head>
<body>
<p class="banner banner-warning" id="stub-banner" role="status" hidden>Демонстрационные данные (заглушка моста)</p>
<header class="topbar">
  <div class="brand">
    <span class="brand-name">NovaVPN</span>
    <span class="badge badge-muted" id="version-badge">—</span>
  </div>
  <nav class="nav" id="nav" aria-label="Экраны" hidden>
    <button type="button" class="nav-btn" data-action="screen" data-screen="home">Главный</button>
    <button type="button" class="nav-btn" data-action="screen" data-screen="catalog">Каталог</button>
    <button type="button" class="nav-btn" data-action="screen" data-screen="settings">Настройки</button>
    <button type="button" class="nav-btn" data-action="screen" data-screen="diagnostics">Диагностика</button>
    <a class="nav-btn" href="help.html">Справка</a>
  </nav>
</header>
<main class="app">
  <p class="banner banner-danger" id="startup-error" role="alert" hidden></p>

  <section class="screen" id="screen-auth" hidden>
    <h1>Подключение к API</h1>
    <p class="muted">NovaVPN — менеджер доступа: приложение выдаёт профиль и файл .conf, туннель не поднимает. Туннель поднимает официальный клиент WireGuard из импортированного файла.</p>
    <article class="card">
      <h2>Адрес API</h2>
      <label class="field">
        <span>Адрес</span>
        <input id="auth-origin" type="url" autocomplete="off" spellcheck="false" maxlength="2048" placeholder="https://api.example.com">
      </label>
      <p class="hint" id="auth-origin-hint"></p>
      <button type="button" class="btn btn-primary" data-action="save-origin">Сохранить адрес</button>
    </article>
    <article class="card" id="auth-credentials" hidden>
      <h2>Вход и регистрация</h2>
      <label class="field">
        <span>Email</span>
        <input id="auth-email" type="email" autocomplete="username" spellcheck="false" maxlength="254">
      </label>
      <label class="field">
        <span>Пароль</span>
        <input id="auth-password" type="password" autocomplete="current-password" maxlength="1024">
      </label>
      <p class="hint">Пароль от 10 до 1024 символов. Пароль не сохраняется и не журналируется.</p>
      <div class="buttons">
        <button type="button" class="btn btn-primary" data-action="login">Войти</button>
        <button type="button" class="btn" data-action="register">Зарегистрироваться</button>
      </div>
    </article>
    <p class="hint"><a class="link" href="help.html">Справка: импорт .conf в официальный WireGuard</a></p>
  </section>

  <section class="screen" id="screen-home" hidden>
    <h1>Главный</h1>
    <div class="columns">
      <article class="card">
        <h2>Аккаунт</h2>
        <dl class="facts">
          <dt>Email</dt><dd id="account-email">—</dd>
          <dt>Статус</dt><dd id="account-status">—</dd>
          <dt>План</dt><dd id="account-plan">—</dd>
          <dt>Устройства</dt><dd id="account-devices">—</dd>
          <dt>Трафик</dt><dd id="account-quota">—</dd>
        </dl>
        <p class="banner banner-warning" id="account-warning" hidden></p>
      </article>
      <article class="card">
        <h2>Устройство</h2>
        <ul class="list" id="device-list"></ul>
        <label class="field">
          <span>Имя нового устройства</span>
          <input id="device-name" type="text" maxlength="64" placeholder="Windows">
        </label>
        <div class="buttons">
          <button type="button" class="btn btn-primary" data-action="create-device">Создать устройство</button>
          <button type="button" class="btn btn-danger" data-action="forget-device" hidden>Забыть это устройство</button>
        </div>
        <p class="hint">Пересоздание отзывает текущее устройство: его профили и сохранённые .conf перестанут работать.</p>
      </article>
    </div>
    <article class="card">
      <h2>Профили доступа</h2>
      <ul class="list" id="profile-list"></ul>
      <div class="issue-row">
        <label class="field">
          <span>Сервер</span>
          <select id="issue-select"></select>
        </label>
        <button type="button" class="btn btn-primary" data-action="issue" id="issue-button">Выдать профиль</button>
      </div>
      <p class="hint" id="issue-hint"></p>
      <p class="hint">Конфиг не показывается в приложении: выберите «Сохранить .conf» и импортируйте файл в официальный WireGuard.</p>
    </article>
  </section>

  <section class="screen" id="screen-catalog" hidden>
    <h1>Каталог серверов</h1>
    <p class="muted">Доступность показана буквально: «доступен» или «неизвестно». Незамеренные показатели — «не измерялось» и «не заявлена», а не ноль.</p>
    <p class="muted" id="catalog-empty" hidden>Каталог пуст.</p>
    <div class="columns" id="catalog-list"></div>
  </section>

  <section class="screen" id="screen-settings" hidden>
    <h1>Настройки</h1>
    <article class="card">
      <h2>Адрес API</h2>
      <label class="field">
        <span>Адрес</span>
        <input id="settings-origin" type="url" autocomplete="off" spellcheck="false" maxlength="2048">
      </label>
      <p class="hint" id="settings-hint"></p>
      <button type="button" class="btn btn-primary" data-action="save-settings" id="settings-save">Сохранить</button>
    </article>
    <article class="card">
      <h2>Устройство и сессия</h2>
      <p class="muted">Ключ устройства хранится локально под защитой DPAPI и переживает выход из аккаунта, чтобы не тратить лимит устройств.</p>
      <div class="buttons">
        <button type="button" class="btn btn-danger" data-action="forget-device" hidden>Забыть это устройство</button>
        <button type="button" class="btn" data-action="logout" id="logout" hidden>Выйти из аккаунта</button>
      </div>
    </article>
    <article class="card">
      <h2>О приложении</h2>
      <dl class="facts">
        <dt>Версия</dt><dd id="settings-version">—</dd>
        <dt>Режим</dt><dd>preview: без туннеля и без фоновых служб</dd>
      </dl>
    </article>
  </section>

  <section class="screen" id="screen-diagnostics" hidden>
    <h1>Диагностика</h1>
    <p class="muted">Последние команды моста без тел запросов и секретов. Версия: <span id="diagnostics-version">—</span>.</p>
    <button type="button" class="btn" data-action="refresh-diagnostics">Обновить</button>
    <p class="muted" id="diagnostics-empty" hidden>Событий пока нет.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Время</th><th>Команда</th><th>Код</th><th>request_id</th></tr></thead>
        <tbody id="diagnostics-body"></tbody>
      </table>
    </div>
  </section>
</main>
<p class="toast" id="toast" role="status" aria-live="polite" hidden></p>
<div class="busy" id="busy" role="status" hidden>Загрузка…</div>
</body>
</html>
```

- [ ] **Step 6: Написать `app.css`**

`client/ui/app.css` — токены дизайн-системы из `docs/guide/guide.css`, локальные шрифты, тёмная и светлая темы, без inline-стилей.

```css
@font-face {
  font-family: Inter;
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url("fonts/inter-latin-400-normal.woff2") format("woff2");
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
@font-face {
  font-family: Inter;
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url("fonts/inter-cyrillic-400-normal.woff2") format("woff2");
  unicode-range: U+0301, U+0400-045F, U+0490-0491, U+04B0-04B1, U+2116;
}
@font-face {
  font-family: Inter;
  font-style: normal;
  font-weight: 500;
  font-display: swap;
  src: url("fonts/inter-latin-500-normal.woff2") format("woff2");
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
@font-face {
  font-family: Inter;
  font-style: normal;
  font-weight: 500;
  font-display: swap;
  src: url("fonts/inter-cyrillic-500-normal.woff2") format("woff2");
  unicode-range: U+0301, U+0400-045F, U+0490-0491, U+04B0-04B1, U+2116;
}
@font-face {
  font-family: Inter;
  font-style: normal;
  font-weight: 600;
  font-display: swap;
  src: url("fonts/inter-latin-600-normal.woff2") format("woff2");
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
@font-face {
  font-family: Inter;
  font-style: normal;
  font-weight: 600;
  font-display: swap;
  src: url("fonts/inter-cyrillic-600-normal.woff2") format("woff2");
  unicode-range: U+0301, U+0400-045F, U+0490-0491, U+04B0-04B1, U+2116;
}
@font-face {
  font-family: "JetBrains Mono";
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url("fonts/jetbrains-mono-latin-400-normal.woff2") format("woff2");
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
@font-face {
  font-family: "JetBrains Mono";
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url("fonts/jetbrains-mono-cyrillic-400-normal.woff2") format("woff2");
  unicode-range: U+0301, U+0400-045F, U+0490-0491, U+04B0-04B1, U+2116;
}

:root {
  color-scheme: dark;
  --nv-bg: #0A0E1A;
  --nv-surface-1: #121828;
  --nv-surface-2: #1A2135;
  --nv-border: #232B3F;
  --nv-input-border: #5B6B94;
  --nv-text-1: #F3F5FA;
  --nv-text-2: #A6B0C3;
  --nv-text-muted: #7C86A3;
  --nv-accent: #5180F4;
  --nv-accent-strong: #3D66CE;
  --nv-accent-soft: rgba(81, 128, 244, .10);
  --nv-success: #34D399;
  --nv-warning: #FBBF24;
  --nv-danger: #F87171;
  --nv-success-soft: rgba(52, 211, 153, .12);
  --nv-warning-soft: rgba(251, 191, 36, .12);
  --nv-danger-soft: rgba(248, 113, 113, .12);
  --nv-radius-s: 6px;
  --nv-radius-m: 10px;
  --nv-radius-l: 14px;
  --nv-shadow-card: 0 1px 2px rgba(0, 0, 0, .4);
}

@media (prefers-color-scheme: light) {
  :root {
    color-scheme: light;
    --nv-bg: #F6F8FC;
    --nv-surface-1: #FFFFFF;
    --nv-surface-2: #EFF2F8;
    --nv-border: #DCE2EE;
    --nv-input-border: #7F8CA8;
    --nv-text-1: #131A29;
    --nv-text-2: #47536B;
    --nv-text-muted: #647084;
    --nv-accent: #3D66CE;
    --nv-accent-strong: #2F55B8;
    --nv-accent-soft: rgba(61, 102, 206, .10);
    --nv-success: #047857;
    --nv-warning: #92400E;
    --nv-danger: #B91C1C;
    --nv-success-soft: rgba(4, 120, 87, .12);
    --nv-warning-soft: rgba(146, 64, 14, .12);
    --nv-danger-soft: rgba(185, 28, 28, .12);
    --nv-shadow-card: 0 1px 2px rgba(19, 26, 41, .06);
  }
}

* { box-sizing: border-box; }
[hidden] { display: none !important; }

body {
  margin: 0;
  background: var(--nv-bg);
  color: var(--nv-text-1);
  font: 400 15px/23px Inter, "Segoe UI", system-ui, sans-serif;
  -webkit-font-smoothing: antialiased;
}

a { color: var(--nv-accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.link { color: var(--nv-accent); }
.mono, code {
  font-family: "JetBrains Mono", Consolas, monospace;
  font-size: 13px;
  line-height: 20px;
  overflow-wrap: anywhere;
}
.muted { color: var(--nv-text-2); }
.hint { margin: 8px 0 0; color: var(--nv-text-muted); font-size: 13px; line-height: 20px; }
:focus-visible { outline: 2px solid var(--nv-accent); outline-offset: 2px; }

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  padding: 12px 24px;
  border-bottom: 1px solid var(--nv-border);
  background: var(--nv-surface-1);
}
.brand { display: flex; align-items: center; gap: 10px; font-weight: 600; }
.brand-name { font-size: 15px; line-height: 22px; }
.nav { display: flex; gap: 4px; flex-wrap: wrap; }
.nav-btn {
  padding: 7px 12px;
  border: 0;
  border-radius: var(--nv-radius-s);
  background: transparent;
  color: var(--nv-text-2);
  font: 500 13px/18px Inter, "Segoe UI", system-ui, sans-serif;
  cursor: pointer;
}
.nav-btn:hover { background: var(--nv-surface-2); color: var(--nv-text-1); text-decoration: none; }
.nav-btn[aria-current="page"] { background: var(--nv-accent-soft); color: var(--nv-text-1); }

.app { max-width: 1080px; margin: 0 auto; padding: 24px 24px 72px; }
.screen > h1 { margin: 0 0 12px; font-size: 26px; line-height: 34px; letter-spacing: -.01em; }
.screen > .muted { margin: 0 0 16px; max-width: 760px; }
.card {
  margin: 0 0 16px;
  padding: 18px;
  border: 1px solid var(--nv-border);
  border-radius: var(--nv-radius-m);
  background: var(--nv-surface-1);
  box-shadow: var(--nv-shadow-card);
}
.card h2 { margin: 0 0 12px; font-size: 17px; line-height: 24px; }
.columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; align-items: start; }
.columns > .card { margin: 0; }
.columns + .card { margin-top: 16px; }

.facts { display: grid; grid-template-columns: minmax(96px, auto) minmax(0, 1fr); gap: 6px 16px; margin: 0; }
.facts dt { color: var(--nv-text-muted); font-size: 13px; line-height: 20px; }
.facts dd { margin: 0; font-size: 14px; line-height: 20px; overflow-wrap: anywhere; }

.field { display: block; margin: 0 0 12px; }
.field > span { display: block; margin-bottom: 6px; color: var(--nv-text-2); font-size: 13px; line-height: 18px; }
input, select {
  width: 100%;
  min-height: 38px;
  padding: 8px 12px;
  border: 1px solid var(--nv-input-border);
  border-radius: var(--nv-radius-s);
  background: var(--nv-surface-2);
  color: var(--nv-text-1);
  font: 400 14px/20px Inter, "Segoe UI", system-ui, sans-serif;
}
input:disabled, select:disabled { opacity: .6; cursor: not-allowed; }

.buttons { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.btn {
  min-height: 36px;
  padding: 7px 14px;
  border: 1px solid var(--nv-border);
  border-radius: var(--nv-radius-s);
  background: var(--nv-surface-2);
  color: var(--nv-text-1);
  font: 500 13px/20px Inter, "Segoe UI", system-ui, sans-serif;
  cursor: pointer;
}
.btn:hover { border-color: var(--nv-input-border); }
.btn:disabled { opacity: .55; cursor: not-allowed; }
.btn-primary { border-color: transparent; background: var(--nv-accent-strong); color: #FFFFFF; }
.btn-primary:hover { background: var(--nv-accent); border-color: transparent; }
.btn-danger { border-color: color-mix(in srgb, var(--nv-danger) 40%, var(--nv-border)); background: var(--nv-danger-soft); color: var(--nv-danger); }

.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 9px;
  border: 1px solid var(--nv-border);
  border-radius: 999px;
  background: var(--nv-surface-1);
  color: var(--nv-text-2);
  font-size: 12px;
  line-height: 18px;
  font-weight: 500;
}
.badge-ok { border-color: color-mix(in srgb, var(--nv-success) 45%, var(--nv-border)); background: var(--nv-success-soft); color: var(--nv-text-1); }
.badge-warn { border-color: color-mix(in srgb, var(--nv-warning) 45%, var(--nv-border)); background: var(--nv-warning-soft); color: var(--nv-text-1); }
.badge-danger { border-color: color-mix(in srgb, var(--nv-danger) 45%, var(--nv-border)); background: var(--nv-danger-soft); color: var(--nv-text-1); }
.badge-muted { color: var(--nv-text-2); }

.list { margin: 0 0 12px; padding: 0; list-style: none; }
.row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  padding: 10px 0;
  border-bottom: 1px solid var(--nv-border);
}
.row:last-child { border-bottom: 0; }
.row-main { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; min-width: 0; }
.row-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.row .muted { font-size: 13px; line-height: 20px; }

.issue-row { display: flex; align-items: flex-end; gap: 12px; flex-wrap: wrap; }
.issue-row .field { flex: 1 1 240px; margin-bottom: 0; }

.banner { margin: 0 0 16px; padding: 10px 14px; border-radius: var(--nv-radius-s); font-size: 14px; line-height: 21px; }
.banner-warning { border: 1px solid color-mix(in srgb, var(--nv-warning) 45%, var(--nv-border)); background: var(--nv-warning-soft); color: var(--nv-text-1); }
.banner-danger { border: 1px solid color-mix(in srgb, var(--nv-danger) 45%, var(--nv-border)); background: var(--nv-danger-soft); color: var(--nv-text-1); }
#stub-banner { margin: 0; border-radius: 0; text-align: center; }

.table-wrap { margin-top: 12px; overflow-x: auto; border: 1px solid var(--nv-border); border-radius: var(--nv-radius-m); }
table { width: 100%; border-collapse: collapse; font-size: 13px; line-height: 20px; }
th, td { padding: 8px 12px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--nv-border); }
th { background: var(--nv-surface-2); color: var(--nv-text-2); font-weight: 600; font-size: 11px; letter-spacing: .05em; text-transform: uppercase; }
tr:last-child td { border-bottom: 0; }
td { color: var(--nv-text-2); overflow-wrap: anywhere; }

.toast {
  position: fixed;
  left: 24px;
  bottom: 24px;
  max-width: min(560px, calc(100vw - 48px));
  margin: 0;
  padding: 10px 14px;
  border: 1px solid var(--nv-border);
  border-radius: var(--nv-radius-s);
  background: var(--nv-surface-1);
  color: var(--nv-text-1);
  font-size: 14px;
  line-height: 21px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, .35);
  z-index: 20;
}
.toast-ok { border-color: color-mix(in srgb, var(--nv-success) 45%, var(--nv-border)); }
.toast-error { border-color: color-mix(in srgb, var(--nv-danger) 45%, var(--nv-border)); }

.busy {
  position: fixed;
  right: 24px;
  bottom: 24px;
  padding: 6px 12px;
  border: 1px solid var(--nv-border);
  border-radius: 999px;
  background: var(--nv-surface-2);
  color: var(--nv-text-2);
  font-size: 12px;
  line-height: 18px;
  z-index: 20;
}

@media (max-width: 980px) {
  .columns { grid-template-columns: minmax(0, 1fr); }
}

@media (max-width: 720px) {
  .topbar { padding: 10px 16px; }
  .app { padding: 20px 16px 64px; }
  .card { padding: 14px; }
  .toast { left: 16px; right: 16px; bottom: 16px; max-width: none; }
}
```

- [ ] **Step 7: Написать `app.js`**

`client/ui/app.js` — один мост, одно состояние, отрисовка через `textContent`; HTML не собирается строками, сеть из UI не вызывается.

```js
"use strict";

const stubMode = new URLSearchParams(location.search).get("stub") === "1";
const native = window.chrome && window.chrome.webview;
const bridge = native && !stubMode ? liveBridge(native) : stubBridge();

const state = {
  screen: null,
  appInfo: null,
  settings: null,
  session: null,
  me: null,
  devices: null,
  servers: [],
  profiles: [],
  diagnostics: null,
  currentDeviceId: null,
};

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function setText(id, text) {
  const node = $(id);
  if (node) node.textContent = text;
}

function setHiddenFor(action, hidden) {
  for (const node of document.querySelectorAll(`[data-action="${action}"]`)) node.hidden = hidden;
}

function fmtDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function fmtQuota(bytes) {
  if (bytes === null || bytes === undefined) return "без квоты";
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + " ГиБ";
  if (bytes >= 1048576) return Math.round(bytes / 1048576) + " МиБ";
  return bytes + " Б";
}

function profileStatus(status) {
  return {
    active: "активен",
    revoked: "отозван",
    expired: "истёк",
    replaced: "заменён",
  }[status] || status;
}

function profileStatusClass(status) {
  if (status === "active") return "badge badge-ok";
  if (status === "revoked" || status === "expired" || status === "replaced") return "badge badge-danger";
  return "badge badge-muted";
}

function availability(status) {
  if (status === "available") return "доступен";
  if (status === "unknown") return "неизвестно";
  return status;
}

function latency(value) {
  return value === null || value === undefined ? "не измерялось" : value + " мс";
}

function loadText(value) {
  return value === null || value === undefined ? "не заявлена" : "нагрузка " + value;
}

function capacity(value) {
  return value === null || value === undefined ? "не заявлена" : value + " Мбит/с";
}

function toast(message, kind) {
  const node = $("toast");
  node.textContent = message;
  node.className = "toast toast-" + (kind || "info");
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { node.hidden = true; }, 6000);
}

function toastError(error) {
  const parts = [error.message || "Ошибка операции.", "код: " + (error.code || "internal")];
  if (error.requestId) parts.push("request_id: " + error.requestId);
  toast(parts.join(" · "), "error");
}

function liveBridge(webview) {
  let sequence = 0;
  const pending = new Map();
  webview.addEventListener("message", (event) => {
    const message = event.data;
    if (!message || typeof message.id !== "string") return;
    const entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id);
    clearTimeout(entry.timer);
    if (message.ok) {
      entry.resolve(message.data);
      return;
    }
    const error = message.error || {};
    entry.reject({
      code: error.code || "internal",
      message: error.message || "Ошибка операции.",
      requestId: error.request_id || null,
    });
  });
  return {
    mode: "live",
    send(command, args) {
      const id = "r" + (++sequence);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject({ code: "timeout", message: "Истекло время ожидания ответа приложения.", requestId: null });
        }, 60000);
        pending.set(id, { resolve, reject, timer });
        webview.postMessage({ id, command, args: args || {} });
      });
    },
  };
}

function stubBridge() {
  const device = {
    id: "22222222-2222-4222-8222-222222222222",
    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    platform: "windows",
    name: "DEMO-WS",
    created_at: "2026-11-24T10:00:00Z",
    last_seen_at: null,
    revoked_at: null,
  };
  const servers = [
    {
      id: "33333333-3333-4333-8333-333333333333", name: "ams-1", country_code: "NL", city: "Амстердам",
      host: "203.0.113.10", port: 51820, mtu: 1420, latitude: 52.37, longitude: 4.89,
      availability: "available", latency_ms: null, load: null, capacity_mbps: null,
      provider: "demo", region: "eu-west",
    },
    {
      id: "44444444-4444-4444-8444-444444444444", name: "fra-2", country_code: "DE", city: "Франкфурт",
      host: "203.0.113.11", port: 51820, mtu: 1420, latitude: 50.11, longitude: 8.68,
      availability: "unknown", latency_ms: null, load: null, capacity_mbps: null,
      provider: "demo", region: "eu-central",
    },
  ];
  const events = [];
  let apiBaseUrl = "https://api.novavpn.test/";
  let email = null;
  let profiles = [];
  const note = (command, code) => events.unshift({
    time: new Date().toISOString(), command, code, request_id: null,
  });
  const fail = (code, message) => Promise.reject({ code, message, requestId: null });
  const me = () => ({
    user: {
      id: "11111111-1111-4111-8111-111111111111", email: email || "demo@novavpn.test",
      display_name: null, status: "active", locale: "ru", created_at: "2026-11-24T09:00:00Z",
    },
    plan: { slug: "internal-default", device_limit: 3, traffic_quota_bytes: null },
    devices: { live: 1, limit: 3 },
  });
  return {
    mode: "stub",
    send(command, args) {
      note(command, "ok");
      switch (command) {
        case "app.info":
          return Promise.resolve({ version: "0.1.0-preview", platform: "windows", web_view: "заглушка", mode: "stub" });
        case "settings.get":
          return Promise.resolve({ api_base_url: apiBaseUrl, window_width: 900, window_height: 700 });
        case "settings.set":
          apiBaseUrl = args.api_base_url;
          return Promise.resolve({ api_base_url: apiBaseUrl, window_width: 900, window_height: 700 });
        case "session.state":
          return Promise.resolve({ signed_in: email !== null, email, api_base_url: apiBaseUrl, startup_error: null });
        case "account.get":
          return email ? Promise.resolve(me()) : fail("unauthenticated", "Сессия не открыта.");
        case "auth.login":
        case "auth.register":
          email = String(args.email);
          return Promise.resolve(me());
        case "auth.logout":
          email = null;
          return Promise.resolve(null);
        case "devices.list":
          return Promise.resolve({ devices: [device], current_device_id: device.id });
        case "devices.create":
          return Promise.resolve(device);
        case "devices.delete":
          return Promise.resolve(null);
        case "servers.list":
          return Promise.resolve(servers);
        case "profiles.list":
          return Promise.resolve(profiles);
        case "profiles.issue": {
          const profile = {
            id: "55555555-5555-4555-8555-555555555555", device_id: device.id, server_id: args.server_id,
            address_v4: "10.66.0.2", status: "active",
            issued_at: "2026-11-24T12:00:00Z", expires_at: "2026-12-24T12:00:00Z",
            overlap_valid_until: null, revoked_at: null,
          };
          profiles = profiles.filter((p) => p.server_id !== args.server_id).concat(profile);
          return Promise.resolve(profile);
        }
        case "profiles.revoke":
          profiles = profiles.map((p) => p.server_id === args.server_id
            ? { ...p, status: "revoked", revoked_at: "2026-11-24T13:00:00Z" }
            : p);
          return Promise.resolve(null);
        case "profiles.export":
          return Promise.resolve({ saved: true, cancelled: false, file_name: "NovaVPN-ams-1.conf", saved_at: "2026-11-24T13:10:00Z" });
        case "diagnostics.get":
          return Promise.resolve({ version: "0.1.0-preview", events: events.slice(0, 20) });
        default:
          return fail("unknown_command", "Неизвестная команда.");
      }
    },
  };
}

let busyCount = 0;

function setBusy(on) {
  busyCount += on ? 1 : -1;
  if (busyCount < 0) busyCount = 0;
  $("busy").hidden = busyCount === 0;
}

async function attempt(command, args) {
  setBusy(true);
  try {
    return { ok: true, data: await bridge.send(command, args) };
  } catch (error) {
    if (error && typeof error === "object") toastError(error);
    return { ok: false, error };
  } finally {
    setBusy(false);
  }
}

function showScreen(name) {
  state.screen = name;
  for (const section of document.querySelectorAll(".screen")) {
    section.hidden = section.id !== "screen-" + name;
  }
  const signedIn = Boolean(state.session && state.session.signed_in);
  $("nav").hidden = !signedIn;
  for (const button of document.querySelectorAll("#nav [data-screen]")) {
    if (button.dataset.screen === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  if (name === "home") renderHome();
  if (name === "catalog") renderCatalog();
  if (name === "settings") renderSettings();
  if (name === "diagnostics") void refreshDiagnostics();
  if (name === "auth") renderAuth();
}

function renderAuth() {
  const origin = state.settings ? state.settings.api_base_url : null;
  $("auth-origin").value = origin || "";
  $("auth-credentials").hidden = !origin;
  setText("auth-origin-hint", origin
    ? "Адрес сохранён: " + origin + ". Сменить его можно только до входа."
    : "https:// для любого хоста, http:// — только для 127.0.0.1, localhost или [::1].");
}

function renderAll() {
  renderAccount();
  renderDevices();
  renderProfiles();
  renderCatalog();
}

function renderAccount() {
  const me = state.me;
  if (!me) return;
  setText("account-email", me.user.email);
  setText("account-status", me.user.status === "active" ? "активен" : me.user.status);
  setText("account-plan", me.plan ? me.plan.slug : "активного плана нет");
  setText("account-devices", me.devices.live + " из " + me.devices.limit);
  setText("account-quota", me.plan ? fmtQuota(me.plan.traffic_quota_bytes) : "—");
  const warning = $("account-warning");
  if (me.plan) {
    warning.hidden = true;
    warning.textContent = "";
  } else {
    warning.textContent = "Активного плана нет: выдача профилей недоступна.";
    warning.hidden = false;
  }
}

function renderDevices() {
  const list = $("device-list");
  list.replaceChildren();
  const devices = state.devices ? state.devices.devices : [];
  if (devices.length === 0) {
    list.append(el("li", "row muted", "На аккаунте нет устройств."));
  } else {
    for (const device of devices) {
      const row = el("li", "row");
      const main = el("div", "row-main");
      main.append(el("strong", null, device.name));
      const status = device.revoked_at
        ? "отозвано"
        : device.id === state.currentDeviceId ? "это устройство" : "активно";
      main.append(el("span", device.revoked_at ? "badge badge-danger" : "badge badge-ok", status));
      main.append(el("span", "muted mono", device.id));
      row.append(main);
      row.append(el("span", "muted", "создано " + fmtDate(device.created_at)));
      list.append(row);
    }
  }
  setHiddenFor("forget-device", !state.currentDeviceId);
}

function renderProfiles() {
  const list = $("profile-list");
  list.replaceChildren();
  const select = $("issue-select");
  const issueButton = $("issue-button");
  const hint = $("issue-hint");

  if (!state.currentDeviceId) {
    list.append(el("li", "row muted", "Сначала создайте устройство."));
    select.replaceChildren();
    select.disabled = true;
    issueButton.disabled = true;
    setText("issue-hint", "");
    return;
  }

  if (state.profiles.length === 0) {
    list.append(el("li", "row muted", "Профиль не выдан."));
  }
  for (const profile of state.profiles) {
    const server = state.servers.find((s) => s.id === profile.server_id);
    const row = el("li", "row");
    const main = el("div", "row-main");
    main.append(el("strong", null, server ? server.name : profile.server_id));
    main.append(el("span", profileStatusClass(profile.status), profileStatus(profile.status)));
    main.append(el("span", "mono", profile.address_v4));
    main.append(el("span", "muted",
      "выдан " + fmtDate(profile.issued_at) + " · действует до " + fmtDate(profile.expires_at)));
    row.append(main);
    if (profile.status === "active") {
      const actions = el("div", "row-actions");
      const save = el("button", "btn btn-primary", "Сохранить .conf");
      save.type = "button";
      save.dataset.action = "export";
      save.dataset.server = profile.server_id;
      const revoke = el("button", "btn btn-danger", "Отозвать");
      revoke.type = "button";
      revoke.dataset.action = "revoke";
      revoke.dataset.server = profile.server_id;
      actions.append(save, revoke);
      row.append(actions);
    }
    list.append(row);
  }

  const taken = new Set(state.profiles.filter((p) => p.status !== "revoked").map((p) => p.server_id));
  const options = state.servers.filter((s) => !taken.has(s.id));
  select.replaceChildren();
  for (const server of options) {
    const option = el("option", null,
      server.name + " · " + server.city + " · " + availability(server.availability));
    option.value = server.id;
    select.append(option);
  }
  const hasPlan = Boolean(state.me && state.me.plan);
  const canIssue = options.length > 0 && hasPlan;
  select.disabled = !canIssue;
  issueButton.disabled = !canIssue;
  setText("issue-hint", canIssue
    ? ""
    : hasPlan ? "Нет доступных серверов для выдачи." : "Активного плана нет: выдача профилей недоступна.");
}

function renderCatalog() {
  const list = $("catalog-list");
  list.replaceChildren();
  $("catalog-empty").hidden = state.servers.length !== 0;
  for (const server of state.servers) {
    const card = el("article", "card");
    const head = el("div", "row-main");
    head.append(el("h2", null, server.name));
    head.append(el("span",
      server.availability === "available" ? "badge badge-ok" : "badge badge-muted",
      availability(server.availability)));
    card.append(head);
    card.append(el("p", "muted", server.country_code + " · " + server.city + " · " + server.host + ":" + server.port));
    card.append(el("p", "muted",
      "Задержка: " + latency(server.latency_ms) + " · " + loadText(server.load) + " · " + capacity(server.capacity_mbps)));
    card.append(el("p", "muted", "Провайдер: " + server.provider + " · регион: " + server.region));
    const button = el("button", "btn btn-primary", "Выдать профиль");
    button.type = "button";
    button.dataset.action = "issue";
    button.dataset.server = server.id;
    button.disabled = !state.currentDeviceId || !(state.me && state.me.plan);
    card.append(button);
    list.append(card);
  }
}

function renderSettings() {
  const signedIn = Boolean(state.session && state.session.signed_in);
  $("settings-origin").value = state.settings && state.settings.api_base_url ? state.settings.api_base_url : "";
  $("settings-origin").disabled = signedIn;
  $("settings-save").disabled = signedIn;
  setText("settings-hint", signedIn ? "Чтобы изменить адрес API, выйдите из аккаунта." : "");
  setText("settings-version", state.appInfo
    ? state.appInfo.version + " · " + state.appInfo.platform + " · WebView2 " + state.appInfo.web_view
    : "—");
  setHiddenFor("forget-device", !state.currentDeviceId);
  $("logout").hidden = !signedIn;
}

async function refreshDiagnostics() {
  const result = await attempt("diagnostics.get");
  if (!result.ok) return;
  state.diagnostics = result.data;
  const body = $("diagnostics-body");
  body.replaceChildren();
  $("diagnostics-empty").hidden = result.data.events.length !== 0;
  for (const event of result.data.events) {
    const row = el("tr");
    row.append(el("td", "mono", fmtDate(event.time)));
    row.append(el("td", null, event.command));
    row.append(el("td", null, event.code));
    row.append(el("td", "mono", event.request_id || "—"));
    body.append(row);
  }
  setText("diagnostics-version", result.data.version);
}

async function loadSignedIn() {
  const account = await attempt("account.get");
  if (!account.ok) {
    showScreen("auth");
    return;
  }
  state.me = account.data;
  const devices = await attempt("devices.list");
  if (devices.ok) {
    state.devices = devices.data;
    state.currentDeviceId = devices.data.current_device_id;
  }
  const servers = await attempt("servers.list");
  if (servers.ok) state.servers = servers.data;
  state.profiles = [];
  if (state.currentDeviceId) {
    const profiles = await attempt("profiles.list", { device_id: state.currentDeviceId });
    if (profiles.ok) state.profiles = profiles.data;
  }
  renderAll();
  showScreen("home");
}

async function refreshDeviceData() {
  const devices = await attempt("devices.list");
  if (devices.ok) {
    state.devices = devices.data;
    state.currentDeviceId = devices.data.current_device_id;
  }
  state.profiles = [];
  if (state.currentDeviceId) {
    const profiles = await attempt("profiles.list", { device_id: state.currentDeviceId });
    if (profiles.ok) state.profiles = profiles.data;
  }
  renderAll();
}

async function saveOrigin(inputId) {
  const value = $(inputId).value.trim();
  const result = await attempt("settings.set", { api_base_url: value });
  if (!result.ok) return;
  state.settings = result.data;
  toast("Адрес API сохранён.", "ok");
  renderAuth();
}

async function authenticate(command) {
  const email = $("auth-email").value.trim();
  const password = $("auth-password").value;
  if (email.length === 0) {
    toast("Введите email.", "error");
    return;
  }
  if (password.length < 10) {
    toast("Пароль должен быть не короче 10 символов.", "error");
    return;
  }
  const result = await attempt(command, { email, password });
  $("auth-password").value = "";
  if (!result.ok) return;
  state.me = result.data;
  state.session = {
    signed_in: true,
    email,
    api_base_url: state.settings ? state.settings.api_base_url : null,
    startup_error: null,
  };
  await loadSignedIn();
  toast(command === "auth.register" ? "Аккаунт создан." : "Вы вошли в аккаунт.", "ok");
}

async function logout() {
  const result = await attempt("auth.logout");
  if (!result.ok) return;
  state.me = null;
  state.devices = null;
  state.profiles = [];
  state.servers = [];
  state.currentDeviceId = null;
  state.session = {
    signed_in: false,
    email: null,
    api_base_url: state.settings ? state.settings.api_base_url : null,
    startup_error: null,
  };
  showScreen("auth");
  toast("Вы вышли из аккаунта. Ключ устройства сохранён.", "ok");
}

async function createDevice() {
  const name = ($("device-name").value.trim() || "Windows").slice(0, 64);
  const result = await attempt("devices.create", { name });
  if (!result.ok) return;
  toast("Устройство создано: " + result.data.name, "ok");
  await refreshDeviceData();
}

async function forgetDevice() {
  if (!state.currentDeviceId) return;
  const confirmed = window.confirm(
    "Забыть это устройство? Его профили и сохранённые .conf перестанут работать.");
  if (!confirmed) return;
  const result = await attempt("devices.delete", { device_id: state.currentDeviceId });
  if (!result.ok) return;
  toast("Устройство забыто.", "ok");
  await refreshDeviceData();
}

async function issueProfile(serverId) {
  if (!serverId) return;
  if (!state.currentDeviceId) {
    toast("Сначала создайте устройство.", "error");
    return;
  }
  const result = await attempt("profiles.issue", {
    device_id: state.currentDeviceId,
    server_id: serverId,
  });
  if (!result.ok) return;
  toast("Профиль выдан.", "ok");
  await refreshDeviceData();
}

async function exportProfile(serverId) {
  if (!state.currentDeviceId) return;
  const result = await attempt("profiles.export", {
    device_id: state.currentDeviceId,
    server_id: serverId,
  });
  if (!result.ok) return;
  if (result.data.cancelled) {
    toast("Сохранение отменено.", "info");
    return;
  }
  toast("Файл сохранён: " + result.data.file_name, "ok");
}

async function revokeProfile(serverId) {
  if (!state.currentDeviceId) return;
  const confirmed = window.confirm("Отозвать профиль? Сохранённый .conf перестанет работать.");
  if (!confirmed) return;
  const result = await attempt("profiles.revoke", {
    device_id: state.currentDeviceId,
    server_id: serverId,
  });
  if (!result.ok) return;
  toast("Профиль отозван.", "ok");
  await refreshDeviceData();
}

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (!target) return;
  const action = target.dataset.action;
  if (action === "screen") showScreen(target.dataset.screen);
  else if (action === "save-origin") void saveOrigin("auth-origin");
  else if (action === "save-settings") void saveOrigin("settings-origin");
  else if (action === "login") void authenticate("auth.login");
  else if (action === "register") void authenticate("auth.register");
  else if (action === "logout") void logout();
  else if (action === "create-device") void createDevice();
  else if (action === "forget-device") void forgetDevice();
  else if (action === "issue") void issueProfile(target.dataset.server || $("issue-select").value);
  else if (action === "export") void exportProfile(target.dataset.server);
  else if (action === "revoke") void revokeProfile(target.dataset.server);
  else if (action === "refresh-diagnostics") void refreshDiagnostics();
});

async function boot() {
  if (bridge.mode === "stub") $("stub-banner").hidden = false;
  const info = await attempt("app.info");
  if (info.ok) {
    state.appInfo = info.data;
    setText("version-badge", info.data.version);
  }
  const settings = await attempt("settings.get");
  if (settings.ok) state.settings = settings.data;
  const session = await attempt("session.state");
  if (!session.ok) {
    showScreen("auth");
    return;
  }
  state.session = session.data;
  if (session.data.startup_error) {
    $("startup-error").textContent = session.data.startup_error;
    $("startup-error").hidden = false;
  }
  if (!session.data.signed_in) {
    showScreen("auth");
    return;
  }
  await loadSignedIn();
}

void boot().then(() => {
  window.__nova = { booted: true, mode: bridge.mode };
});
```

`window.confirm` — системный диалог WebView2; он не требует прав и не относится к сетевому API. Путь файла по-прежнему выбирает только хост.

- [ ] **Step 8: Написать `help.html`**

`client/ui/help.html` — статическая справка; единственная внешняя ссылка открывается системным браузером через `NewWindowRequested`.

```html
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NovaVPN — справка по импорту .conf</title>
<link rel="icon" href="data:,">
<link rel="stylesheet" href="app.css">
</head>
<body>
<header class="topbar">
  <div class="brand"><span class="brand-name">NovaVPN</span><span class="badge badge-muted">справка</span></div>
  <nav class="nav" aria-label="Навигация"><a class="nav-btn" href="index.html">Назад к приложению</a></nav>
</header>
<main class="app">
  <h1>Импорт .conf в официальный WireGuard</h1>
  <p class="muted">NovaVPN выдаёт профиль и сохраняет готовый файл конфигурации. Туннель поднимает официальный клиент WireGuard — приложение не управляет сетью и не устанавливает драйвер.</p>

  <article class="card">
    <h2>Порядок действий</h2>
    <ol class="steps">
      <li>На главном экране выберите активный профиль и нажмите «Сохранить .conf»; в системном диалоге укажите папку. Приложение предупредит, что файл содержит приватный ключ.</li>
      <li>Установите официальный клиент WireGuard для Windows со страницы <a href="https://www.wireguard.com/install/" target="_blank" rel="noopener">wireguard.com/install</a>. Ссылка откроется в системном браузере.</li>
      <li>В клиенте WireGuard выберите «Импорт туннеля из файла» и укажите сохранённый .conf.</li>
      <li>Включите туннель кнопкой «Подключить». Проверка связи выполняется средствами WireGuard, а не NovaVPN.</li>
      <li>При отзыве профиля или устройства старый .conf перестаёт работать; выдайте новый профиль и повторите импорт.</li>
    </ol>
  </article>

  <article class="card">
    <h2>Границы приложения</h2>
    <ul class="list">
      <li class="row"><span class="row-main">Не поднимает туннель, не меняет маршруты, DNS и сетевые адаптеры.</span></li>
      <li class="row"><span class="row-main">Текст конфига не показывается на экране и не копируется в буфер обмена.</span></li>
      <li class="row"><span class="row-main">Пароль не сохраняется; refresh-токен и ключ устройства хранятся локально под защитой DPAPI.</span></li>
      <li class="row"><span class="row-main">Нет автоматических обновлений и фоновых служб; версия 0.1.0-preview.</span></li>
    </ul>
  </article>

  <article class="card">
    <h2>Безопасность файла</h2>
    <p class="muted">Файл .conf содержит приватный ключ устройства. Храните его как секрет: не пересылайте в мессенджерах и не публикуйте. Для другого компьютера выдайте отдельное устройство и отдельный профиль.</p>
  </article>
</main>
</body>
</html>
```

- [ ] **Step 9: Прогнать тесты контракта и сборку**

```bash
dotnet test client/NovaVpn.Client.sln --filter UiContractTests
dotnet build client/NovaVpn.Client.sln -c Release
```

Expected: тесты — `Failed: 0` (шесть: две теории и четыре факта); сборка — 0 ошибок, каталог `ui/` копируется в выход приложения по правилу `Content`.

- [ ] **Step 10: Проверить интерфейс в браузере на заглушке**

Заглушка нужна, чтобы проверить вёрстку и потоки без окна WebView2 (сервер приложения из агента не запускается).

```bash
node client/scripts/serve-ui.mjs client/ui 4173
```

Затем в браузерном MCP (Playwright):

1. Открыть `http://127.0.0.1:4173/?stub=1`. Проверить: баннер «Демонстрационные данные (заглушка моста)» виден, экран «Подключение к API» активен, в консоли нет ошибок.
2. Задать ширины через `browser_resize`: 1440×900, 900×700, 720×600 и 360×640; на каждой ширине выполнить в странице
   ```js
   document.documentElement.scrollWidth <= document.documentElement.clientWidth
   ```
   Expected: `true` на всех четырёх. Это проверка на горизонтальный вылет; `min-width: 0` в grid-колонках обязателен.
3. Сохранить адрес `https://api.novavpn.test/` → появился блок «Вход и регистрация». Войти с email `demo@novavpn.test` и паролем от 10 символов → экран «Главный», план `internal-default`, устройство `DEMO-WS`.
4. Каталог: два сервера; у `fra-2` бейдж «неизвестно», но кнопка «Выдать профиль» доступна — решение о допуске принимает API, а `availability` лишь честно сообщает, что связность не измерялась; у `ams-1` задержка «не измерялось».
5. Главный: выбрать `ams-1`, «Выдать профиль» → строка профиля «активен», адрес `10.66.0.2`; «Сохранить .conf» → уведомление «Файл сохранён: NovaVPN-ams-1.conf».
6. Диагностика: таблица содержит команды `auth.login`, `devices.list`, `profiles.export`; коды `ok`.
7. `browser_console_messages` — без ошибок уровня error. Снимки экрана для задач 12 можно сохранить здесь; временные файлы и профиль браузера удалить после проверки.

Остановить сервер (Ctrl+C в его терминале или `TaskStop`). Если ширины 720 и 360 дают горизонтальную прокрутку, ищите причину в grid-колонках и `overflow-wrap: anywhere` у `mono`, а не уменьшайте шрифт.

- [ ] **Step 11: Коммит**

```bash
git add client/ui client/scripts/serve-ui.mjs client/tests/NovaVpn.Client.App.Tests/UiContractTests.cs
git commit -m "feat(client): экраны, локальные шрифты и заглушка моста для проверки UI"
```

### Task 10: Самопроверка `--selftest` — окно, WebView2, CSP и живой мост

**Files:**
- Create: `client/src/NovaVpn.Client.App/SelfTest/SelfTestRunner.cs`
- Modify: `client/src/NovaVpn.Client.App/Program.cs`

**Interfaces:**
- Consumes: `MainForm(AppServices)` с `internal bool Silent { get; init; }`, `internal TaskCompletionSource<CoreWebView2> Ready`, `internal Exception? StartupFailure`, `internal IReadOnlyList<string> ConsoleErrors` (добавлены в задаче 8); `AppServices(string dataDir, IFileSavePicker picker)`; `FileSavePicker`; `ClientVersion.Value`; маркер `window.__nova = { booted, mode }` из `app.js`.
- Produces: `SelfTestRunner.Run()` → `int`; приложение принимает `--selftest` и возвращает этот код как код выхода. Коды: 0 — успех; 2 — нет WebView2 Runtime; 3 — интерфейс не загрузился за 30 с; 4 — ошибка в консоли страницы; 5 — прочий сбой (нет `ui/`, CSP или состояние не совпали).

Это дымовая проверка на машине разработчика: она запускает настоящее окно за пределами экрана, ждёт загрузку настоящего интерфейса и проверяет, что мост ответил. Юнит-тестов здесь нет — проверке нужны окно и WebView2; в CI она не запускается и в `docs/testing-status.md` учитывается как not-run.

> **Правки перед задачей 10 (решения контроллера):**
> 1. `AppServices` реализует только `IAsyncDisposable`, поэтому `using (var services = new AppServices(...))` из Step 1 и `using var services = ...` из Step 2 не компилируются (CS8418). Освобождение — явное, `DisposeAsync().AsTask().GetAwaiter().GetResult()` в `finally`, как в `Program.cs` задачи 8; форма освобождается раньше сервисов.
> 2. Step 2 сохраняет защищённое создание `AppServices` и сообщение «Не удалось подготовить каталог данных NovaVPN: …» из задачи 8; из брифа берётся только `int Main`, ветка `--selftest` до мьютекса и коды возврата.
> 3. Если старт падает до события `Shown`, `VerifyAsync` не запускается (форма уже закрыта). После возврата `Application.Run` код 5 пересматривается по `form.StartupFailure`: `WebView2RuntimeNotFoundException` дает 2, остальное остаётся 5. Без этого контракт кода 2 недостижим.
> 4. Запуск — собранный exe (`client/src/NovaVpn.Client.App/bin/Debug/net10.0-windows/win-x64/NovaVpn.Client.App.exe --selftest`) напрямую из Git Bash, код выхода берётся сразу после процесса. Приложение — `WinExe`: если `selftest: ok` не появится в stdout при коде 0, это оговорка окружения, а не провал; авторитетен код выхода.
> 5. Если WebView2 Runtime отсутствует (код 2), исполнитель докладывает BLOCKED с кодом 2 и не имитирует успех; commit не делается.

> **Правки после ревью задачи 10:**
> 1. `Cleanup`: профиль WebView2 освобождается асинхронно в течение ~5 с после закрытия формы; окно 10 попыток по 300 мс мало (остаток в 3 из 4 прогонов). Окно расширяется до 60 попыток по 500 мс (30 с); замер контроллера: 3 из 3 прогонов, 0 каталогов, ~8 с на прогон.
> 2. Режим `stub` при ожидании живого моста даёт код 5 с текстом «интерфейс открылся в режиме заглушки вместо живого моста»; код 3 остаётся только для `pending` по таймауту.
> 3. В начале `Run()` — `Console.OutputEncoding = Encoding.UTF8`, чтобы русские сообщения читались в Git Bash; текст сообщений не меняется.

- [ ] **Step 1: Написать `SelfTestRunner.cs`**

`client/src/NovaVpn.Client.App/SelfTest/SelfTestRunner.cs`:

```csharp
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using NovaVpn.Client.App.Export;
using NovaVpn.Client.App.Host;
using NovaVpn.Client.Core;

namespace NovaVpn.Client.App.SelfTest;

internal static class SelfTestRunner
{
    private const string ExpectedCsp =
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; " +
        "connect-src 'none'; base-uri 'none'; form-action 'none'";
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan BootTimeout = TimeSpan.FromSeconds(30);

    public static int Run()
    {
        var dataDir = Path.Combine(Path.GetTempPath(), "novavpn-selftest-" + Guid.NewGuid().ToString("N"));
        var code = 5;
        try
        {
            using (var services = new AppServices(dataDir, new FileSavePicker()))
            using (var form = new MainForm(services)
                   {
                       Silent = true,
                       ShowInTaskbar = false,
                       StartPosition = FormStartPosition.Manual,
                       Location = new Point(-32000, -32000),
                   })
            {
                form.Shown += (_, _) => _ = VerifyAsync(form, value => code = value);
                Application.Run(form);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("selftest: " + ex.GetType().Name + ": " + ex.Message);
            code = 5;
        }
        finally
        {
            Cleanup(dataDir);
        }

        if (code == 0) Console.WriteLine("selftest: ok");
        return code;
    }

    private static async Task VerifyAsync(MainForm form, Action<int> setCode)
    {
        try
        {
            CoreWebView2 core;
            try
            {
                core = await form.Ready.Task.WaitAsync(StartupTimeout);
            }
            catch (TimeoutException)
            {
                Fail(setCode, form, 3, $"окно не подготовило WebView2 за {StartupTimeout.TotalSeconds:0} с.");
                return;
            }
            catch (WebView2RuntimeNotFoundException)
            {
                Fail(setCode, form, 2, "WebView2 Runtime не установлен.");
                return;
            }
            catch (Exception ex)
            {
                Fail(setCode, form, 5, "сбой запуска: " + ex.Message);
                return;
            }

            var deadline = DateTime.UtcNow + BootTimeout;
            var mode = "none";
            while (DateTime.UtcNow < deadline)
            {
                mode = await EvaluateStringAsync(core,
                    "window.__nova && window.__nova.booted === true ? window.__nova.mode : 'pending'");
                if (mode is "live" or "stub") break;
                await Task.Delay(250);
            }
            if (mode != "live")
            {
                Fail(setCode, form, 3, $"интерфейс не загрузился за {BootTimeout.TotalSeconds:0} с (режим: {mode}).");
                return;
            }

            var stateJson = await core.ExecuteScriptAsync(
                "JSON.stringify({" +
                "stub: !document.getElementById('stub-banner').hidden," +
                "authVisible: !document.getElementById('screen-auth').hidden," +
                "badge: document.getElementById('version-badge').textContent," +
                "csp: (document.querySelector('meta[http-equiv=\"Content-Security-Policy\"]') || {}).content || ''" +
                "})");
            using var outer = JsonDocument.Parse(stateJson);
            using var state = JsonDocument.Parse(outer.RootElement.GetString()!);
            var root = state.RootElement;
            if (root.GetProperty("stub").GetBoolean())
            {
                Fail(setCode, form, 5, "в живом режиме показан баннер заглушки.");
                return;
            }
            if (!root.GetProperty("authVisible").GetBoolean())
            {
                Fail(setCode, form, 5, "экран входа не показан при пустом профиле.");
                return;
            }
            if (!string.Equals(root.GetProperty("badge").GetString(), ClientVersion.Value, StringComparison.Ordinal))
            {
                Fail(setCode, form, 5, "версия в интерфейсе не совпадает с " + ClientVersion.Value + ".");
                return;
            }
            if (!string.Equals(root.GetProperty("csp").GetString(), ExpectedCsp, StringComparison.Ordinal))
            {
                Fail(setCode, form, 5, "CSP страницы отличается от ожидаемой.");
                return;
            }
            if (form.ConsoleErrors.Count > 0)
            {
                Fail(setCode, form, 4,
                    "ошибки в консоли страницы (" + form.ConsoleErrors.Count + "): " + form.ConsoleErrors[0]);
                return;
            }

            setCode(0);
            form.Close();
        }
        catch (Exception ex)
        {
            Fail(setCode, form, 5, "непойманный сбой: " + ex.GetType().Name + ": " + ex.Message);
        }
    }

    private static async Task<string> EvaluateStringAsync(CoreWebView2 core, string script)
    {
        var raw = await core.ExecuteScriptAsync(script);
        return JsonSerializer.Deserialize<string>(raw) ?? "";
    }

    private static void Fail(Action<int> setCode, MainForm form, int exitCode, string message)
    {
        Console.Error.WriteLine("selftest: " + message);
        setCode(exitCode);
        form.Close();
    }

    private static void Cleanup(string dataDir)
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                if (!Directory.Exists(dataDir)) return;
                Directory.Delete(dataDir, recursive: true);
                return;
            }
            catch (IOException) { Thread.Sleep(300); }
            catch (UnauthorizedAccessException) { Thread.Sleep(300); }
        }
        Console.Error.WriteLine("selftest: временный каталог не удалён: " + dataDir);
    }
}
```

Версия в бейдже приходит через мост (`app.info`), поэтому проверка версии доказывает, что `postMessage`-обмен жив, а не только что страница отрисована. Ожидаемый CSP продублирован из `UiContractTests`: если меняется политика, падают оба места — так и задумано.

- [ ] **Step 2: Переписать `Program.cs`**

`client/src/NovaVpn.Client.App/Program.cs` целиком:

```csharp
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
        using var services = new AppServices(dataDir, new FileSavePicker());
        using var form = new MainForm(services);
        Application.Run(form);
        return 0;
    }
}
```

`--selftest` стоит до мьютекса: самопроверка не должна зависеть от того, открыт ли обычный экземпляр, и не показывает модальных окон.

- [ ] **Step 3: Собрать и прогнать самопроверку**

```bash
dotnet build client/NovaVpn.Client.sln -c Debug
dotnet run --project client/src/NovaVpn.Client.App -c Debug -- --selftest
echo "EXIT=$?"
```

Expected: в stdout `selftest: ok`, `EXIT=0`; в `%TEMP%` не осталось каталогов `novavpn-selftest-*`.

- [ ] **Step 4: Доказать, что проверка ловит поломку**

Временно заменить в `SelfTestRunner.ExpectedCsp` `connect-src 'none'` на `connect-src 'self'`, затем:

```bash
dotnet run --project client/src/NovaVpn.Client.App -c Debug -- --selftest
echo "EXIT=$?"
```

Expected: `selftest: CSP страницы отличается от ожидаемой.`, `EXIT=5`. Вернуть строку и повторить Step 3 — снова `EXIT=0`. Без этого шага «зелёная» самопроверка не доказывает, что сравнение вообще выполняется.

- [ ] **Step 5: Коммит**

```bash
git add client/src/NovaVpn.Client.App
git commit -m "feat(client): самопроверка --selftest для окна, CSP и моста"
```

В CI шаг не добавляется: окно и WebView2 Runtime на раннере не гарантированы. В `docs/testing-status.md` задача 12 зафиксирует эту строку как not-run с причиной.

### Task 11: Живой E2E клиентского ядра против dev-стенда

**Files:**
- Create: `client/tests/NovaVpn.Client.E2E/NovaVpn.Client.E2E.csproj`
- Create: `client/tests/NovaVpn.Client.E2E/Program.cs`
- Create: `client/scripts/e2e.sh`
- Modify: `Makefile` (цель `client-e2e`)
- Modify: `client/NovaVpn.Client.sln` (`dotnet sln add`)

**Interfaces:**
- Consumes: `ApiClient(Uri, HttpMessageHandler? = null, TimeSpan? timeout = null, IApiObserver? observer = null)`; `SessionService(ApiClient, Uri, SessionStore, TimeProvider? = null)`; `DeviceService(ApiClient, SessionService, DeviceIdentityStore, string? hostName = null)`; `ProfileService(ApiClient, SessionService)`; `WireGuardConfig.Compose`, `ConfigExporter.DefaultFileName/Write`; `DeviceIdentityStore.AccountKey/Get`.
- Produces: два режима CLI — `prepare` (печатает `E2E_USER=<uuid>` и `E2E_SERVER=<uuid>`) и `run` (печатает `E2E OK`); скрипт `client/scripts/e2e.sh`; цель `make client-e2e`. Код выхода 0 — успех, 1 — отказ проверки, 2 — неверные аргументы.

Живой прогон использует настоящий API и PostgreSQL dev-стенда. Пароли передаются только через stdin: в argv, журналах и отчётах их нет. План `internal-default` выдаётся SQL-вставкой между фазами — публичного способа выдать план у API нет, и это ограничение продукта, а не стенда.

- [ ] **Step 1: Создать проект E2E и подключить его к решению**

`client/tests/NovaVpn.Client.E2E/NovaVpn.Client.E2E.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <RootNamespace>NovaVpn.Client.E2E</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="../../src/NovaVpn.Client.Core/NovaVpn.Client.Core.csproj" />
  </ItemGroup>
</Project>
```

```bash
dotnet sln client/NovaVpn.Client.sln add client/tests/NovaVpn.Client.E2E/NovaVpn.Client.E2E.csproj
dotnet restore client/NovaVpn.Client.sln
```

- [ ] **Step 2: Написать `Program.cs` фазы `prepare`**

`client/tests/NovaVpn.Client.E2E/Program.cs`:

```csharp
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Auth;
using NovaVpn.Client.Core.Config;
using NovaVpn.Client.Core.Devices;
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
        using var body = JsonContent.Create(new { email, password }, options: JsonDefaults.Options);
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
            Content = JsonContent.Create(payload, options: JsonDefaults.Options),
        };
        if (token is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.SendAsync(request);
        return await ReadJsonAsync(response);
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
```

Фаза `prepare` ещё не содержит `RunAsync` — добавьте заглушку, чтобы проект собирался:

```csharp
    private static Task<int> RunAsync(
        Uri baseUrl, string email, Guid serverId, string stateDir, string outDir) =>
        throw new NotImplementedException();
```

- [ ] **Step 3: Добавить фазу `run` и собрать**

Заменить заглушку `RunAsync` на:

```csharp
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
        var composed = WireGuardConfig.Compose(serverText, identity!.PrivateKeyBase64, identity.PublicKeyBase64);
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
```

Текст конфига и приватный ключ не печатаются: наружу уходят только имя файла и его размер. Собрать:

```bash
dotnet build client/tests/NovaVpn.Client.E2E -c Debug
```

Expected: 0 ошибок, 0 предупреждений (`TreatWarningsAsErrors`).

- [ ] **Step 4: Написать скрипт живого прогона**

`client/scripts/e2e.sh`:

```bash
#!/usr/bin/env bash
# Живой E2E клиентского ядра против dev-стенда. Секреты — только stdin и переменные
# процесса: в argv, файлах и выводе их нет. Стенд postgres/redis поднимается, но не
# снимается: это dev-окружение разработчика, а не собственность прогона.
set -euo pipefail
cd "$(dirname "$0")/../.."

POSTGRES_HOST_PORT=${POSTGRES_HOST_PORT:-5432}
REDIS_HOST_PORT=${REDIS_HOST_PORT:-6379}
API_PORT=${CLIENT_E2E_API_PORT:-18080}
BASE_URL="http://127.0.0.1:${API_PORT}"
ENV_FILE=infrastructure/docker/.env.dev
API_CONTAINER=novavpn-client-e2e-api
GO_IMAGE=golang:1.26-alpine
DB_URL="postgres://nova:nova@host.docker.internal:${POSTGRES_HOST_PORT}/novavpn?sslmode=disable"
REDIS_ADDR="host.docker.internal:${REDIS_HOST_PORT}"
STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/novavpn-e2e-state.XXXXXX")
OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/novavpn-e2e-out.XXXXXX")
SUFFIX=$(date +%s)
USER_EMAIL="e2e-${SUFFIX}@example.test"
ADMIN_EMAIL="e2e-admin-${SUFFIX}@example.test"
ADMIN_PASSWORD="E2e-a-${SUFFIX}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
USER_PASSWORD="E2e-u-${SUFFIX}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

psql_exec() {
  MSYS_NO_PATHCONV=1 docker compose -f infrastructure/docker/docker-compose.dev.yml \
    exec -T postgres psql -U nova -d novavpn -v ON_ERROR_STOP=1 -c "$1"
}

cleanup() {
  set +e
  MSYS_NO_PATHCONV=1 docker rm -f "$API_CONTAINER" >/dev/null 2>&1
  psql_exec "DELETE FROM users WHERE email LIKE 'e2e-%@example.test'" >/dev/null
  psql_exec "DELETE FROM vpn_servers WHERE name LIKE 'e2e-%'" >/dev/null
  psql_exec "DELETE FROM admin_users WHERE email LIKE 'e2e-admin-%@example.test'" >/dev/null
  rm -rf "$STATE_DIR" "$OUT_DIR"
}
trap cleanup EXIT

test -f "$ENV_FILE" || { echo "нет $ENV_FILE: скопируйте .env.dev.example и заполните секрет" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker недоступен" >&2; exit 1; }

echo "== стенд =="
POSTGRES_HOST_PORT="$POSTGRES_HOST_PORT" REDIS_HOST_PORT="$REDIS_HOST_PORT" make up-dev
make migrate-up

echo "== администратор =="
printf '%s' "$ADMIN_PASSWORD" | MSYS_NO_PATHCONV=1 docker run --rm -i \
  -v "$PWD:/src" -w /src -v novavpn-gomod:/go/pkg/mod -v novavpn-gocache:/root/.cache/go-build \
  -e GOFLAGS=-mod=mod -e CGO_ENABLED=0 --env-file "$ENV_FILE" \
  --add-host=host.docker.internal:host-gateway \
  -e NOVAVPN_DATABASE_URL="$DB_URL" -e NOVAVPN_REDIS_ADDR="$REDIS_ADDR" \
  "$GO_IMAGE" go run -mod=mod ./services/api/cmd/novavpn-api admin create "$ADMIN_EMAIL"

echo "== API =="
MSYS_NO_PATHCONV=1 docker run -d --name "$API_CONTAINER" \
  -v "$PWD:/src" -w /src -v novavpn-gomod:/go/pkg/mod -v novavpn-gocache:/root/.cache/go-build \
  -e GOFLAGS=-mod=mod -e CGO_ENABLED=0 --env-file "$ENV_FILE" \
  --add-host=host.docker.internal:host-gateway -p "${API_PORT}:8080" \
  -e NOVAVPN_LISTEN_ADDR=:8080 -e NOVAVPN_DATABASE_URL="$DB_URL" -e NOVAVPN_REDIS_ADDR="$REDIS_ADDR" \
  "$GO_IMAGE" go run -mod=mod ./services/api/cmd/novavpn-api serve >/dev/null

ready=0
for _ in $(seq 1 180); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/v1/servers" || true)
  if [ "$code" = "401" ]; then ready=1; break; fi
  sleep 1
done
if [ "$ready" != 1 ]; then
  echo "API не поднялся; журнал контейнера:" >&2
  MSYS_NO_PATHCONV=1 docker logs "$API_CONTAINER" >&2 || true
  exit 1
fi

echo "== фаза 1: администратор, сервер, регистрация =="
prepare_out=$(printf '%s\n%s\n' "$ADMIN_PASSWORD" "$USER_PASSWORD" \
  | dotnet run --project client/tests/NovaVpn.Client.E2E -c Debug -- \
      prepare "$BASE_URL" "$ADMIN_EMAIL" "$USER_EMAIL" "$STATE_DIR")
echo "$prepare_out"
USER_ID=$(printf '%s\n' "$prepare_out" | sed -n 's/^E2E_USER=//p')
SERVER_ID=$(printf '%s\n' "$prepare_out" | sed -n 's/^E2E_SERVER=//p')
if [ -z "$USER_ID" ] || [ -z "$SERVER_ID" ]; then
  echo "не получены идентификаторы пользователя или сервера" >&2
  exit 1
fi
printf '%s\n' "$prepare_out" | grep -qx 'E2E PREPARE OK'

echo "== план internal-default =="
psql_exec "INSERT INTO subscriptions (id, user_id, plan_id) VALUES (gen_random_uuid(), '$USER_ID', '00000000-0000-4000-8000-000000000a01')"

echo "== фаза 2: устройство, выдача, экспорт, отзыв =="
run_out=$(printf '%s\n' "$USER_PASSWORD" \
  | dotnet run --project client/tests/NovaVpn.Client.E2E -c Debug -- \
      run "$BASE_URL" "$USER_EMAIL" "$SERVER_ID" "$STATE_DIR" "$OUT_DIR")
echo "$run_out"
printf '%s\n' "$run_out" | grep -qx 'E2E OK'

echo "== создано за прогон =="
users_made=$(psql_exec "SELECT count(*) FROM users WHERE email LIKE 'e2e-%@example.test'" | tr -d ' ')
servers_made=$(psql_exec "SELECT count(*) FROM vpn_servers WHERE name LIKE 'e2e-%'" | tr -d ' ')
echo "users=$users_made servers=$servers_made"
```

```bash
chmod +x client/scripts/e2e.sh
bash -n client/scripts/e2e.sh
```

`cleanup` работает с `set +e`: если стенд уже снят, `psql` вернёт ошибку, но удаление временных каталогов всё равно выполнится. Счётчики «создано за прогон» печатаются до `trap` и служат масштабом прогона; фактическую уборку доказывает отдельный `psql`-запрос в шаге 6.

- [ ] **Step 5: Добавить цель `make client-e2e`**

В `Makefile` рядом с `e2e` / `e2e-down`:

```make
# Клиентский E2E идёт через свой скрипт: ему нужны dev-стенд и собственный
# контейнер API, а не сетевой стенд узлов make e2e.
.PHONY: client-e2e
client-e2e:
	bash client/scripts/e2e.sh
```

И добавить `client-e2e` в существующую строку `.PHONY` рядом не обязательно: отдельный `.PHONY` выше уже объявляет цель.

- [ ] **Step 6: Прогнать живой E2E**

```bash
make client-e2e
echo "EXIT=$?"
```

Expected: `E2E PREPARE OK`, `E2E_FILE=NovaVPN-e2e.conf bytes=<положительное число>`, `E2E OK`, `EXIT=0`. После выхода проверить, что временные каталоги и контейнер удалены:

```bash
docker ps -a --filter name=novavpn-client-e2e-api --format '{{.Names}}'
ls -d "${TMPDIR:-/tmp}"/novavpn-e2e-* 2>/dev/null || echo "временных каталогов нет"
psql_out=$(MSYS_NO_PATHCONV=1 docker compose -f infrastructure/docker/docker-compose.dev.yml \
  exec -T postgres psql -U nova -d novavpn -tAc \
  "SELECT (SELECT count(*) FROM users WHERE email LIKE 'e2e-%@example.test'), (SELECT count(*) FROM vpn_servers WHERE name LIKE 'e2e-%')")
echo "после уборки: $psql_out"
```

Expected: пустой список контейнеров, «временных каталогов нет», `после уборки: 0|0`.

- [ ] **Step 7: Коммит**

```bash
git add client/tests/NovaVpn.Client.E2E client/scripts/e2e.sh Makefile client/NovaVpn.Client.sln
git commit -m "test(client): живой E2E выдачи, экспорта и отзыва профиля"
```

### Task 12: Документы цикла — ADR-0010, страница клиента, README, статус проверок, кадры и portable zip

**Files:**
- Create: `docs/adr/0010-windows-client-shell.md`
- Create: `docs/guide/client.html`
- Create: `docs/images/guide/client-home-dark.png`, `docs/images/guide/client-home-light.png`, `docs/images/guide/client-catalog.png`, `docs/images/guide/client-diagnostics.png`
- Modify: `docs/adr/README.md`, `docs/guide/index.html`, `docs/guide/protocol.html`, `docs/guide/api.html`, `README.md`, `docs/testing-status.md`
- Build: `client/dist/win-x64/` и `client/dist/NovaVpn-Client-0.1.0-preview-win-x64.zip` (каталог в `.gitignore`, в коммит не входит)

**Interfaces:**
- Consumes: `ClientVersion.Value` = `"0.1.0-preview"`; экраны и тексты из задачи 9 (`#screen-auth`, `#screen-home`, `#screen-catalog`, `#screen-settings`, `#screen-diagnostics`, баннер `#stub-banner`); `--selftest` и коды выхода задачи 10; `make client-e2e` и фаза `prepare`/`run` задачи 11; заглушка моста включается `?stub=1`.
- Produces: `docs/guide/client.html` как четвёртая страница инструкции; ADR-0010; честные строки в `README.md` и `docs/testing-status.md`; четыре кадра UI; локальный zip preview-клиента.

- [ ] **Step 1: Записать ADR-0010**

`docs/adr/0010-windows-client-shell.md`:

```markdown
# 0010. Оболочка Windows-клиента: WinForms + WebView2 без локального сервера

**Статус:** принят, 2026-11-24.

## Контекст

Цикл E-1 выпускает первый клиент — Windows-менеджер доступа `0.1.0-preview`. Он входит
в аккаунт, регистрирует устройство с локальной парой X25519, выдаёт и отзывает профиль,
собирает готовый `.conf` для официального WireGuard и не поднимает туннель. Интерфейс
уже существует как HTML/CSS-дизайн-система, а команда небольшая: второй набор экранов
на нативной разметке означал бы две реализации одних и тех же состояний.

Одновременно нужно удержать три границы: секреты (refresh-токен, приватный ключ) не
должны покидать машину и попадать в журналы; страница не должна получить больше прав,
чем перечисленные команды; приложение не должно открывать слушающий порт, который
пришлось бы защищать от других локальных процессов и браузера.

## Решение

1. **Хост — WinForms на .NET 10, интерфейс — WebView2.** Ассеты `client/ui` копируются
   в выход приложения и публикуются по виртуальному origin
   `https://app.novavpn.local/` через `SetVirtualHostNameToFolderMapping(..., DenyCors)`.
   Слушающего TCP-порта нет; переходы за пределы origin отменяются, `NewWindowRequested`
   отменяется, внешние ссылки открывает хост по явному действию пользователя.
2. **Мост — только `postMessage`.** Страница отправляет `{id, command, args}`, хост
   отвечает `{id, ok, data}` или `{id, ok: false, data: null, error: {code, message,
   request_id}}`. Действует белый список команд; сообщение ограничено 64 КиБ, глубина
   JSON — 8. `AddHostObjectToScript` не используется: страница не получает объектный
   граф .NET, только JSON-команды.
3. **Секреты — только DPAPI `CurrentUser`.** Refresh-токен хранится с энтропией
   `NovaVPN/session/v1`, приватные ключи устройств — `NovaVPN/devices/v1`. Access-токен
   живёт только в памяти. Пароль не сохраняется и не журналируется; в журнале —
   `account_id` из `/me`, не email. Текст `.conf` не попадает в JS, журнал, буфер обмена
   и на экран: его собирает Core из полей ответа и локального ключа, а сохраняет
   системный диалог.
4. **CSP ровно одна и та же на обеих страницах:**
   `default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self';
   img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'`.
   Инлайновых скриптов и стилей нет; сетевые вызовы делает только хост.
5. **Проверяемость.** UI открывается в обычном браузере с заглушкой моста по `?stub=1`;
   на экране виден баннер «Демонстрационные данные (заглушка моста)». `--selftest`
   загружает настоящие ассеты в WebView2, сверяет CSP, `app.info` и консоль и завершает
   процесс кодом 0. Пиксельную отрисовку окна агент не видит: её подтверждает человек
   или скриншоты, снятые отдельно.

## Отвергнутые альтернативы

- **Локальный HTTP-сервер (Kestrel/ASP.NET Core) и `http://127.0.0.1:<port>`.** Появляется
  слушающий порт, правила CORS и локальной авторизации, гонка за порт и предупреждение
  брандмауэра. Для двух страниц и JSON-моста это лишняя поверхность атаки.
- **Нативный WPF/XAML.** Пришлось бы переносить дизайн-систему в XAML и поддерживать
  две разметки; визуальная проверка в браузере исчезла бы. Для E-1 отвергнуто; для
  экранов туннеля в E-2 решение можно пересмотреть.
- **Electron или Tauri.** Дополнительный рантайм (Node) или тулчейн (Rust), рост размера
  поставки и подписи. WebView2 Evergreen уже есть на поддерживаемых Windows.
- **`AddHostObjectToScript`.** Открывает странице произвольные методы .NET; ограничить
  поверхность сложнее, чем перечислить команды в одном маршрутизаторе.

## Последствия

- Клиент зависит от WebView2 Evergreen Runtime и .NET Desktop Runtime 10. При отсутствии
  WebView2 приложение показывает сообщение и ссылку на официальный установщик, молчаливой
  установки зависимостей нет. Portable-каталог и zip — framework-dependent.
- Установщик, подпись кода, автообновление, трей и автозапуск остаются в E-3.
- Мост — граница безопасности: новая команда требует строки в белом списке, типа
  аргументов и ответа, теста на отсутствие токенов и ключей в ответе.
- Собственный туннель (WireGuardNT, wintun, привилегированный сервис) в E-1 не
  реализуется; единственный путь в туннель — импорт `.conf` в официальный WireGuard.
  Механизм появится в E-2 после спайка S4 и ADR-008.
- UI можно проверять в браузере и самопроверкой, но не пиксельно из агента; это
  ограничение записано в `docs/testing-status.md` как `not-run`.
```

- [ ] **Step 2: Добавить строку в карту ADR**

В `docs/adr/README.md` в таблицу после строки `009`:

```markdown
| 010 | [0010-windows-client-shell.md](0010-windows-client-shell.md) | принят 2026-11-24; оболочка Windows-клиента E-1: WebView2 без локального сервера |
```

- [ ] **Step 3: Собрать страницу клиента**

`docs/guide/client.html`:

```html
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NovaVPN — Windows-клиент preview: менеджер доступа и .conf</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="guide.css">
</head>
<body>
<header class="topbar">
  <div class="topbar__brand"><span class="topbar__mark"></span>NovaVPN <span class="topbar__sub">/ инструкция</span></div>
  <nav class="topbar__nav" aria-label="Разделы руководства">
    <a href="index.html">Что умеет сервис</a>
    <a href="protocol.html">Протокол прогона</a>
    <a href="client.html" aria-current="page">Клиент</a>
    <a href="api.html">API-справочник</a>
  </nav>
</header>

<div class="wrap">
  <aside class="rail" aria-label="Оглавление">
    <p class="rail__title">На странице</p>
    <a href="#what">Что это</a>
    <a href="#screens">Экраны</a>
    <a href="#run">Сборка и запуск</a>
    <a href="#privacy">Приватность</a>
    <a href="#limits">Чего нет</a>
  </aside>

  <main>
    <div class="hero">
      <h1>Windows-клиент 0.1.0-preview: менеджер доступа</h1>
      <p class="lede">Приложение входит в аккаунт NovaVPN, регистрирует устройство, выдаёт и отзывает профиль и сохраняет готовый <code>.conf</code> для официального клиента WireGuard. Собственного туннеля в нём нет, и состояний «подключено» или «защищено» он не показывает.</p>
      <p>Страница отвечает на три вопроса: что клиент делает, как собрать и запустить preview и где проходит граница честности. Кадры сняты с заглушки моста — на каждом виден баннер «Демонстрационные данные (заглушка моста)».</p>
      <div class="badges">
        <span class="badge badge--accent">Версия 0.1.0-preview</span>
        <span class="badge">Windows 10/11 x64</span>
        <span class="badge">.NET 10 · WebView2</span>
        <span class="badge badge--warning">Туннель не управляется</span>
      </div>
      <div class="summary-strip">
        <div><dt>Экранов</dt><dd>5</dd></div>
        <div><dt>Команд моста</dt><dd>17</dd></div>
        <div><dt>Собственных портов</dt><dd class="ok">0</dd></div>
        <div><dt>Приватный ключ на сервере</dt><dd class="ok">нет</dd></div>
      </div>
      <div class="note">
        <strong>Граница честности.</strong> Preview — portable-каталог и zip без установщика и подписи кода.
        Импорт сохранённого файла в официальный WireGuard на машине сборки не проигрывался, Windows 10
        и второй пользователь Windows не проверялись. Полный список — в
        <a href="../testing-status.md">статусе проверок</a>.
      </div>
    </div>

    <section id="what">
      <h2>Что делает и чего не делает</h2>
      <p class="section-lede">Клиент — это пульт управления доступом. Шифрование и передачу трафика выполняет WireGuard, а не это приложение.</p>
      <div class="grid grid--2">
        <div class="card">
          <span class="card__kicker">Делает</span>
          <ul>
            <li>Регистрация и вход; access-токен только в памяти, refresh — под DPAPI.</li>
            <li>Устройство с локальной парой X25519; публичный ключ уходит на сервер, приватный остаётся на машине под DPAPI.</li>
            <li>Каталог серверов с буквальной доступностью и «не измерялось» вместо нуля.</li>
            <li>Выдача и отзыв профиля; лимит устройств и окно перекрытия ключа соблюдает сервер.</li>
            <li>Сборка <code>.conf</code> с локальным <code>PrivateKey</code> и сохранение системным диалогом.</li>
            <li>Диагностика: имена команд моста, коды и <code>request_id</code>, без тел запросов и секретов.</li>
          </ul>
        </div>
        <div class="card">
          <span class="card__kicker">Не делает</span>
          <ul>
            <li>Не поднимает туннель и не управляет сетевыми интерфейсами.</li>
            <li>Не включает kill switch и раздельную маршрутизацию.</li>
            <li>Не устанавливается установщиком, не подписана и не обновляется сама.</li>
            <li>Не работает в трее и не запускается с системой.</li>
            <li>Не показывает конфиг на экране, в журнале или буфере обмена.</li>
            <li>Не открывает локальный HTTP-порт: интерфейс живёт на виртуальном origin <code>https://app.novavpn.local/</code>.</li>
          </ul>
        </div>
      </div>
    </section>

    <section id="screens">
      <h2>Экраны</h2>
      <p class="section-lede">Пять экранов: подключение к API, главный, каталог, настройки, диагностика. Ниже — четыре кадра заглушки; данные в них демонстрационные.</p>
      <div class="grid grid--2">
        <figure class="figure" style="margin:0">
          <img src="../images/guide/client-home-dark.png" alt="Главный экран клиента в тёмной теме: план internal-default, устройство DEMO-WS, выданный профиль ams-1 и кнопка сохранения .conf; сверху баннер заглушки">
          <figcaption><strong>Главный, тёмная тема.</strong> План <code>internal-default</code>, устройство <code>DEMO-WS</code>, профиль активен. Кнопка сохраняет файл, но туннель не поднимает.</figcaption>
        </figure>
        <figure class="figure" style="margin:0">
          <img src="../images/guide/client-home-light.png" alt="Тот же главный экран клиента в светлой теме: те же демонстрационные данные и баннер заглушки">
          <figcaption><strong>Главный, светлая тема.</strong> Тема выбирается по <code>prefers-color-scheme</code>; контраст проверен по WCAG AA.</figcaption>
        </figure>
      </div>
      <div class="grid grid--2" style="margin-top:20px">
        <figure class="figure" style="margin:0">
          <img src="../images/guide/client-catalog.png" alt="Каталог серверов: ams-1 доступен, fra-2 неизвестен, задержка и нагрузка не измерялись, пропускная способность не заявлена">
          <figcaption><strong>Каталог.</strong> «Доступен» — свежий heartbeat; «неизвестно» — связность не измерялась. Задержка и нагрузка — «не измерялось», а не ноль.</figcaption>
        </figure>
        <figure class="figure" style="margin:0">
          <img src="../images/guide/client-diagnostics.png" alt="Диагностика: таблица команд моста с временем, именем команды, кодом и request_id">
          <figcaption><strong>Диагностика.</strong> Кольцо команд без тел запросов, токенов и ключей; поля — время, команда, код, <code>request_id</code>.</figcaption>
        </figure>
      </div>
      <div class="note note--warning">
        <strong>Что доказывают кадры.</strong> Только вёрстку и состояния интерфейса на заглушке: баннер на кадре — часть
        доказательства. Работу моста, CSP и загрузку настоящих ассетов подтверждает <code>--selftest</code> в WebView2,
        живой путь до <code>.conf</code> — отдельный E2E на dev-стенде.
      </div>
    </section>

    <section id="run">
      <h2>Сборка и запуск preview</h2>
      <p class="section-lede">Нужны Windows 10/11 x64, .NET SDK 10.0.204, WebView2 Evergreen Runtime. Для запуска опубликованной сборки — .NET Desktop Runtime 10.</p>
      <ol class="steps">
        <li>
          <h3>Собрать и прогнать тесты</h3>
          <p>Версии пакетов закреплены lock-файлами; восстановление идёт в locked-режиме.</p>
          <pre><code>dotnet restore client/NovaVpn.Client.sln --locked-mode
dotnet test client/NovaVpn.Client.sln -c Release</code></pre>
        </li>
        <li>
          <h3>Самопроверка WebView2</h3>
          <p>Режим открывает скрытое окно, загружает настоящие ассеты, сверяет CSP, <code>app.info</code> и консоль и завершает процесс.</p>
          <pre><code>dotnet run --project client/src/NovaVpn.Client.App -c Release -- --selftest</code></pre>
          <p>Ожидаемая последняя строка — <code>selftest: ok</code>, код возврата 0. В CI этот режим не запускается: там нет WebView2 и интерактивной сессии.</p>
        </li>
        <li>
          <h3>Опубликовать portable-каталог</h3>
          <p>Сначала восстановить пакеты под RID <code>win-x64</code>, иначе закреплённый lock-файл не содержит нужных ресурсов и публикация с <code>RestoreLockedMode</code> остановится.</p>
          <pre><code>dotnet restore client/NovaVpn.Client.sln -r win-x64 --force-evaluate
dotnet publish client/src/NovaVpn.Client.App -c Release -r win-x64 \
  --self-contained false -p:RestoreLockedMode=true -o client/dist/win-x64</code></pre>
          <p>Каталог <code>client/dist/win-x64</code> и zip <code>NovaVpn-Client-0.1.0-preview-win-x64.zip</code> в репозиторий не входят. Это framework-dependent сборка: .NET Desktop Runtime 10 и WebView2 Runtime должны быть установлены.</p>
        </li>
        <li>
          <h3>Запустить и подключить API</h3>
          <p>Запустите <code>NovaVpn.Client.App.exe</code>, укажите адрес API и войдите. Адрес — только origin: <code>https://</code> с любым хостом; <code>http://</code> разрешён только для <code>127.0.0.1</code>, <code>localhost</code> и <code>[::1]</code>. Путь, query и fragment запрещены; редиректы не выполняются.</p>
        </li>
        <li>
          <h3>Импортировать .conf</h3>
          <p>Приложение сохраняет файл, в котором уже стоит локальный <code>PrivateKey</code>. Импортируйте его в официальный WireGuard: «Добавить туннель» → «Импорт из файла». Подключение выполняет WireGuard; этот клиент туннелем не управляет. Отзыв профиля на сервере делает сохранённый файл нерабочим, но не удаляет его с диска.</p>
        </li>
      </ol>
      <div class="note">
        <strong>Живой путь без GUI.</strong> <code>make client-e2e</code> поднимает dev-стенд, создаёт временного
        администратора, сервер и пользователя, выдаёт профиль, собирает и сохраняет <code>.conf</code>, проверяет отзыв
        и удаляет за собой временные данные. Пароли передаются только через stdin.
      </div>
    </section>

    <section id="privacy">
      <h2>Приватность и границы</h2>
      <p class="section-lede">Секреты остаются на машине, а страница получает только те команды, которые перечислены в мосте.</p>
      <div class="grid grid--2">
        <div class="card">
          <span class="card__kicker">Хранение</span>
          <ul>
            <li>Пароль не сохраняется и не журналируется.</li>
            <li>Refresh-токен — DPAPI <code>CurrentUser</code>, энтропия <code>NovaVPN/session/v1</code>.</li>
            <li>Приватные ключи устройств — DPAPI <code>CurrentUser</code>, энтропия <code>NovaVPN/devices/v1</code>.</li>
            <li>Access-токен — только в памяти процесса.</li>
            <li>В журнале — <code>account_id</code> из <code>/me</code>, не email.</li>
          </ul>
        </div>
        <div class="card">
          <span class="card__kicker">Изоляция</span>
          <ul>
            <li>Виртуальный origin, без слушающего порта и без локального сервера.</li>
            <li>Только <code>postMessage</code>; <code>AddHostObjectToScript</code> не используется.</li>
            <li>Белый список команд; сообщение не больше 64 КиБ, глубина JSON не больше 8.</li>
            <li>CSP запрещает inline-код, внешние скрипты и любые <code>connect-src</code>.</li>
            <li>Переходы за пределы origin и новые окна отменяются.</li>
          </ul>
        </div>
      </div>
      <div class="note">
        <strong>Текст конфига.</strong> <code>.conf</code> собирается в ядре приложения и уходит прямо в системный диалог
        сохранения. Он не показывается в интерфейсе, не пишется в журнал, не копируется в буфер обмена и не
        возвращается странице по мосту.
      </div>
    </section>

    <section id="limits">
      <h2>Чего нет и что не проверено</h2>
      <p class="section-lede">Список не сокращён: непроверенное не выдаётся за готовое, а неизмеренное — за ноль.</p>
      <div class="grid grid--2">
        <div class="card">
          <span class="card__kicker">Не реализовано</span>
          <ul>
            <li>Собственный туннель в клиенте (E-2, после спайка S4)</li>
            <li>Системная блокировка трафика при обрыве</li>
            <li>Раздельная маршрутизация по приложениям</li>
            <li>Установщик, подпись кода и автообновление (E-3)</li>
            <li>Трей, автозапуск и фоновые службы</li>
          </ul>
        </div>
        <div class="card">
          <span class="card__kicker">Не подтверждено испытаниями</span>
          <ul>
            <li>Импорт сохранённого <code>.conf</code> в официальный WireGuard на этой машине</li>
            <li>Windows 10 и второй пользователь Windows для DPAPI</li>
            <li>Клиент против публичного HTTPS API с настоящим сертификатом</li>
            <li><code>--selftest</code> и Windows-джоба CI на GitHub-раннере</li>
            <li>Пиксельная отрисовка окна WebView2 без человека</li>
          </ul>
        </div>
      </div>
      <div class="note">
        <strong>Где смотреть детали.</strong> Матрица доказательств и <code>not-run</code> —
        <a href="../testing-status.md">docs/testing-status.md</a>; решение об оболочке —
        <a href="../adr/0010-windows-client-shell.md">ADR-0010</a>; исходники и тесты —
        <code>client/</code>. Приватный ключ на сервер не уходит: это одна из причин,
        по которой <code>.conf</code> собирается локально.
      </div>
    </section>

    <footer>
      <p>NovaVPN, цикл E-1. Страница собрана 2026-11-24. Кадры сняты с заглушки моста, а не с работающего API; секреты в них не публикуются. Туннель поднимает официальный WireGuard из импортированного файла.</p>
    </footer>
  </main>
</div>
</body>
</html>
```

- [ ] **Step 4: Добавить «Клиент» в навигацию страниц**

В `docs/guide/index.html` заменить:

```html
    <a href="index.html" aria-current="page">Что умеет сервис</a>
    <a href="protocol.html">Протокол прогона</a>
    <a href="api.html">API-справочник</a>
```

на:

```html
    <a href="index.html" aria-current="page">Что умеет сервис</a>
    <a href="protocol.html">Протокол прогона</a>
    <a href="client.html">Клиент</a>
    <a href="api.html">API-справочник</a>
```

В `docs/guide/protocol.html` заменить:

```html
    <a href="index.html">Что умеет сервис</a>
    <a href="protocol.html" aria-current="page">Протокол прогона</a>
    <a href="api.html">API-справочник</a>
```

на:

```html
    <a href="index.html">Что умеет сервис</a>
    <a href="protocol.html" aria-current="page">Протокол прогона</a>
    <a href="client.html">Клиент</a>
    <a href="api.html">API-справочник</a>
```

`docs/guide/api.html` собирается Redoc без оболочки инструкции, поэтому навигация ставится отдельной строкой сразу после `<body>`; стили встроенные, чтобы не подключать `guide.css` к Redoc:

```html
<body>
<nav aria-label="Разделы руководства" style="display:flex;flex-wrap:wrap;gap:4px;padding:10px 16px;background:#0b1220;border-bottom:1px solid #1d2a44;font:14px/1.4 'Segoe UI',Arial,sans-serif">
  <a href="index.html" style="color:#b7c4dd;text-decoration:none;padding:4px 10px;border-radius:6px">Что умеет сервис</a>
  <a href="protocol.html" style="color:#b7c4dd;text-decoration:none;padding:4px 10px;border-radius:6px">Протокол прогона</a>
  <a href="client.html" style="color:#b7c4dd;text-decoration:none;padding:4px 10px;border-radius:6px">Клиент</a>
  <a href="api.html" aria-current="page" style="color:#fff;background:#1b2b4d;text-decoration:none;padding:4px 10px;border-radius:6px">API-справочник</a>
</nav>
  
    <div id="redoc"></div>
```

- [ ] **Step 5: Обновить главную страницу инструкции**

В `docs/guide/index.html`:

1. После вводного абзаца героя добавить абзац:

```html
      <p>Windows-клиент 0.1.0-preview — менеджер доступа: вход, устройство, профиль и готовый <code>.conf</code>. Собственного туннеля в нём нет; <a href="client.html">страница клиента</a> показывает, что проверено, а что — нет.</p>
```

2. Заменить бейдж:

```html
        <span class="badge badge--warning">Клиент ещё не выпущен</span>
```

на:

```html
        <span class="badge badge--accent">Windows-клиент preview 0.1.0</span>
```

3. В `summary-strip` после элемента «Приватный ключ в конфиге» добавить:

```html
        <div><dt>Экранов клиента</dt><dd>5</dd></div>
```

4. Заменить `Восемь областей серверной части` на `Девять областей: восемь серверных и Windows-клиент preview` и добавить карточку после карточки «Профили»:

```html
        <div class="card">
          <span class="card__kicker">Windows-клиент (preview)</span>
          <h3>Менеджер доступа и готовый .conf</h3>
          <p>Клиент 0.1.0-preview входит и регистрирует устройство, хранит ключ X25519 локально, выдаёт и отзывает профиль и собирает файл для официального WireGuard. Собственного туннеля нет: состояния «подключено» приложение не показывает.</p>
        </div>
```

5. В разделе «План и макет» заменить заголовок и вводный абзац:

```html
      <h2>Витрина и клиент: что это не доказывает</h2>
      <p class="section-lede">Клиент preview существует как менеджер доступа: сценарий, ограничения и кадры — на <a href="client.html">отдельной странице</a>. Снимки ниже — по-прежнему витрина запланированного интерфейса туннеля, а не работающий VPN-клиент.</p>
```

6. Заменить предупреждение раздела:

```html
      <div class="note note--warning">
        <strong>Туннель — не в клиенте.</strong> Windows-клиент 0.1.0-preview только выдаёт профиль и файл
        <code>.conf</code> для официального WireGuard. Собственного туннеля, установщика, системной блокировки
        трафика при обрыве и раздельной маршрутизации приложений нет.
      </div>
```

7. В карточке «Не реализовано» заменить первый пункт `Клиентские приложения, в том числе Windows` на:

```html
            <li>Собственный туннель в Windows-клиенте (E-2)</li>
            <li>Установщик, подпись кода и автообновление (E-3)</li>
```

8. В карточку «Не подтверждено испытаниями» добавить пункты:

```html
            <li>Импорт <code>.conf</code> в официальный WireGuard на этой машине</li>
            <li>Windows 10 и второй пользователь Windows для DPAPI</li>
            <li>Клиент против публичного HTTPS API с настоящим сертификатом</li>
```

9. Заменить подвал:

```html
      <p>NovaVPN, циклы A-3 и E-1. Инструкция обновлена 2026-11-24. Секреты не публикуются: пароли и токены заменены пометкой, приватные ключи не покидают устройство, узел и DPAPI-хранилище. Версия контракта — <a href="../../api-spec/openapi.yaml">OpenAPI</a>.</p>
```

- [ ] **Step 6: Обновить README**

В `README.md`:

1. Заменить строку статуса:

```markdown
> **Статус: активная разработка, не готовый сервис.** В `main` завершены циклы A-1–A-3: ядро доступа, профили, узловой агент и сквозной стенд. Windows-клиент 0.1.0-preview — менеджер доступа: он выдаёт профиль и файл `.conf`, но туннель не поднимает. Установщика, подписи кода и системной блокировки трафика при обрыве нет. Скриншоты витрины показывают дизайн-систему, а кадры клиента сняты с заглушки интерфейса.
```

2. После абзаца о реализованном серверном управлении (перед разделом «Дизайн и скриншоты») добавить раздел:

```markdown
## Windows-клиент (preview)

Клиент 0.1.0-preview — [менеджер доступа](docs/guide/client.html), а не VPN-туннель. Он регистрирует устройство с локальной парой X25519, выдаёт и отзывает профиль, собирает готовый `.conf` с локальным приватным ключом и сохраняет его системным диалогом; подключение выполняет официальный клиент WireGuard.

- Интерфейс — HTML/CSS из дизайн-системы в WebView2 поверх WinForms. Виртуальный origin `https://app.novavpn.local/`, слушающего порта нет, `AddHostObjectToScript` не используется.
- Refresh-токен и приватные ключи хранятся под DPAPI `CurrentUser`; access-токен живёт только в памяти; пароль не сохраняется и не журналируется.
- Собственного туннеля, kill switch, раздельной маршрутизации, установщика и автообновления нет.
- Сборка, самопроверка и ограничения — на [странице клиента](docs/guide/client.html); решение об оболочке — [ADR-0010](docs/adr/0010-windows-client-shell.md).
```

3. В mermaid-схеме заменить подписи:

```mermaid
flowchart LR
    C[Windows-клиент preview: выдаёт .conf] -->|Сессия и профиль| API[Управляющий API на Go]
    API --> DB[(PostgreSQL)]
    API --> R[(Redis)]
    N[Узловой агент A-3] -->|HTTPS: конфигурация и отчёты| API
    N -->|Применение изменений| WG[WireGuard в ядре Linux]
    C -.->|Импорт .conf в официальный WireGuard| WG
    WG -.-> NET[Интернет]
```

4. В таблицу «Технологии» добавить строку:

```markdown
| Windows-клиент | .NET 10, WinForms, WebView2, BouncyCastle (X25519), DPAPI |
```

5. В блок проверок добавить команды клиента и строки таблицы:

```bash
dotnet restore client/NovaVpn.Client.sln --locked-mode
dotnet test client/NovaVpn.Client.sln -c Release
dotnet run --project client/src/NovaVpn.Client.App -c Release -- --selftest
make client-e2e
```

```markdown
| `dotnet test client/NovaVpn.Client.sln` | Модульные тесты клиентского ядра, сборки `.conf` и контрактов моста |
| `--selftest` | Настоящий WebView2: ассеты, CSP, `app.info`, консоль, код возврата 0 |
| `make client-e2e` | Живой путь против dev-стенда: выдача, сохранение `.conf`, отзыв |
```

6. В таблицу «Структура репозитория» добавить строку:

```markdown
| [`client/`](client/) | Windows-клиент preview: ядро, приложение, тесты, интерфейс и скрипты |
```

7. В таблице «Этапы развития» заменить строку A-3 и добавить строки E-1–E-3:

```markdown
| A-3 | Агент узла, настоящий туннель, DNS, TLS, развёртывание и сквозные испытания | Завершён, в `main` |
| E-1 | Windows-клиент: менеджер доступа и `.conf` без собственного туннеля | Preview, ветка `cycle/e1-windows-access-manager` |
| E-2 | Собственный туннель, kill switch и раздельная маршрутизация после спайка S4 | Запланирован |
| E-3 | Установщик, подпись кода и автообновление | Запланирован |
```

8. Заменить абзац о нереализованном:

```markdown
Сквозные испытания на контейнерном стенде подтвердили реальную работу туннеля и отсутствие утечек DNS и IPv6-трафика в границах стенда (приёмка задачи 18, `docs/testing-status.md`); на реальной инфраструктуре эти проверки впереди — задача 19. Пока **не реализованы или не подтверждены сквозными испытаниями**: собственный туннель в Windows-клиенте, системная блокировка трафика при обрыве VPN, раздельная маршрутизация приложений, установщик и подпись клиента, публичное развёртывание узла, платежи и нагрузочные показатели. Не используйте текущую сборку как доказанную защиту трафика.
```

9. В список документации добавить:

```markdown
- [Windows-клиент preview: сборка, экраны и границы](docs/guide/client.html)
- [Почему клиент использует WebView2 без локального сервера](docs/adr/0010-windows-client-shell.md)
```

- [ ] **Step 7: Записать E-1 в статус проверок**

В `docs/testing-status.md`:

1. В глобальной таблице `not-run` заменить строку про клиентов:

```markdown
| Собственный туннель, kill switch, split tunnel и отключение IPv6 на реальной ОС | клиент E-1 — только менеджер доступа: он выдаёт `.conf` и не управляет сетью; WireGuardNT, wintun и привилегированный сервис относятся к E-2 после спайка S4; пиксельную отрисовку окна агент не видит | цикл E-2, спайк S4 (ADR-008) |
```

2. В той же таблице перед заключительным абзацем «Ни одна строка «Проверено»…» добавить:

```markdown
| Импорт сохранённого `.conf` в официальный клиент WireGuard на машине сборки | WireGuard там не установлен; клиент проверяет только сборку и байты файла, а handshake из импортированного профиля не наблюдался | отдельная проверка на Windows с установленным WireGuard |
| Windows 10 и второй пользователь Windows для DPAPI | прогоны шли на Windows 11 (10.0.26300) под одной учётной записью; энтропии `CurrentUser` и права файлов под вторым профилем не наблюдались | отдельная проверка на Windows 10 и втором пользователе |
| Установщик, подпись кода и автообновление клиента | в E-1 только portable-каталог и zip; установщика и сертификата подписи нет | цикл E-3 |
| `--selftest` в CI | на GitHub-раннере нет WebView2 Runtime и интерактивной сессии; в CI выполняются только `restore --locked-mode` и `dotnet test` | отдельная Windows-машина или self-hosted раннер при появлении |
| Windows-джоба CI клиента | workflow объявляет джобу `windows-client`, но прогон состоится только после пуша; локально выполнены restore, test и publish | пуш ветки цикла E-1 |
| Клиент против публичного HTTPS API с настоящим сертификатом | живой E2E идёт на HTTP-стенде `127.0.0.1:18080`; правила origin разрешают HTTP только для loopback, но внешний TLS-путь не проигрывался | цикл E-1/E-2 на реальном API |
| Пиксельная отрисовка окна WebView2 | агент не видит GUI; `--selftest` проверяет загрузку, CSP и консоль, а кадры инструкции сняты с заглушки в браузере | визуальный просмотр человеком на Windows |
```

3. В конец файла добавить раздел:

```markdown
## Цикл E-1: Windows-клиент — 2026-11-24

Проверки выполнены на Windows 11 (10.0.26300) с .NET SDK 10.0.204. Журналы прогонов —
`e1-task12-dotnet-test.log`, `e1-task12-selftest.log`, `e1-task12-selftest-red.log`,
`e1-task12-client-e2e.log`, `e1-task12-publish.log` в каталоге постановки задачи; числа
ниже прочитаны из этих журналов, а не пересказаны.

| что | чем подтверждено | как повторить |
| --- | --- | --- |
| Клиентское ядро: адрес API, конверт ошибки, запрет редиректов, DPAPI-хранилище, сессия с single-flight refresh, X25519, сборка `.conf`, маршрутизатор моста | `dotnet test client/NovaVpn.Client.sln -c Release` — итоговая строка `Passed!` с `Failed: 0`; падение каждой группы проверялось до реализации в задачах 2–7 (`e1-task12-dotnet-test.log`) | `dotnet test client/NovaVpn.Client.sln -c Release` |
| WebView2 грузит настоящие ассеты, CSP не ломает интерфейс, мост отвечает на `app.info`, консольных ошибок нет | `dotnet run --project client/src/NovaVpn.Client.App -c Release -- --selftest` — `selftest: ok`, код 0 (`e1-task12-selftest.log`); красный замер: замена `connect-src 'none'` на `'self'` дала код 5, файл восстановлен (`e1-task12-selftest-red.log`) | та же команда; красный — временно изменить CSP в `ui/index.html` и вернуть |
| Живой путь клиента против dev-стенда: вход, устройство, каталог, выдача, сборка и сохранение `.conf`, отказ после отзыва, удаление устройства | `make client-e2e` — `E2E PREPARE OK`, `E2E OK`, строка `E2E_FILE=` с байтами файла, повторное получение после отзыва отклонено; отдельный `psql`-запрос печатает `после уборки: 0\|0` (`e1-task12-client-e2e.log`) | `make client-e2e` при свободном dev-стенде |
| Вёрстка и потоки интерфейса на заглушке моста: баннер виден, четыре ширины без горизонтального вылета, каталог и профиль в честных состояниях, консоль без ошибок | Playwright по `http://127.0.0.1:4173/?stub=1`: `document.documentElement.scrollWidth <= clientWidth` — `true` на 1440, 900, 720 и 360; кадры `client-home-dark.png`, `client-home-light.png`, `client-catalog.png`, `client-diagnostics.png` просмотрены | `node client/scripts/serve-ui.mjs client/ui 4173`, затем браузерный MCP |
| Portable-сборка: publish даёт exe и каталог `ui/`, zip содержит exe, ядро, страницы и восемь шрифтов, файлов сессий и журналов в нём нет | `dotnet publish … -o client/dist/win-x64`, затем `Compress-Archive`; проверка состава zip — вывод `zip ok: <число> files, 8 fonts, <число> bytes` с фактическими числами из журнала, поиск `*.log`, `.env`, `session`, `device-key` — пусто (`e1-task12-publish.log`) | команды шага 9 задачи 12 |
```

- [ ] **Step 8: Снять кадры с заглушки**

Поднять статический сервер UI:

```bash
node client/scripts/serve-ui.mjs client/ui 4173
```

В браузерном MCP (Playwright):

1. `browser_navigate` → `http://127.0.0.1:4173/?stub=1`.
2. `browser_resize` → 900×700; `browser_emulate_media` → `colorScheme: "dark"`.
3. Заполнить `#auth-origin` значением `https://api.novavpn.test/`, нажать «Сохранить адрес».
4. Заполнить `#auth-email` значением `demo@novavpn.test`, `#auth-password` — `demo-password` (12 символов), нажать «Войти».
5. Дождаться видимости `#screen-home`; в `#issue-select` выбрать значение `33333333-3333-4333-8333-333333333333` (ams-1), нажать `#issue-button`.
6. `browser_take_screenshot` — `type: "png"`, `fullPage: true`, `filename: "client-home-dark.png"`.
7. Нажать `[data-screen="catalog"]`, снять `client-catalog.png`; нажать `[data-screen="diagnostics"]`, снять `client-diagnostics.png`.
8. `browser_emulate_media` → `colorScheme: "light"`; вернуться на `[data-screen="home"]`; снять `client-home-light.png`.
9. `browser_console_messages` — ни одного сообщения уровня `error`.

Инструмент кладёт файлы в свой корень; перенести каждый в документацию по пути из результата:

```bash
cp "<путь из результата browser_take_screenshot>" docs/images/guide/client-home-dark.png
cp "<путь из результата browser_take_screenshot>" docs/images/guide/client-home-light.png
cp "<путь из результата browser_take_screenshot>" docs/images/guide/client-catalog.png
cp "<путь из результата browser_take_screenshot>" docs/images/guide/client-diagnostics.png
```

Просмотреть все четыре файла через `Read`. На каждом обязан быть виден баннер «Демонстрационные данные (заглушка моста)», не должно быть обрезанных подписей, пустых мест вместо данных и горизонтальной прокрутки. Если на ширине 900 текст или таблица обрезаны — это дефект `app.css`, а не повод снимать шире: исправить grid `minmax(0,1fr)`/`overflow-wrap` и повторить проверки задачи 9, затем переснять.

Остановить сервер и удалить временные файлы прогона; каталог `client/dist` не трогать — он нужен шагу 9.

- [ ] **Step 9: Собрать portable zip и проверить состав**

```bash
dotnet restore client/NovaVpn.Client.sln -r win-x64 --force-evaluate
dotnet publish client/src/NovaVpn.Client.App -c Release -r win-x64 \
  --self-contained false -p:RestoreLockedMode=true -o client/dist/win-x64
( cd client/dist/win-x64 && powershell.exe -NoProfile -Command \
  "Compress-Archive -Path * -DestinationPath ../NovaVpn-Client-0.1.0-preview-win-x64.zip -Force" )
sha256sum client/dist/NovaVpn-Client-0.1.0-preview-win-x64.zip
```

Проверка состава:

```bash
python - <<'PY'
import os, zipfile
p = "client/dist/NovaVpn-Client-0.1.0-preview-win-x64.zip"
with zipfile.ZipFile(p) as z:
    names = z.namelist()
need = ["NovaVpn.Client.App.exe", "NovaVpn.Client.Core.dll",
        "ui/index.html", "ui/app.css", "ui/app.js", "ui/help.html"]
missing = [n for n in need if n not in names]
fonts = [n for n in names if n.startswith("ui/fonts/") and n.endswith(".woff2")]
bad = [n for n in names if n.endswith((".log", ".env")) or "session" in n.lower() or "device-key" in n.lower()]
assert not missing, missing
assert len(fonts) == 8, fonts
assert not bad, bad
print("zip ok:", len(names), "files,", len(fonts), "fonts,", os.path.getsize(p), "bytes")
PY
```

Expected: `zip ok: … 8 fonts …`. Zip и каталог остаются в `client/dist/` (git-игнор), хеш и число байт — в отчёт задачи. В документации не обещать опубликованный артефакт: это локальная сборка.

- [ ] **Step 10: Проверить страницу клиента в браузере**

```bash
node client/scripts/serve-ui.mjs docs 4174
```

В браузерном MCP:

1. Открыть `http://127.0.0.1:4174/guide/client.html`.
2. На ширинах 1440×900, 900×700, 720×600 и 360×640 выполнить
   ```js
   document.documentElement.scrollWidth <= document.documentElement.clientWidth
   ```
   Expected: `true` на всех четырёх.
3. Проверить, что все четыре кадра загрузились: у каждого `img.naturalWidth > 0`.
4. Нажать «Клиент» в навигации `index.html` и `protocol.html` — переход на `client.html`; в `api.html` навигационная строка видна и ведёт на все четыре страницы.
5. `browser_console_messages` — без ошибок уровня `error`.
6. Остановить сервер.

- [ ] **Step 11: Гигиена и коммит**

```bash
git diff --check
git status --short
git diff --stat
```

Проверить, что в диффе и кадрах нет секретов: поиск по добавленным строкам `password=`, `BEGIN PRIVATE KEY`, `Bearer `, `access_token` не должен находить значений (только слова в тексте). Кадры содержат лишь демонстрационные данные заглушки. Временные каталоги и профили, созданные прогонами, удалить.

```bash
git add docs/adr/0010-windows-client-shell.md docs/adr/README.md \
  docs/guide/client.html docs/guide/index.html docs/guide/protocol.html docs/guide/api.html \
  docs/images/guide/client-home-dark.png docs/images/guide/client-home-light.png \
  docs/images/guide/client-catalog.png docs/images/guide/client-diagnostics.png \
  README.md docs/testing-status.md
git commit -m "docs(e1): клиент preview — ADR-0010, страница инструкции, кадры и статус проверок"
```

