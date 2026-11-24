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

    private static string RouterSource()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "client", "src",
                "NovaVpn.Client.App", "Bridge", "BridgeRouter.cs");
            if (File.Exists(candidate)) return File.ReadAllText(candidate);
            dir = dir.Parent;
        }
        throw new InvalidOperationException("BridgeRouter.cs не найден выше каталога тестов.");
    }

    [Theory]
    [InlineData("index.html")]
    [InlineData("help.html")]
    public void Page_declares_exact_csp_and_no_inline_code(string name)
    {
        var html = Read(name);

        Assert.Contains($"content=\"{Csp}\"", html);
        Assert.DoesNotMatch(@"<script(?![^>]*\ssrc=)", html);
        Assert.DoesNotMatch(@"<style", html);
        Assert.DoesNotMatch(@"\sstyle\s*=\s*[""']", html);
        Assert.DoesNotMatch(@"\son[a-z]+\s*=\s*[""']", html);
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

        var attempted = Regex.Matches(js, "(?:attempt|bridge\\.send)\\(\\s*[\"']([a-z0-9._]+)[\"']")
            .Select(m => m.Groups[1].Value);
        var stubCases = Regex.Matches(js, "case\\s+[\"']([a-z0-9._]+)[\"']\\s*:")
            .Select(m => m.Groups[1].Value);
        var used = attempted.Concat(stubCases).ToHashSet(StringComparer.Ordinal);

        var router = Regex.Matches(RouterSource(), "\\[\"([a-z.]+)\"\\]\\s*=")
            .Select(m => m.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);
        Assert.Equal(whitelist.Count, router.Count);
        Assert.Subset(whitelist, router);

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
        Assert.Contains(
            "Конфиг сохранён. Подключение выполняет WireGuard; этот клиент туннелем не управляет.",
            js);
        Assert.Contains("Как подключить", js);
        Assert.Contains("help.href = \"help.html\"", js);
        Assert.Contains("superseded", js);
        Assert.Contains("stubMode && !hasNative", js);
        Assert.Contains("id=\"host-banner\"", html);
        Assert.Contains("Демонстрационные данные (заглушка моста)", html);
        Assert.Contains("туннель не поднимает", html);
        Assert.Contains("Туннель не поднимает", Read("help.html"));
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
        Assert.Contains("JetBrains",
            File.ReadAllText(Path.Combine(UiDir, "fonts", "OFL-JetBrainsMono.txt")));
        Assert.Contains("wireguard.com/install", Read("help.html"));
        Assert.Contains("rel=\"noopener\"", Read("help.html"));
    }

    [Fact]
    public void Page_loads_local_script_and_styles()
    {
        var html = Read("index.html");
        Assert.Matches(@"<link[^>]*rel=""stylesheet""[^>]*href=""app\.css""", html);
        Assert.Matches(@"<script[^>]*src=""app\.js""[^>]*defer", html);
    }

    [Fact]
    public void Styles_use_only_local_fonts_and_assets()
    {
        var css = Read("app.css");
        Assert.DoesNotContain("http://", css);
        Assert.DoesNotContain("https://", css);
        Assert.DoesNotContain("@import", css);
        Assert.Equal(8, Regex.Matches(css, "@font-face").Count);

        var urls = Regex.Matches(css, "url\\(\"([^\"]+)\"\\)")
            .Select(m => m.Groups[1].Value)
            .ToList();
        Assert.Equal(8, urls.Count);
        foreach (var url in urls)
        {
            Assert.StartsWith("fonts/", url);
            Assert.True(File.Exists(Path.Combine(UiDir, url)), $"нет файла {url}");
        }
    }
}
