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
