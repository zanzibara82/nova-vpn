namespace NovaVpn.Client.Core.Tests;

public sealed class ClientVersionTests
{
    [Fact]
    public void Version_is_preview()
    {
        Assert.Equal("0.1.0-preview", ClientVersion.Value);
    }
}
