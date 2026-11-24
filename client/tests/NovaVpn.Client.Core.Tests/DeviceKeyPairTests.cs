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
