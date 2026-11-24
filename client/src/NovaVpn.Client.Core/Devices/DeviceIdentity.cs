namespace NovaVpn.Client.Core.Devices;

public sealed record DeviceIdentity(
    Uri ApiBaseUrl,
    string Email,
    Guid? DeviceId,
    string PublicKey,
    string PrivateKey,
    string Name,
    DateTimeOffset CreatedAt);
