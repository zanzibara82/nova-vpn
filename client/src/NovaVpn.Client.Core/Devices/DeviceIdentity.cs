namespace NovaVpn.Client.Core.Devices;

public sealed record DeviceIdentity(
    Uri ApiBaseUrl,
    string Email,
    Guid? DeviceId,
    string PublicKey,
    string PrivateKey,
    string Name,
    DateTimeOffset CreatedAt)
{
    /// <summary>
    /// Строковое представление без приватного ключа: <see cref="ToString"/> попадает в логи и
    /// отладочный вывод, поэтому секрет туда не включается.
    /// </summary>
    public override string ToString() =>
        $"DeviceIdentity {{ ApiBaseUrl = {ApiBaseUrl}, Email = {Email}, " +
        $"DeviceId = {(DeviceId is { } id ? id.ToString() : "null")}, " +
        $"PublicKey = {PublicKey}, Name = {Name}, CreatedAt = {CreatedAt:O} }}";
}
