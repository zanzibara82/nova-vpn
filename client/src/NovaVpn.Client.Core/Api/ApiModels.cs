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
