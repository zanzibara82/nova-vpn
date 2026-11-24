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
