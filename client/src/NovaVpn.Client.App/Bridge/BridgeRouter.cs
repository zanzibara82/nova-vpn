using System.Text;
using System.Text.Json;
using NovaVpn.Client.Core.Api;
using NovaVpn.Client.Core.Diagnostics;
using NovaVpn.Client.Core.Storage;

namespace NovaVpn.Client.App.Bridge;

public sealed class BridgeRouter
{
    public const int MaxMessageBytes = 64 * 1024;
    public const int MaxDepth = 8;

    private const string StorageCorruptedMessage =
        "Хранилище повреждено или принадлежит другому пользователю. Войдите заново.";

    private readonly Dictionary<string, Func<JsonElement, CancellationToken, Task<object?>>> _commands;
    private readonly IBridgeBackend _backend;
    private readonly DiagnosticRing _ring;
    private readonly ClientLog? _log;

    public BridgeRouter(IBridgeBackend backend, DiagnosticRing ring, ClientLog? log = null)
    {
        _backend = backend;
        _ring = ring;
        _log = log;
        // Единственный перечень команд: ключи словаря — это и есть белый список.
        _commands = new(StringComparer.Ordinal)
        {
            ["app.info"] = (_, ct) => AsObject(_backend.GetAppInfoAsync(ct)),
            ["settings.get"] = (_, _) => Task.FromResult<object?>(_backend.GetSettings()),
            ["settings.set"] = (args, ct) => AsObject(_backend.SetSettingsAsync(
                RequireString(args, "api_base_url", 1, 2048), ct)),
            ["session.state"] = (_, ct) => AsObject(_backend.GetSessionStateAsync(ct)),
            ["account.get"] = (_, ct) => AsObject(_backend.GetAccountAsync(ct)),
            ["auth.login"] = (args, ct) => AsObject(_backend.LoginAsync(
                RequireString(args, "email", 1, 254),
                RequireString(args, "password", 10, 1024), ct)),
            ["auth.register"] = (args, ct) => AsObject(_backend.RegisterAsync(
                RequireString(args, "email", 1, 254),
                RequireString(args, "password", 10, 1024), ct)),
            ["auth.logout"] = (_, ct) => AsEmpty(_backend.LogoutAsync(ct)),
            ["devices.list"] = (_, ct) => AsObject(_backend.ListDevicesAsync(ct)),
            ["devices.create"] = (args, ct) => AsObject(_backend.CreateDeviceAsync(
                RequireTrimmedString(args, "name", 1, 64), ct)),
            ["devices.delete"] = (args, ct) => AsEmpty(_backend.DeleteDeviceAsync(
                RequireGuid(args, "device_id"), ct)),
            ["servers.list"] = (_, ct) => AsObject(_backend.ListServersAsync(ct)),
            ["profiles.list"] = (args, ct) => AsObject(_backend.ListProfilesAsync(
                RequireGuid(args, "device_id"), ct)),
            ["profiles.issue"] = (args, ct) => AsObject(_backend.IssueProfileAsync(
                RequireGuid(args, "device_id"), RequireGuid(args, "server_id"), ct)),
            ["profiles.revoke"] = (args, ct) => AsEmpty(_backend.RevokeProfileAsync(
                RequireGuid(args, "device_id"), RequireGuid(args, "server_id"), ct)),
            ["profiles.export"] = (args, ct) => AsObject(_backend.ExportProfileAsync(
                RequireGuid(args, "device_id"), RequireGuid(args, "server_id"), ct)),
            ["diagnostics.get"] = (_, ct) => AsObject(_backend.GetDiagnosticsAsync(ct)),
        };
    }

    public async Task<string> HandleAsync(string json, CancellationToken ct)
    {
        if (Encoding.UTF8.GetByteCount(json) > MaxMessageBytes)
        {
            _ring.Add("oversized", ClientErrorCodes.BadArgs, null);
            return Fail(null, "bad_args", "Сообщение слишком велико.", null, "oversized");
        }

        string? id = null;
        string command = "unknown";
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = MaxDepth });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                // Команда ещё не разобрана — в кольце пустая строка, журнальная строка без изменений.
                _ring.Add("", ClientErrorCodes.BadArgs, null);
                return Fail(null, "bad_args", "Ожидался объект запроса.", null, command);
            }

            id = OptionalId(root);
            if (id is null)
            {
                _ring.Add("", ClientErrorCodes.BadArgs, null);
                return Fail(null, "bad_args", "В запросе нет корректного id.", null, command);
            }

            command = root.TryGetProperty("command", out var c) && c.ValueKind == JsonValueKind.String
                ? c.GetString() ?? ""
                : "";
            if (!_commands.TryGetValue(command, out var handler))
            {
                _ring.Add(command, ClientErrorCodes.UnknownCommand, null);
                return Fail(id, ClientErrorCodes.UnknownCommand, "Неизвестная команда.", null, command);
            }

            var args = root.TryGetProperty("args", out var a) && a.ValueKind == JsonValueKind.Object
                ? a
                : default;
            var data = await handler(args, ct);
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
        catch (StorageCorruptedException)
        {
            _ring.Add(command, ClientErrorCodes.StorageCorrupted, null);
            return Fail(id, ClientErrorCodes.StorageCorrupted, StorageCorruptedMessage, null, command);
        }
        catch (Exception ex)
        {
            _ring.Add(command, $"internal:{ex.GetType().Name}", null);
            return Fail(id, "internal", "Внутренняя ошибка клиента.", null, command);
        }
    }

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
        var value = RequireRawString(args, name);
        if (value.Length < min || value.Length > max)
            throw new CommandArgumentException($"Поле {name} имеет недопустимую длину.");
        return value;
    }

    /// <summary>Обрезка выполняется до проверки длины: имя из одних пробелов не проходит лимит 1..64.</summary>
    private static string RequireTrimmedString(JsonElement args, string name, int min, int max)
    {
        var value = RequireRawString(args, name).Trim();
        if (value.Length < min || value.Length > max)
            throw new CommandArgumentException($"Поле {name} имеет недопустимую длину.");
        return value;
    }

    private static string RequireRawString(JsonElement args, string name)
    {
        if (args.ValueKind != JsonValueKind.Object
            || !args.TryGetProperty(name, out var p)
            || p.ValueKind != JsonValueKind.String)
            throw new CommandArgumentException($"Поле {name} обязательно.");
        return p.GetString() ?? "";
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
            "storage_corrupted" => StorageCorruptedMessage,
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
