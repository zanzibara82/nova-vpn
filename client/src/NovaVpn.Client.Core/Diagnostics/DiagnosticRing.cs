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
