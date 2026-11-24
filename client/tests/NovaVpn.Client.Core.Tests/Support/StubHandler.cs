using System.Net;
using System.Text;

namespace NovaVpn.Client.Core.Tests.Support;

internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, int, HttpResponseMessage> _respond;
    private readonly object _gate = new();

    public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : this((r, _) => respond(r)) { }

    public StubHandler(Func<HttpRequestMessage, int, HttpResponseMessage> respond) => _respond = respond;

    public List<Captured> Requests { get; } = new();

    internal sealed record Captured(string Method, string Path, string? Auth, string? Idem, string? Body);

    public static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Text(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "text/plain") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        int ordinal;
        lock (_gate)
        {
            Requests.Add(new Captured(
                request.Method.Method,
                request.RequestUri!.PathAndQuery,
                request.Headers.Authorization?.ToString(),
                request.Headers.TryGetValues("Idempotency-Key", out var v) ? v.Single() : null,
                body));
            ordinal = Requests.Count;
        }
        return _respond(request, ordinal);
    }
}
