using System.Net;
using System.Text;

namespace NovaVpn.Client.Core.Tests.Support;

internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, int, HttpResponseMessage> _respond;

    public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : this((r, _) => respond(r)) { }

    public StubHandler(Func<HttpRequestMessage, int, HttpResponseMessage> respond) => _respond = respond;

    public List<(string Method, string Path, string? Auth, string? Idem)> Requests { get; } = new();

    public static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Requests.Add((
            request.Method.Method,
            request.RequestUri!.PathAndQuery,
            request.Headers.Authorization?.ToString(),
            request.Headers.TryGetValues("Idempotency-Key", out var v) ? v.Single() : null));
        return Task.FromResult(_respond(request, Requests.Count));
    }
}
