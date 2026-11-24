using System.Net;
using System.Text;

namespace NovaVpn.Client.App.Tests;

internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "novavpn-app-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); }
        catch (IOException) { }
    }
}

internal sealed record CapturedRequest(string Method, string Path,
    string? IdempotencyKey, string? Body);

internal sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, string?, int, HttpResponseMessage> _respond;
    private int _count;

    public StubHandler(Func<HttpRequestMessage, string?, int, HttpResponseMessage> respond) => _respond = respond;

    public List<CapturedRequest> Requests { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken ct)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        _count++;
        Requests.Add(new CapturedRequest(request.Method.Method, request.RequestUri!.PathAndQuery,
            request.Headers.TryGetValues("Idempotency-Key", out var v) ? v.Single() : null, body));
        return _respond(request, body, _count);
    }

    public static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Text(HttpStatusCode status, string text) =>
        new(status) { Content = new StringContent(text, Encoding.UTF8, "text/plain") };
}
