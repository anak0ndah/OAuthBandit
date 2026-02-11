using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace OAuthBandit.Mfa;

public class GraphClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly string _accessToken;

    public GraphClient(string accessToken)
    {
        _accessToken = accessToken;
    }

    public JsonElement? Get(string url)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            req.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

            var resp = Http.SendAsync(req).Result;
            if (!resp.IsSuccessStatusCode) return null;

            var json = resp.Content.ReadAsStringAsync().Result;
            return JsonDocument.Parse(json).RootElement.Clone();
        }
        catch { return null; }
    }

    public (JsonElement? result, int statusCode, string? errorCode, string? errorMessage) GetDetailed(string url)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            req.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

            var resp = Http.SendAsync(req).Result;
            var json = resp.Content.ReadAsStringAsync().Result;

            if (resp.IsSuccessStatusCode)
                return (JsonDocument.Parse(json).RootElement.Clone(), (int)resp.StatusCode, null, null);

            try
            {
                var err = JsonDocument.Parse(json).RootElement;
                var code = err.TryGetProperty("error", out var e) && e.TryGetProperty("code", out var c) ? c.GetString() : null;
                var msg = err.TryGetProperty("error", out var e2) && e2.TryGetProperty("message", out var m) ? m.GetString() : null;
                return (null, (int)resp.StatusCode, code, msg);
            }
            catch
            {
                return (null, (int)resp.StatusCode, null, null);
            }
        }
        catch (Exception ex) { return (null, 0, null, ex.Message); }
    }

    public (JsonElement? result, int statusCode, string? errorCode, string? errorMessage) Post(string url, object data)
    {
        try
        {
            var jsonBody = JsonSerializer.Serialize(data);
            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            req.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            req.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

            var resp = Http.SendAsync(req).Result;
            var responseJson = resp.Content.ReadAsStringAsync().Result;

            if (resp.IsSuccessStatusCode)
            {
                if (string.IsNullOrWhiteSpace(responseJson))
                    return (null, (int)resp.StatusCode, null, null);
                return (JsonDocument.Parse(responseJson).RootElement.Clone(), (int)resp.StatusCode, null, null);
            }

            try
            {
                var err = JsonDocument.Parse(responseJson).RootElement;
                var code = err.TryGetProperty("error", out var e) && e.TryGetProperty("code", out var c) ? c.GetString() : null;
                var msg = err.TryGetProperty("error", out var e2) && e2.TryGetProperty("message", out var m) ? m.GetString() : null;
                return (null, (int)resp.StatusCode, code, msg);
            }
            catch
            {
                return (null, (int)resp.StatusCode, null, null);
            }
        }
        catch (Exception ex) { return (null, 0, null, ex.Message); }
    }
}
