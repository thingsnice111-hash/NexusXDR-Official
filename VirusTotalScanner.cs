using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace NexusAV.Engine;

public sealed class VirusTotalResult
{
    public bool IsMalicious { get; set; }
    public int MaliciousCount { get; set; }
    public int TotalEngines { get; set; }
    public string SHA256 { get; set; } = string.Empty;
    public string DetectionNames { get; set; } = string.Empty;
    public DateTime ScanDate { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
    /// <summary>True when the hash was unknown and the file was deliberately NOT uploaded (hash-only mode).</summary>
    public bool UploadSkipped { get; set; }
}

public sealed class VirusTotalScanner : IDisposable
{
    private const string API_BASE = "https://www.virustotal.com/api/v3";
    private string _apiKey;

    public bool HasApiKey => !string.IsNullOrEmpty(_apiKey);

    private readonly HttpClient _httpClient;
    private readonly Dictionary<string, VirusTotalResult> _cache = new();
    private readonly object _cacheLock = new();
    private readonly Timer _cacheCleanupTimer;
    private readonly SemaphoreSlim _rateLimiter = new(4, 4); // 4 concurrent requests
    private int _disposed;

    public VirusTotalScanner(string? apiKey = null)
    {
        _apiKey = apiKey ?? Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY") ?? "";
        _httpClient = new HttpClient();
        if (!string.IsNullOrEmpty(_apiKey))
        {
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
        }
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _httpClient.Timeout = TimeSpan.FromSeconds(30);

        // Cleanup cache every hour
        _cacheCleanupTimer = new Timer(CleanupCache, null, TimeSpan.FromHours(1), TimeSpan.FromHours(1));
    }

    /// <summary>Configure the API key at runtime (from the console UI). Applies to future requests.</summary>
    public void SetApiKey(string apiKey)
    {
        _apiKey = apiKey ?? string.Empty;
        _httpClient.DefaultRequestHeaders.Remove("x-apikey");
        if (!string.IsNullOrEmpty(_apiKey))
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
    }

    /// <summary>Look up a cached hash verdict (lowercase-hex key, same as ScanFileAsync).</summary>
    public bool TryGetCachedVerdict(byte[] sha256, out int malicious, out int total)
    {
        malicious = 0;
        total = 0;
        if (sha256 == null || sha256.Length == 0) return false;
        string key;
        try { key = Convert.ToHexString(sha256).ToLowerInvariant(); }
        catch { return false; }
        try
        {
            lock (_cacheLock)
            {
                if (_cache.TryGetValue(key, out var r))
                {
                    malicious = r.MaliciousCount;
                    total = r.TotalEngines;
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    /// <summary>
    /// Real connectivity + key validation against the VT users/me endpoint.
    /// Returns (ok, humanStatus). 200 => valid key; 401/403 => bad key; else network/other.
    /// </summary>
    public async Task<(bool Ok, string Status)> TestConnectivity(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_apiKey))
            return (false, "No API key configured");
        try
        {
            using var resp = await _httpClient.GetAsync($"{API_BASE}/users/me", cancellationToken);
            int code = (int)resp.StatusCode;
            if (code == 200)
            {
                string quota = "Quota: available";
                try
                {
                    var content = await resp.Content.ReadAsStringAsync(cancellationToken);
                    using var doc = JsonDocument.Parse(content);
                    if (doc.RootElement.TryGetProperty("data", out var d)
                        && d.TryGetProperty("attributes", out var a)
                        && a.TryGetProperty("api_requests", out var ar)
                        && ar.TryGetProperty("day", out var day))
                        quota = $"Public quota/day: {day.GetInt32()}";
                }
                catch { /* status still valid */ }
                return (true, $"Connected. Key valid. {quota}");
            }
            if (code == 401 || code == 403)
                return (false, $"Key rejected (HTTP {code}) — invalid or revoked API key");
            return (false, $"HTTP {code}");
        }
        catch (Exception ex)
        {
            return (false, $"Connection failed: {ex.Message}");
        }
    }

    /// <summary>Scan an arbitrary file path (bypasses trusted-path/exclusion filters). Used by the on-demand scan button — uploads unknown files so a full verdict is produced.</summary>
    public Task<VirusTotalResult> ScanAnyFileAsync(string filePath, CancellationToken cancellationToken = default)
        => ScanFileAsync(filePath, uploadIfUnknown: true, cancellationToken);

    /// <summary>
    /// Hash-lookup a file's reputation. When <paramref name="uploadIfUnknown"/> is false and VT has
    /// never seen the hash, the file is NOT uploaded — files must never leave the machine from
    /// background watchers; only explicit on-demand scans may upload.
    /// </summary>
    public async Task<VirusTotalResult> ScanFileAsync(string filePath, bool uploadIfUnknown = true, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);

        try
        {
            // Calculate SHA256
            string sha256;
            using (var fs = File.OpenRead(filePath))
            using (var sha256Hash = SHA256.Create())
            {
                byte[] hashBytes = await sha256Hash.ComputeHashAsync(fs, cancellationToken);
                sha256 = Convert.ToHexString(hashBytes).ToLowerInvariant();
            }

            // Check cache first (24h validity). A hash-only "not found" entry must not satisfy an
            // upload-capable on-demand scan, or a file the watcher already skipped could never
            // get a real verdict until the cache entry expires.
            lock (_cacheLock)
            {
                if (_cache.TryGetValue(sha256, out var cachedResult))
                {
                    if (DateTime.Now - cachedResult.ScanDate < TimeSpan.FromHours(24))
                    {
                        if (!uploadIfUnknown || !cachedResult.UploadSkipped)
                            return cachedResult;
                    }
                    else
                    {
                        _cache.Remove(sha256);
                    }
                }
            }

            await _rateLimiter.WaitAsync(cancellationToken);
            try
            {
                // Check if file already exists in VT
                var existingResult = await CheckFileExistsAsync(sha256, cancellationToken);
                if (existingResult != null)
                {
                    lock (_cacheLock) _cache[sha256] = existingResult;
                    return existingResult;
                }

                if (!uploadIfUnknown)
                {
                    // Hash-only mode (background watcher): do not upload the user's files
                    // to VirusTotal's public corpus without an explicit action.
                    var skipped = new VirusTotalResult
                    {
                        IsMalicious = false,
                        SHA256 = sha256,
                        UploadSkipped = true,
                        ScanDate = DateTime.Now,
                        ErrorMessage = "Hash not in VirusTotal (upload skipped — hash-only mode)"
                    };
                    lock (_cacheLock) _cache[sha256] = skipped;
                    return skipped;
                }

                // Upload and scan the file
                return await UploadAndScanFileAsync(filePath, sha256, cancellationToken);
            }
            finally
            {
                _rateLimiter.Release();
            }
        }
        catch (Exception ex)
        {
            return new VirusTotalResult
            {
                IsMalicious = false,
                ErrorMessage = $"VirusTotal scan failed: {ex.Message}",
                SHA256 = "unknown"
            };
        }
    }

    private async Task<VirusTotalResult?> CheckFileExistsAsync(string sha256, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _httpClient.GetAsync($"{API_BASE}/files/{sha256}", cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    return null;
                return null;
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken);
            var json = JsonDocument.Parse(content);

            var data = json.RootElement.GetProperty("data");
            var attributes = data.GetProperty("attributes");

            var lastAnalysisStats = attributes.GetProperty("last_analysis_stats");
            int malicious = lastAnalysisStats.GetProperty("malicious").GetInt32();
            int total = 0;
            foreach (var stat in lastAnalysisStats.EnumerateObject())
            {
                total += stat.Value.GetInt32();
            }

            var detectionNames = new List<string>();
            if (malicious > 0)
            {
                var lastAnalysisResults = attributes.GetProperty("last_analysis_results");
                foreach (var engine in lastAnalysisResults.EnumerateObject())
                {
                    var result = engine.Value.GetProperty("category").GetString();
                    if (result == "malicious")
                    {
                        var engineName = engine.Name;
                        var resultName = engine.Value.GetProperty("result").GetString();
                        detectionNames.Add($"{engineName}: {resultName}");
                    }
                }
            }

            return new VirusTotalResult
            {
                IsMalicious = malicious > 0,
                MaliciousCount = malicious,
                TotalEngines = total,
                SHA256 = sha256,
                DetectionNames = string.Join(", ", detectionNames),
                ScanDate = DateTime.Now
            };
        }
        catch
        {
            return null;
        }
    }

    private async Task<VirusTotalResult> UploadAndScanFileAsync(string filePath, string sha256, CancellationToken cancellationToken)
    {
        try
        {
            // /files/upload_url is only for the >32 MB tier; smaller files must go to /files
            // or the endpoint rejects them and the scan never starts.
            var fileInfo = new FileInfo(filePath);
            byte[] fileBytes = await File.ReadAllBytesAsync(filePath, cancellationToken);
            const long LARGE_FILE_BYTES = 32L * 1024 * 1024;

            string targetUrl;
            bool signedUpload = false;
            if (fileInfo.Length > LARGE_FILE_BYTES)
            {
                var uploadUrlResponse = await _httpClient.PostAsync(
                    $"{API_BASE}/files/upload_url",
                    new StringContent($"{{\"size\":{fileBytes.Length}}}", Encoding.UTF8, "application/json"),
                    cancellationToken);

                if (!uploadUrlResponse.IsSuccessStatusCode)
                {
                    return new VirusTotalResult
                    {
                        IsMalicious = false,
                        ErrorMessage = "Failed to get upload URL",
                        SHA256 = sha256
                    };
                }

                var uploadUrlContent = await uploadUrlResponse.Content.ReadAsStringAsync(cancellationToken);
                var uploadUrlJson = JsonDocument.Parse(uploadUrlContent);
                targetUrl = uploadUrlJson.RootElement.GetProperty("data").GetString() ?? string.Empty;
                signedUpload = true;
            }
            else
            {
                targetUrl = $"{API_BASE}/files";
            }

            // /files expects multipart/form-data; the signed upload URL expects the raw bytes.
            HttpContent uploadBody;
            if (signedUpload)
            {
                uploadBody = new ByteArrayContent(fileBytes);
                uploadBody.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            }
            else
            {
                var part = new ByteArrayContent(fileBytes);
                part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                var form = new MultipartFormDataContent();
                form.Add(part, "file", Path.GetFileName(filePath));
                uploadBody = form;
            }

            var uploadResponse = await _httpClient.PostAsync(targetUrl, uploadBody, cancellationToken);
            uploadBody.Dispose();
            if (!uploadResponse.IsSuccessStatusCode)
            {
                return new VirusTotalResult
                {
                    IsMalicious = false,
                    ErrorMessage = "File upload failed",
                    SHA256 = sha256
                };
            }

            // Wait for analysis to complete (poll)
            var analysisResponseContent = await uploadResponse.Content.ReadAsStringAsync(cancellationToken);
            var analysisJson = JsonDocument.Parse(analysisResponseContent);
            string analysisId = analysisJson.RootElement.GetProperty("data").GetProperty("id").GetString() ?? string.Empty;

            // Poll for results (max 60 seconds)
            for (int i = 0; i < 12; i++)
            {
                await Task.Delay(5000, cancellationToken);

                var analysisResponse = await _httpClient.GetAsync(
                    $"{API_BASE}/analyses/{analysisId}",
                    cancellationToken);

                if (analysisResponse.IsSuccessStatusCode)
                {
                    var analysisContent = await analysisResponse.Content.ReadAsStringAsync(cancellationToken);
                    var analysisResultJson = JsonDocument.Parse(analysisContent);
                    var status = analysisResultJson.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("status").GetString();

                    if (status == "completed")
                    {
                        var stats = analysisResultJson.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("stats");
                        int malicious = stats.GetProperty("malicious").GetInt32();
                        int total = 0;
                        foreach (var stat in stats.EnumerateObject())
                        {
                            total += stat.Value.GetInt32();
                        }

                        var result = new VirusTotalResult
                        {
                            IsMalicious = malicious > 0,
                            MaliciousCount = malicious,
                            TotalEngines = total,
                            SHA256 = sha256,
                            ScanDate = DateTime.Now
                        };

                        lock (_cacheLock) _cache[sha256] = result;
                        return result;
                    }
                }
            }

            return new VirusTotalResult
            {
                IsMalicious = false,
                ErrorMessage = "Analysis timeout",
                SHA256 = sha256
            };
        }
        catch (Exception ex)
        {
            return new VirusTotalResult
            {
                IsMalicious = false,
                ErrorMessage = $"Upload failed: {ex.Message}",
                SHA256 = sha256
            };
        }
    }

    public async Task<VirusTotalResult> ScanUrlAsync(string url, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed == 1, this);

        try
        {
            await _rateLimiter.WaitAsync(cancellationToken);
            try
            {
                var content = new StringContent($"{{\"url\":\"{url}\"}}", Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync($"{API_BASE}/urls", content, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    return new VirusTotalResult
                    {
                        IsMalicious = false,
                        ErrorMessage = "URL scan request failed",
                        SHA256 = "url"
                    };
                }

                var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
                var json = JsonDocument.Parse(responseContent);
                string analysisId = json.RootElement.GetProperty("data").GetProperty("id").GetString() ?? string.Empty;

                // Poll for results
                for (int i = 0; i < 12; i++)
                {
                    await Task.Delay(5000, cancellationToken);

                    var analysisResponse = await _httpClient.GetAsync(
                        $"{API_BASE}/analyses/{analysisId}",
                        cancellationToken);

                    if (analysisResponse.IsSuccessStatusCode)
                    {
                        var analysisContent = await analysisResponse.Content.ReadAsStringAsync(cancellationToken);
                        var analysisResultJson = JsonDocument.Parse(analysisContent);
                        var status = analysisResultJson.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("status").GetString();

                        if (status == "completed")
                        {
                            var stats = analysisResultJson.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("stats");
                            int malicious = stats.GetProperty("malicious").GetInt32();
                            int total = 0;
                            foreach (var stat in stats.EnumerateObject())
                            {
                                total += stat.Value.GetInt32();
                            }

                            return new VirusTotalResult
                            {
                                IsMalicious = malicious > 0,
                                MaliciousCount = malicious,
                                TotalEngines = total,
                                SHA256 = "url",
                                ScanDate = DateTime.Now
                            };
                        }
                    }
                }

                return new VirusTotalResult
                {
                    IsMalicious = false,
                    ErrorMessage = "URL analysis timeout",
                    SHA256 = "url"
                };
            }
            finally
            {
                _rateLimiter.Release();
            }
        }
        catch (Exception ex)
        {
            return new VirusTotalResult
            {
                IsMalicious = false,
                ErrorMessage = $"URL scan failed: {ex.Message}",
                SHA256 = "url"
            };
        }
    }

    private void CleanupCache(object? state)
    {
        var cutoff = DateTime.Now - TimeSpan.FromHours(24);
        lock (_cacheLock)
        {
            var keysToRemove = new List<string>();
            foreach (var kvp in _cache)
            {
                if (kvp.Value.ScanDate < cutoff)
                {
                    keysToRemove.Add(kvp.Key);
                }
            }

            foreach (var key in keysToRemove)
            {
                _cache.Remove(key);
            }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _cacheCleanupTimer?.Dispose();
            _rateLimiter?.Dispose();
            _httpClient?.Dispose();
        }
    }
}
