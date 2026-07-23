using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace LiteMonitor.src.Plugins.Native
{
    /// <summary>
    /// 复用本机 Kimi Code CLI 登录态，获取 7 天配额和短期限额窗口。
    /// 凭据仅发送到 Kimi 官方认证与用量端点，不写入 LiteMonitor 设置或日志。
    /// </summary>
    public static class KimiQuotaNative
    {
        private const string ClientId = "17e5f671-d194-4dfb-9706-5516cb48c098";
        private const string TokenUrl = "https://auth.kimi.com/api/oauth/token";
        private const string UsageUrl = "https://api.kimi.com/coding/v1/usages";
        private const long MaxCredentialBytes = 256 * 1024;
        private const long MaxResponseBytes = 1024 * 1024;
        private const long RefreshThresholdSeconds = 300;

        private static readonly object ClientLock = new();
        private static readonly SemaphoreSlim CredentialLock = new(1, 1);
        private static HttpClient _client = CreateClient();

        private sealed class AuthContext
        {
            public string AccessToken { get; init; } = "";
            public string RefreshToken { get; init; } = "";
            public DateTimeOffset? ExpiresAt { get; init; }
            public string CredentialPath { get; init; } = "";
            public string KimiHome { get; init; } = "";
            public bool IsApiKey { get; init; }
        }

        private sealed class RefreshResult
        {
            public string AccessToken { get; init; } = "";
            public string RefreshToken { get; init; } = "";
            public long ExpiresIn { get; init; }
        }

        private sealed class QuotaWindow
        {
            public double Limit { get; init; }
            public double Used { get; init; }
            public double Remaining { get; init; }
            public double UsedPercent { get; init; }
            public DateTimeOffset? ResetsAt { get; init; }
        }

        private static HttpClient CreateClient()
        {
            var handler = new SocketsHttpHandler
            {
                AutomaticDecompression =
                    DecompressionMethods.GZip |
                    DecompressionMethods.Deflate |
                    DecompressionMethods.Brotli,
                AllowAutoRedirect = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                MaxConnectionsPerServer = 2,
                UseProxy = true,
                Proxy = WebRequest.GetSystemWebProxy()
            };

            // Kimi 凭据属于敏感信息，始终使用系统默认 TLS 证书校验。
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(12)
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("KimiCLI/1.6");
            return client;
        }

        private static HttpClient GetClient()
        {
            lock (ClientLock)
            {
                return _client;
            }
        }

        public static void ResetClient()
        {
            HttpClient oldClient;
            lock (ClientLock)
            {
                oldClient = _client;
                _client = CreateClient();
            }

            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(15));
                try { oldClient.Dispose(); } catch { }
            });
        }

        public static async Task<string> FetchAsync(CancellationToken cancellationToken = default)
        {
            AuthContext auth = await GetValidAuthAsync(forceRefresh: false, cancellationToken);

            try
            {
                string rawJson = await FetchUsageJsonAsync(auth.AccessToken, cancellationToken);
                return NormalizeUsageResponse(rawJson);
            }
            catch (UnauthorizedAccessException) when (!auth.IsApiKey)
            {
                // expires_at 可能因休眠或时钟变化而不准确，401/403 时强制刷新一次。
                auth = await GetValidAuthAsync(forceRefresh: true, cancellationToken);
                string rawJson = await FetchUsageJsonAsync(auth.AccessToken, cancellationToken);
                return NormalizeUsageResponse(rawJson);
            }
        }

        private static async Task<AuthContext> GetValidAuthAsync(
            bool forceRefresh,
            CancellationToken cancellationToken)
        {
            await CredentialLock.WaitAsync(cancellationToken);
            try
            {
                AuthContext auth = LoadAuth();
                if (auth.IsApiKey) return auth;

                bool needsRefresh =
                    forceRefresh ||
                    string.IsNullOrEmpty(auth.AccessToken) ||
                    (auth.ExpiresAt != null &&
                     auth.ExpiresAt.Value <= DateTimeOffset.UtcNow.AddSeconds(RefreshThresholdSeconds));

                if (!needsRefresh) return auth;
                if (string.IsNullOrEmpty(auth.RefreshToken))
                {
                    throw new InvalidOperationException("Kimi 登录已过期，请运行 kimi login 重新登录。");
                }

                RefreshResult refreshed = await RefreshAccessTokenAsync(auth, cancellationToken);
                bool saved = PersistRefreshedTokens(auth, refreshed);

                if (!saved)
                {
                    // 请求期间若 Kimi CLI 已轮换 refresh_token，使用它刚写入的新凭据。
                    AuthContext concurrentAuth = LoadAuth();
                    if (!string.IsNullOrEmpty(concurrentAuth.AccessToken))
                    {
                        return concurrentAuth;
                    }
                    throw new IOException("Kimi 凭据在刷新期间发生变化，请稍后重试。");
                }

                return new AuthContext
                {
                    AccessToken = refreshed.AccessToken,
                    RefreshToken = refreshed.RefreshToken,
                    ExpiresAt = refreshed.ExpiresIn > 0
                        ? DateTimeOffset.UtcNow.AddSeconds(refreshed.ExpiresIn)
                        : null,
                    CredentialPath = auth.CredentialPath,
                    KimiHome = auth.KimiHome,
                    IsApiKey = false
                };
            }
            finally
            {
                CredentialLock.Release();
            }
        }

        private static AuthContext LoadAuth()
        {
            string apiKey = Environment.GetEnvironmentVariable("KIMI_API_KEY") ?? "";
            string? credentialPath = FindCredentialPath(out string kimiHome);
            if (credentialPath == null)
            {
                if (!string.IsNullOrWhiteSpace(apiKey))
                {
                    return new AuthContext
                    {
                        AccessToken = apiKey.Trim(),
                        IsApiKey = true
                    };
                }
                throw new FileNotFoundException("未找到 Kimi Code 登录信息，请先运行 kimi login。");
            }

            string raw = ReadLimitedFile(credentialPath, MaxCredentialBytes, "Kimi 登录信息不可用。");
            using var document = JsonDocument.Parse(raw);
            JsonElement root = document.RootElement;

            string accessToken = GetString(root, "access_token", "accessToken");
            string refreshToken = GetString(root, "refresh_token", "refreshToken");
            if (string.IsNullOrEmpty(accessToken) && string.IsNullOrEmpty(refreshToken))
            {
                if (!string.IsNullOrWhiteSpace(apiKey))
                {
                    return new AuthContext
                    {
                        AccessToken = apiKey.Trim(),
                        IsApiKey = true
                    };
                }
                throw new InvalidOperationException("Kimi Code 登录信息中没有可用凭据，请运行 kimi login。");
            }

            return new AuthContext
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresAt = GetCredentialExpiration(root),
                CredentialPath = credentialPath,
                KimiHome = kimiHome,
                IsApiKey = false
            };
        }

        private static string? FindCredentialPath(out string kimiHome)
        {
            string userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string configuredHome = Environment.GetEnvironmentVariable("KIMI_CODE_HOME") ?? "";

            var homes = new List<string>();
            if (!string.IsNullOrWhiteSpace(configuredHome)) homes.Add(configuredHome.Trim());
            homes.Add(Path.Combine(userHome, ".kimi-code"));
            homes.Add(Path.Combine(userHome, ".kimi"));

            foreach (string home in homes.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                string path = Path.Combine(home, "credentials", "kimi-code.json");
                if (File.Exists(path))
                {
                    kimiHome = home;
                    return path;
                }
            }

            kimiHome = "";
            return null;
        }

        private static DateTimeOffset? GetCredentialExpiration(JsonElement root)
        {
            if (!TryGetProperty(root, out var value, "expires_at", "expiresAt")) return null;

            double timestamp;
            if (value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out timestamp))
            {
                return UnixTimestampToDateTime(timestamp);
            }
            if (value.ValueKind == JsonValueKind.String)
            {
                string raw = value.GetString() ?? "";
                if (double.TryParse(
                        raw,
                        NumberStyles.Float,
                        CultureInfo.InvariantCulture,
                        out timestamp))
                {
                    return UnixTimestampToDateTime(timestamp);
                }
                if (DateTimeOffset.TryParse(
                        raw,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal,
                        out var parsed))
                {
                    return parsed;
                }
            }

            return null;
        }

        private static DateTimeOffset? UnixTimestampToDateTime(double timestamp)
        {
            if (timestamp <= 0) return null;
            if (timestamp > 100_000_000_000) timestamp /= 1000;
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds((long)timestamp);
            }
            catch
            {
                return null;
            }
        }

        private static async Task<RefreshResult> RefreshAccessTokenAsync(
            AuthContext auth,
            CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, TokenUrl);
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = ClientId,
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = auth.RefreshToken
            });
            AddKimiAuthHeaders(request, auth.KimiHome);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(12));

            using HttpResponseMessage response = await GetClient().SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token);
            string rawJson = await ReadLimitedStringAsync(response.Content, timeout.Token);

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                throw new InvalidOperationException("Kimi 登录已过期，请运行 kimi login 重新登录。");
            }
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Kimi 登录刷新失败（HTTP {(int)response.StatusCode}）。");
            }

            using var document = JsonDocument.Parse(rawJson);
            JsonElement root = document.RootElement;
            string error = GetString(root, "error");
            if (!string.IsNullOrEmpty(error))
            {
                throw new InvalidOperationException("Kimi 登录刷新失败，请运行 kimi login 重新登录。");
            }

            string accessToken = GetString(root, "access_token", "accessToken");
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new InvalidDataException("Kimi 登录刷新响应缺少 access_token。");
            }

            string refreshToken = GetString(root, "refresh_token", "refreshToken");
            if (string.IsNullOrEmpty(refreshToken)) refreshToken = auth.RefreshToken;

            return new RefreshResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = Math.Max(0, GetInt64(root, "expires_in", "expiresIn"))
            };
        }

        private static void AddKimiAuthHeaders(HttpRequestMessage request, string kimiHome)
        {
            string deviceId = ReadDeviceId(kimiHome);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("X-Msh-Platform", "lite-monitor");
            request.Headers.Add("X-Msh-Version", "1.3.6");
            request.Headers.Add("X-Msh-Device-Name", Environment.MachineName);
            request.Headers.Add("X-Msh-Device-Model", $"Windows {Environment.OSVersion.Version}");
            request.Headers.Add("X-Msh-Device-Id", deviceId);
        }

        private static string ReadDeviceId(string kimiHome)
        {
            try
            {
                string path = Path.Combine(kimiHome, "device_id");
                var info = new FileInfo(path);
                if (info.Exists && info.Length is > 0 and <= 256)
                {
                    string value = ReadLimitedFile(path, 256, "Kimi device_id 不可用。").Trim();
                    if (!string.IsNullOrEmpty(value)) return value;
                }
            }
            catch
            {
                // device_id 不是用量查询所必需；缺失时使用稳定的本机名称。
            }

            return Environment.MachineName;
        }

        private static bool PersistRefreshedTokens(AuthContext auth, RefreshResult refreshed)
        {
            string currentRaw = ReadLimitedFile(
                auth.CredentialPath,
                MaxCredentialBytes,
                "Kimi 登录信息不可用。");
            JsonObject current = JsonNode.Parse(currentRaw)?.AsObject()
                ?? throw new InvalidDataException("Kimi 登录信息格式不正确。");

            string currentRefresh = GetNodeString(current, "refresh_token", "refreshToken");
            if (!string.Equals(currentRefresh, auth.RefreshToken, StringComparison.Ordinal))
            {
                return false;
            }

            current["access_token"] = refreshed.AccessToken;
            current["refresh_token"] = refreshed.RefreshToken;
            current["expires_in"] = refreshed.ExpiresIn;
            current["expires_at"] = refreshed.ExpiresIn > 0
                ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() + refreshed.ExpiresIn
                : 0;

            string tempPath =
                auth.CredentialPath +
                $".litemonitor.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
            try
            {
                string json = current.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
                using (var stream = new FileStream(
                           tempPath,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           4096,
                           FileOptions.WriteThrough))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                {
                    writer.Write(json);
                    writer.Flush();
                    stream.Flush(flushToDisk: true);
                }

                File.Move(tempPath, auth.CredentialPath, overwrite: true);
                return true;
            }
            finally
            {
                try
                {
                    if (File.Exists(tempPath)) File.Delete(tempPath);
                }
                catch { }
            }
        }

        private static async Task<string> FetchUsageJsonAsync(
            string accessToken,
            CancellationToken cancellationToken)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, UsageUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(12));

            using HttpResponseMessage response = await GetClient().SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token);

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                throw new UnauthorizedAccessException("Kimi 登录已过期。");
            }
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                throw new HttpRequestException("Kimi 用量服务请求过于频繁，请稍后重试。");
            }
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Kimi 用量服务暂时不可用（HTTP {(int)response.StatusCode}）。");
            }

            return await ReadLimitedStringAsync(response.Content, timeout.Token);
        }

        private static string NormalizeUsageResponse(string rawJson)
        {
            using var document = JsonDocument.Parse(rawJson);
            JsonElement root = document.RootElement;

            QuotaWindow? weekly = TryGetProperty(root, out var usage, "usage")
                ? ParseQuotaWindow(usage)
                : null;

            QuotaWindow? shortWindow = null;
            long windowMinutes = 0;
            if (TryGetProperty(root, out var limits, "limits") &&
                limits.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in limits.EnumerateArray())
                {
                    if (!TryGetProperty(item, out var detail, "detail")) continue;
                    QuotaWindow? parsed = ParseQuotaWindow(detail);
                    if (parsed == null) continue;

                    shortWindow = parsed;
                    windowMinutes = GetWindowMinutes(item);
                    break;
                }
            }

            if (weekly == null && shortWindow == null)
            {
                throw new InvalidDataException("Kimi 用量响应中没有可识别的额度窗口。");
            }

            string windowLabel = FormatWindowLabel(windowMinutes);
            var normalized = new
            {
                status = "ok",
                source = "kimi_cli_auth",
                weekly_limit = weekly?.Limit ?? 0,
                weekly_used = weekly?.Used ?? 0,
                weekly_remaining = weekly?.Remaining ?? 0,
                weekly_used_percent = weekly?.UsedPercent ?? -1,
                weekly_reset = FormatReset(weekly),
                weekly_display = FormatDisplay(weekly),
                weekly_color = GetWeeklyPaceColor(weekly),
                window_limit = shortWindow?.Limit ?? 0,
                window_used = shortWindow?.Used ?? 0,
                window_remaining = shortWindow?.Remaining ?? 0,
                window_used_percent = shortWindow?.UsedPercent ?? -1,
                window_minutes = windowMinutes,
                window_label = windowLabel,
                window_reset = FormatReset(shortWindow),
                window_display = FormatDisplay(shortWindow),
                window_color = GetUsageColor(shortWindow),
                updated_at = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture)
            };

            return JsonSerializer.Serialize(normalized);
        }

        private static QuotaWindow? ParseQuotaWindow(JsonElement value)
        {
            if (value.ValueKind != JsonValueKind.Object) return null;

            double limit = GetNumber(value, "limit");
            double used = GetNumber(value, "used");
            double remaining = GetNumber(value, "remaining");
            if (limit <= 0 && used + remaining > 0) limit = used + remaining;
            if (limit <= 0) return null;
            if (remaining <= 0 && used < limit) remaining = limit - used;

            return new QuotaWindow
            {
                Limit = limit,
                Used = Math.Max(0, used),
                Remaining = Math.Max(0, remaining),
                UsedPercent = Math.Clamp(used * 100 / limit, 0, 100),
                ResetsAt = GetTimestamp(value, "resetTime", "reset_time", "resetAt", "reset_at")
            };
        }

        private static long GetWindowMinutes(JsonElement entry)
        {
            if (!TryGetProperty(entry, out var window, "window") ||
                window.ValueKind != JsonValueKind.Object)
            {
                return 0;
            }

            long duration = GetInt64(window, "duration");
            if (duration <= 0) return 0;

            string unit = GetString(window, "timeUnit", "time_unit");
            return unit switch
            {
                "TIME_UNIT_MINUTE" => duration,
                "TIME_UNIT_HOUR" => duration * 60,
                "TIME_UNIT_DAY" => duration * 24 * 60,
                _ => 0
            };
        }

        private static string FormatWindowLabel(long minutes)
        {
            if (minutes > 0 && minutes % (24 * 60) == 0)
            {
                return $"{minutes / (24 * 60)}天用量";
            }
            if (minutes > 0 && minutes % 60 == 0)
            {
                return $"{minutes / 60}小时用量";
            }
            if (minutes > 0)
            {
                return $"{minutes}分钟用量";
            }
            return "短期用量";
        }

        private static string FormatDisplay(QuotaWindow? window)
        {
            if (window == null) return "—";

            string percent = window.UsedPercent.ToString("0.#", CultureInfo.InvariantCulture);
            string reset = FormatReset(window);
            return string.IsNullOrEmpty(reset) ? $"{percent}%" : $"{percent}% · {reset}";
        }

        private static string FormatReset(QuotaWindow? window)
        {
            if (window?.ResetsAt == null) return "";

            TimeSpan remaining = window.ResetsAt.Value - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero) return "即将重置";
            if (remaining.TotalDays >= 1)
            {
                return $"{(int)remaining.TotalDays}天{remaining.Hours}时";
            }
            if (remaining.TotalHours >= 1)
            {
                return $"{(int)remaining.TotalHours}时{remaining.Minutes}分";
            }
            return $"{Math.Max(1, remaining.Minutes)}分";
        }

        private static string GetWeeklyPaceColor(QuotaWindow? weekly)
        {
            if (weekly?.ResetsAt == null) return GetUsageColor(weekly);

            double remainingHours = (weekly.ResetsAt.Value - DateTimeOffset.UtcNow).TotalHours;
            if (remainingHours is < 0 or > 168) return GetUsageColor(weekly);

            double elapsedPercent = (168 - remainingHours) / 168 * 100;
            double paceDelta = weekly.UsedPercent - elapsedPercent;
            if (paceDelta > 10) return "2";
            if (paceDelta > 0) return "1";
            return "0";
        }

        private static string GetUsageColor(QuotaWindow? window)
        {
            if (window == null) return "1";
            if (window.UsedPercent > 80) return "2";
            if (window.UsedPercent > 50) return "1";
            return "0";
        }

        private static async Task<string> ReadLimitedStringAsync(
            HttpContent content,
            CancellationToken cancellationToken)
        {
            if (content.Headers.ContentLength is long length && length > MaxResponseBytes)
            {
                throw new InvalidDataException("Kimi 响应过大。");
            }

            await using Stream input = await content.ReadAsStreamAsync(cancellationToken);
            using var output = new MemoryStream();
            byte[] buffer = new byte[8192];

            while (true)
            {
                int read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                if (read == 0) break;
                if (output.Length + read > MaxResponseBytes)
                {
                    throw new InvalidDataException("Kimi 响应过大。");
                }
                output.Write(buffer, 0, read);
            }

            return Encoding.UTF8.GetString(output.ToArray());
        }

        private static string ReadLimitedFile(string path, long maxBytes, string errorMessage)
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= 0 || info.Length > maxBytes)
            {
                throw new InvalidDataException(errorMessage);
            }

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8, true);
            return reader.ReadToEnd();
        }

        private static bool TryGetProperty(
            JsonElement value,
            out JsonElement result,
            params string[] names)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                foreach (string name in names)
                {
                    if (value.TryGetProperty(name, out result)) return true;
                }
            }

            result = default;
            return false;
        }

        private static string GetString(JsonElement value, params string[] names)
        {
            if (!TryGetProperty(value, out var result, names)) return "";
            return result.ValueKind == JsonValueKind.String
                ? result.GetString() ?? ""
                : "";
        }

        private static string GetNodeString(JsonObject value, params string[] names)
        {
            foreach (string name in names)
            {
                if (value[name] is JsonValue item &&
                    item.TryGetValue<string>(out string? result))
                {
                    return result ?? "";
                }
            }
            return "";
        }

        private static double GetNumber(JsonElement value, params string[] names)
        {
            if (!TryGetProperty(value, out var result, names)) return 0;
            if (result.ValueKind == JsonValueKind.Number && result.TryGetDouble(out double number))
            {
                return number;
            }
            if (result.ValueKind == JsonValueKind.String &&
                double.TryParse(
                    result.GetString(),
                    NumberStyles.Float,
                    CultureInfo.InvariantCulture,
                    out number))
            {
                return number;
            }
            return 0;
        }

        private static long GetInt64(JsonElement value, params string[] names)
        {
            if (!TryGetProperty(value, out var result, names)) return 0;
            if (result.ValueKind == JsonValueKind.Number && result.TryGetInt64(out long number))
            {
                return number;
            }
            if (result.ValueKind == JsonValueKind.String &&
                long.TryParse(
                    result.GetString(),
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out number))
            {
                return number;
            }
            return 0;
        }

        private static DateTimeOffset? GetTimestamp(JsonElement value, params string[] names)
        {
            if (!TryGetProperty(value, out var result, names)) return null;

            if (result.ValueKind == JsonValueKind.Number && result.TryGetDouble(out double unixSeconds))
            {
                return UnixTimestampToDateTime(unixSeconds);
            }
            if (result.ValueKind == JsonValueKind.String)
            {
                string raw = result.GetString() ?? "";
                if (double.TryParse(
                        raw,
                        NumberStyles.Float,
                        CultureInfo.InvariantCulture,
                        out unixSeconds))
                {
                    return UnixTimestampToDateTime(unixSeconds);
                }
                if (DateTimeOffset.TryParse(
                        raw,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal,
                        out var timestamp))
                {
                    return timestamp;
                }
            }

            return null;
        }
    }
}
