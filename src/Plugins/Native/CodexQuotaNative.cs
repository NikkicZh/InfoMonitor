using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace LiteMonitor.src.Plugins.Native
{
    /// <summary>
    /// 读取本机 Codex 登录态并获取 ChatGPT/Codex 配额。
    /// Token 仅在内存中用于固定的 chatgpt.com 配额请求，不会写入 LiteMonitor 设置或日志。
    /// </summary>
    public static class CodexQuotaNative
    {
        private const string UsageUrl = "https://chatgpt.com/backend-api/wham/usage";
        private const long MaxAuthBytes = 256 * 1024;
        private const long MaxResponseBytes = 1024 * 1024;

        private static readonly object ClientLock = new();
        private static HttpClient _client = CreateClient();

        private sealed class AuthContext
        {
            public string AccessToken { get; init; } = "";
            public string AccountId { get; init; } = "";
        }

        private sealed class QuotaWindow
        {
            public double RemainingPercent { get; init; }
            public DateTimeOffset? ResetsAt { get; init; }
            public long WindowSeconds { get; init; }
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

            // 保持系统默认 TLS 证书校验，不能复用插件执行器中放宽证书校验的客户端。
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(12)
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("LiteMonitor/1.3.6 CodexQuota");
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
            AuthContext auth = LoadAuth();

            using var request = new HttpRequestMessage(HttpMethod.Get, UsageUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.AccessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.TryAddWithoutValidation("originator", "Codex Desktop");
            request.Headers.TryAddWithoutValidation("OAI-Product-Sku", "CODEX");
            if (!string.IsNullOrEmpty(auth.AccountId))
            {
                request.Headers.Add("ChatGPT-Account-Id", auth.AccountId);
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(12));

            using HttpResponseMessage response = await GetClient().SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token);

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                throw new InvalidOperationException("Codex 登录已过期，请重新登录 Codex。");
            }
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                throw new HttpRequestException("Codex 配额服务请求过于频繁，请稍后重试。");
            }
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Codex 配额服务暂时不可用（HTTP {(int)response.StatusCode}）。");
            }

            string rawJson = await ReadLimitedStringAsync(response.Content, timeout.Token);
            return NormalizeUsageResponse(rawJson);
        }

        private static AuthContext LoadAuth()
        {
            string codexHome = Environment.GetEnvironmentVariable("CODEX_HOME") ?? "";
            if (string.IsNullOrWhiteSpace(codexHome))
            {
                string userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                codexHome = Path.Combine(userHome, ".codex");
            }

            string authPath = Path.Combine(codexHome, "auth.json");
            var info = new FileInfo(authPath);
            if (!info.Exists)
            {
                throw new FileNotFoundException("未找到 Codex 登录信息，请先登录 Codex。");
            }
            if (info.Length <= 0 || info.Length > MaxAuthBytes)
            {
                throw new InvalidDataException("Codex 登录信息不可用。");
            }

            string raw;
            using (var stream = new FileStream(
                authPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(stream, Encoding.UTF8, true))
            {
                raw = reader.ReadToEnd();
            }

            using var document = JsonDocument.Parse(raw);
            JsonElement root = document.RootElement;
            JsonElement tokens = TryGetProperty(root, out var tokenObject, "tokens") &&
                                 tokenObject.ValueKind == JsonValueKind.Object
                ? tokenObject
                : root;

            string accessToken = GetString(tokens, "access_token", "accessToken");
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new InvalidOperationException("当前 Codex 登录不是可读取的 ChatGPT 登录，请重新登录 Codex。");
            }

            string accountId = GetString(tokens, "account_id", "accountId");
            if (string.IsNullOrEmpty(accountId))
            {
                accountId = GetString(root, "account_id", "accountId");
            }
            if (string.IsNullOrEmpty(accountId))
            {
                accountId = TryReadAccountIdFromJwt(accessToken);
            }

            return new AuthContext
            {
                AccessToken = accessToken,
                AccountId = accountId
            };
        }

        private static string TryReadAccountIdFromJwt(string token)
        {
            try
            {
                string[] parts = token.Split('.');
                if (parts.Length < 2) return "";

                string payload = parts[1].Replace('-', '+').Replace('_', '/');
                payload = payload.PadRight(payload.Length + ((4 - payload.Length % 4) % 4), '=');

                byte[] bytes = Convert.FromBase64String(payload);
                using var document = JsonDocument.Parse(bytes);
                return GetString(
                    document.RootElement,
                    "https://api.openai.com/auth.chatgpt_account_id",
                    "chatgpt_account_id");
            }
            catch
            {
                return "";
            }
        }

        private static async Task<string> ReadLimitedStringAsync(
            HttpContent content,
            CancellationToken cancellationToken)
        {
            if (content.Headers.ContentLength is long length && length > MaxResponseBytes)
            {
                throw new InvalidDataException("Codex 配额响应过大。");
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
                    throw new InvalidDataException("Codex 配额响应过大。");
                }
                output.Write(buffer, 0, read);
            }

            return Encoding.UTF8.GetString(output.ToArray());
        }

        private static string NormalizeUsageResponse(string rawJson)
        {
            using var document = JsonDocument.Parse(rawJson);
            JsonElement root = document.RootElement;
            JsonElement rateLimit = TryGetProperty(root, out var rateLimitObject, "rate_limit", "rateLimit")
                ? rateLimitObject
                : root;

            QuotaWindow? shortWindow = FindWindow(
                rateLimit,
                new[]
                {
                    "primary_window", "primaryWindow", "short_window", "shortWindow",
                    "five_hour_window", "fiveHourWindow", "5h", "primary"
                },
                expectedSeconds: 5 * 60 * 60);

            QuotaWindow? weeklyWindow = FindWindow(
                rateLimit,
                new[]
                {
                    "secondary_window", "secondaryWindow", "weekly_window", "weeklyWindow",
                    "week_window", "weekWindow", "weekly", "secondary"
                },
                expectedSeconds: 7 * 24 * 60 * 60);

            // 部分账号只有一个窗口，并且后端仍把周窗口命名为 primary。
            if (shortWindow == null && weeklyWindow == null)
            {
                weeklyWindow = FindWindow(
                    rateLimit,
                    new[] { "primary_window", "primaryWindow", "primary" },
                    expectedSeconds: 7 * 24 * 60 * 60);
            }

            if (shortWindow == null && weeklyWindow == null)
            {
                throw new InvalidDataException("Codex 配额响应中没有可识别的额度窗口。");
            }

            string plan = GetString(root, "plan_type", "planType");
            if (string.IsNullOrEmpty(plan))
            {
                plan = GetString(rateLimit, "plan_type", "planType");
            }

            var normalized = new
            {
                status = "ok",
                source = "local_auth",
                plan = plan.ToUpperInvariant(),
                short_remaining = shortWindow?.RemainingPercent ?? -1,
                short_reset = FormatReset(shortWindow),
                short_display = FormatDisplay(shortWindow),
                short_color = GetColor(shortWindow),
                weekly_remaining = weeklyWindow?.RemainingPercent ?? -1,
                weekly_reset = FormatReset(weeklyWindow),
                weekly_display = FormatDisplay(weeklyWindow),
                weekly_color = GetColor(weeklyWindow),
                updated_at = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture)
            };

            return JsonSerializer.Serialize(normalized);
        }

        private static QuotaWindow? FindWindow(
            JsonElement rateLimit,
            string[] names,
            long expectedSeconds)
        {
            foreach (string name in names)
            {
                if (!TryGetProperty(rateLimit, out var candidate, name)) continue;

                QuotaWindow? window = ParseWindow(candidate);
                if (MatchesDuration(window, expectedSeconds)) return window;
            }

            foreach (string collectionName in new[]
                     {
                         "windows", "limit_windows", "limitWindows", "limits", "buckets"
                     })
            {
                if (!TryGetProperty(rateLimit, out var items, collectionName) ||
                    items.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (JsonElement item in items.EnumerateArray())
                {
                    QuotaWindow? window = ParseWindow(item);
                    if (window == null) continue;

                    string itemName = GetString(item, "name", "type", "id", "window", "label");
                    bool nameMatches = false;
                    foreach (string name in names)
                    {
                        if (itemName.Contains(name, StringComparison.OrdinalIgnoreCase))
                        {
                            nameMatches = true;
                            break;
                        }
                    }

                    if (nameMatches || MatchesDuration(window, expectedSeconds))
                    {
                        return window;
                    }
                }
            }

            return null;
        }

        private static bool MatchesDuration(QuotaWindow? window, long expectedSeconds)
        {
            if (window == null) return false;
            if (window.WindowSeconds == 0) return true;
            return Math.Abs(window.WindowSeconds - expectedSeconds) <= 60;
        }

        private static QuotaWindow? ParseWindow(JsonElement value)
        {
            if (value.ValueKind != JsonValueKind.Object) return null;

            double remainingPercent;
            if (TryGetNumber(
                    value,
                    out double remaining,
                    out string remainingKey,
                    "remaining_percent", "remainingPercent", "remaining_pct", "remainingPct",
                    "remaining_ratio", "remainingRatio", "remaining"))
            {
                remainingPercent = ShouldScaleRatio(remainingKey, remaining)
                    ? remaining * 100
                    : remaining;
            }
            else if (TryGetNumber(
                         value,
                         out double used,
                         out string usedKey,
                         "used_percent", "usedPercent", "used_pct", "usedPct",
                         "used_ratio", "usedRatio", "utilization", "used"))
            {
                double usedPercent = ShouldScaleRatio(usedKey, used)
                    ? used * 100
                    : used;
                remainingPercent = 100 - usedPercent;
            }
            else
            {
                return null;
            }

            long windowSeconds = GetInt64(
                value,
                "limit_window_seconds", "limitWindowSeconds", "window_seconds", "windowSeconds",
                "duration_seconds", "durationSeconds", "period_seconds", "periodSeconds");

            if (windowSeconds == 0)
            {
                long windowMinutes = GetInt64(value, "windowDurationMins", "window_duration_mins");
                windowSeconds = windowMinutes > 0 ? windowMinutes * 60 : 0;
            }

            return new QuotaWindow
            {
                RemainingPercent = Math.Clamp(remainingPercent, 0, 100),
                ResetsAt = GetTimestamp(
                    value,
                    "reset_at", "resetAt", "resets_at", "resetsAt", "reset_time", "resetTime"),
                WindowSeconds = windowSeconds
            };
        }

        private static bool ShouldScaleRatio(string key, double value)
        {
            return key.Contains("ratio", StringComparison.OrdinalIgnoreCase) ||
                   key.Equals("utilization", StringComparison.OrdinalIgnoreCase) ||
                   (!key.Contains("percent", StringComparison.OrdinalIgnoreCase) &&
                    !key.Contains("pct", StringComparison.OrdinalIgnoreCase) &&
                    value is >= 0 and <= 1);
        }

        private static string FormatDisplay(QuotaWindow? window)
        {
            if (window == null) return "—";

            string percent = window.RemainingPercent.ToString("0.#", CultureInfo.InvariantCulture);
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

        private static string GetColor(QuotaWindow? window)
        {
            if (window == null) return "1";
            if (window.RemainingPercent < 20) return "2";
            if (window.RemainingPercent < 50) return "1";
            return "0";
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

        private static bool TryGetNumber(
            JsonElement value,
            out double number,
            out string matchedKey,
            params string[] names)
        {
            foreach (string name in names)
            {
                if (!TryGetProperty(value, out var result, name)) continue;

                if (result.ValueKind == JsonValueKind.Number && result.TryGetDouble(out number))
                {
                    matchedKey = name;
                    return true;
                }
                if (result.ValueKind == JsonValueKind.String &&
                    double.TryParse(
                        result.GetString(),
                        NumberStyles.Float,
                        CultureInfo.InvariantCulture,
                        out number))
                {
                    matchedKey = name;
                    return true;
                }
            }

            number = 0;
            matchedKey = "";
            return false;
        }

        private static long GetInt64(JsonElement value, params string[] names)
        {
            if (!TryGetProperty(value, out var result, names)) return 0;
            if (result.ValueKind == JsonValueKind.Number && result.TryGetInt64(out long number))
            {
                return number;
            }
            if (result.ValueKind == JsonValueKind.String &&
                long.TryParse(result.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number))
            {
                return number;
            }
            return 0;
        }

        private static DateTimeOffset? GetTimestamp(JsonElement value, params string[] names)
        {
            if (!TryGetProperty(value, out var result, names)) return null;

            if (result.ValueKind == JsonValueKind.Number && result.TryGetInt64(out long unixSeconds))
            {
                try { return DateTimeOffset.FromUnixTimeSeconds(unixSeconds); } catch { return null; }
            }

            if (result.ValueKind == JsonValueKind.String)
            {
                string raw = result.GetString() ?? "";
                if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out unixSeconds))
                {
                    try { return DateTimeOffset.FromUnixTimeSeconds(unixSeconds); } catch { return null; }
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
