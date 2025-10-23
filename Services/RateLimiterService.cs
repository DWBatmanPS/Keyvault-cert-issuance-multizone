using System;
using System.Threading.Tasks;
using Azure.Data.Tables;

namespace Keyvault_cert_issueance.Services;

public class RateLimiterService
{
    private readonly TableClient _eventsTable;
    private readonly int _maxEvents;
    private static readonly TimeSpan Window = TimeSpan.FromHours(3);

    // Simple short-lived cache to avoid hammering storage
    private DateTime _cacheTime;
    private int _cachedTotal;

    public RateLimiterService(TableClient eventsTable)
    {
        _eventsTable = eventsTable;
        _maxEvents = int.TryParse(Environment.GetEnvironmentVariable("GLOBAL_MAX_3H"), out var m) ? m : 300;
    }

    // Main method used by callers
    public async Task<(bool allowed, int currentCount, TimeSpan? retryAfter)> CheckAndRecordAsync(
        string zone, string certName, string action, string correlationId)
    {
        var now = DateTime.UtcNow;
        int total = await GetGlobalCountAsync(now);

        if (total >= _maxEvents)
        {
            var oldestTs = await GetOldestTimestampAsync(now);
            TimeSpan? retry = oldestTs.HasValue ? (oldestTs.Value.Add(Window) - now) : TimeSpan.FromMinutes(15);
            return (false, total, retry);
        }

        await WriteEventAsync(now, zone, certName, action, correlationId);
        return (true, total + 1, null);
    }

    private async Task<int> GetGlobalCountAsync(DateTime now)
    {
        if ((now - _cacheTime) < TimeSpan.FromSeconds(15) && _cachedTotal > 0)
            return _cachedTotal;

        int sum = 0;
        DateTime lowerBound = now - Window;

        // We only need at most the last 3 partition hours
        for (int i = 0; i < 3; i++)
        {
            var dt = now.AddHours(-i);
            string part = dt.ToString("yyyyMMddHH");
            var query = _eventsTable.QueryAsync<TableEntity>(x => x.PartitionKey == part);
            await foreach (var e in query)
            {
                var ts = e.GetDateTime("timestamp") ?? DateTime.MinValue;
                if (ts >= lowerBound && ts <= now)
                    sum++;
            }
        }

        _cachedTotal = sum;
        _cacheTime = now;
        return sum;
    }

    private async Task<DateTime?> GetOldestTimestampAsync(DateTime now)
    {
        DateTime lowerBound = now - Window;
        DateTime? oldest = null;

        for (int i = 0; i < 3; i++)
        {
            var dt = now.AddHours(-i);
            string part = dt.ToString("yyyyMMddHH");
            var query = _eventsTable.QueryAsync<TableEntity>(x => x.PartitionKey == part);
            await foreach (var e in query)
            {
                var ts = e.GetDateTime("timestamp") ?? DateTime.MinValue;
                if (ts >= lowerBound && ts <= now)
                {
                    if (!oldest.HasValue || ts < oldest.Value)
                        oldest = ts;
                }
            }
        }
        return oldest;
    }

    private async Task WriteEventAsync(DateTime now, string zone, string certName,
        string action, string correlationId)
    {
        // Partition: hour bucket; RowKey: guid
        var entity = new TableEntity(now.ToString("yyyyMMddHH"), Guid.NewGuid().ToString())
        {
            { "timestamp", now },
            { "zone", zone },
            { "certificateName", certName },
            { "eventType", action },
            { "correlationId", correlationId }
        };
        await _eventsTable.AddEntityAsync(entity);
    }
}