using Azure.Data.Tables;

public class ZoneConfigService
{
    private readonly TableClient _table;
    private Dictionary<(string zone,string cert), ZoneConfig> _cache = new();
    private DateTime _lastLoad = DateTime.MinValue;

    public ZoneConfigService(TableClient zoneConfigTable)
    {
        _table = zoneConfigTable;
    }

    public ZoneConfig? Get(string zone, string cert)
    {
        EnsureLoaded();
        _cache.TryGetValue((zone, cert), out var cfg);
        return cfg;
    }

    public IEnumerable<ZoneConfig> GetAll()
    {
        EnsureLoaded();
        return _cache.Values;
    }

    private void EnsureLoaded()
    {
        if ((DateTime.UtcNow - _lastLoad) < TimeSpan.FromMinutes(5)) return;
        var map = new Dictionary<(string,string), ZoneConfig>();
        foreach (var e in _table.Query<TableEntity>())
        {
            var zone = e.PartitionKey;
            var cert = e.RowKey;
            map[(zone, cert)] = new ZoneConfig
            {
                DnsZone = zone,
                CertificateName = cert,
                SubscriptionId = e.GetString("subscriptionId") ?? "",
                ResourceGroup = e.GetString("resourceGroup") ?? "",
                KeyVaultName = e.GetString("keyVaultName") ?? "",
                Email = e.GetString("email") ?? "",
                Staging = e.GetBoolean("staging") ?? false,
                PrimaryDomain = e.GetString("primaryDomain") ?? "",
                AdditionalNames = (e.GetString("additionalNames") ?? "")
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                RenewalThresholdDays = e.GetInt32("renewalThresholdDays") ?? 20,
                PropagationMinutes = e.GetInt32("propagationMinutes") ?? 2,
                ChallengeMinutes = e.GetInt32("challengeMinutes") ?? 5,
                CleanupDns = e.GetBoolean("cleanupDns") ?? true,
                PfxPassword = e.GetString("pfxPassword")
            };
        }
        _cache = map;
        _lastLoad = DateTime.UtcNow;
    }
}