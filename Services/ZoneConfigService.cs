using System;
using System.Collections.Generic;
using System.Linq;
using Azure.Data.Tables;
using Keyvault_cert_issueance.Models;
using Keyvault_cert_issueance;

namespace Keyvault_cert_issueance.Services;

public sealed class ZoneCertTupleComparer : IEqualityComparer<(string zone, string cert)>
{
    public bool Equals((string zone, string cert) x, (string zone, string cert) y) =>
        string.Equals(x.zone, y.zone, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(x.cert, y.cert, StringComparison.OrdinalIgnoreCase);

    public int GetHashCode((string zone, string cert) obj)
    {
        var h1 = StringComparer.OrdinalIgnoreCase.GetHashCode(obj.zone ?? string.Empty);
        var h2 = StringComparer.OrdinalIgnoreCase.GetHashCode(obj.cert ?? string.Empty);
        return HashCode.Combine(h1, h2);
    }
}

public class ZoneConfigService
{
    private readonly TableClient _table;
    private Dictionary<(string zone, string cert), ZoneConfig> _cache = new();
    private DateTime _lastLoad = DateTime.MinValue;
    private readonly TimeSpan _ttl = TimeSpan.FromMinutes(5);

    public ZoneConfigService(ZoneConfigTableProvider provider)
    {
        _table = provider.Table;
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

    public void Reload()
    {
        _lastLoad = DateTime.MinValue;
        EnsureLoaded(force: true);
    }

    private void EnsureLoaded(bool force = false)
    {
        if (!force && (DateTime.UtcNow - _lastLoad) < _ttl) return;

        var map = new Dictionary<(string zone, string cert), ZoneConfig>(new ZoneCertTupleComparer());

        bool addApexForWildcard =
            (Environment.GetEnvironmentVariable("ADD_APEX_FOR_WILDCARD")?
                .Equals("true", StringComparison.OrdinalIgnoreCase) ?? true);

        foreach (var e in _table.Query<TableEntity>())
        {
            var zonePartition = e.PartitionKey;
            var rowKey = e.RowKey;

            var certNameProp = e.GetString("certificateName") ?? e.GetString("CertificateName");
            var certName = string.IsNullOrWhiteSpace(certNameProp) ? rowKey : certNameProp!.Trim();

            var primary = (e.GetString("primaryDomain") ?? "").Trim();

            var additionalRawList = (e.GetString("additionalNames") ?? "")
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();

            if (addApexForWildcard &&
                primary.StartsWith("*.", StringComparison.OrdinalIgnoreCase))
            {
                var apex = primary[2..];
                if (!string.IsNullOrWhiteSpace(apex) &&
                    !additionalRawList.Contains(apex, StringComparer.OrdinalIgnoreCase) &&
                    !string.Equals(primary, apex, StringComparison.OrdinalIgnoreCase))
                {
                    additionalRawList.Add(apex);
                }
            }

            map[(zonePartition, certName)] = new ZoneConfig
            {
                Zone = zonePartition,
                DnsZone = e.GetString("dnsZone") ?? zonePartition,
                CertificateName = certName,
                SubscriptionId = e.GetString("subscriptionId") ?? "",
                zoneResourceGroup = e.GetString("zoneResourceGroup") ?? "",
                KeyVaultName = e.GetString("keyVaultName") ?? "",
                Email = e.GetString("email"),
                Staging = e.GetBoolean("staging") ?? false,
                PrimaryDomain = primary,
                AdditionalNames = additionalRawList.ToArray(),
                renewalThresholdDays = e.GetInt32("renewalThresholdDays") ?? 15,
                PropagationMinutes = e.GetInt32("propagationMinutes") ?? 2,
                ChallengeMinutes = e.GetInt32("challengeMinutes") ?? 5,
                CleanupDns = e.GetBoolean("cleanupDns") ?? true,
                PfxPassword = e.GetString("pfxPassword"),
                DryRun = e.GetBoolean("dryRun")
            };
        }

        _cache = map;
        _lastLoad = DateTime.UtcNow;
    }
}