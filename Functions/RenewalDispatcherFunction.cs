using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Keyvault_cert_issueance.Services;

namespace Keyvault_cert_issueance.Functions;
public class RenewalDispatcherFunction
{
    private readonly ZoneConfigService _zones;
    private readonly KeyVaultService _kv;
    private readonly CertificateOrderService _order;
    private readonly RateLimiterService _rate;
    private readonly ILogger _log;

    public RenewalDispatcherFunction(ZoneConfigService zones, KeyVaultService kv,
        CertificateOrderService order, RateLimiterService rate, ILoggerFactory lf)
    {
        _zones = zones; _kv = kv; _order = order; _rate = rate;
        _log = lf.CreateLogger<RenewalDispatcherFunction>();
    }

    [Function("RenewalDispatcher")]
    public async Task Run([TimerTrigger("0 0 */3 * * *")] TimerInfo timer) // every 3 hours
    {
        string correlationId = Guid.NewGuid().ToString("n");
        var configs = _zones.GetAll(); // implement GetAll() if needed
        foreach (var cfg in configs)
        {
            try
            {
                var current = await _kv.GetCurrentCertificateAsync(cfg.KeyVaultName, cfg.CertificateName);
                if (current.meta == null) continue;
                var remaining = current.meta.NotAfter - DateTimeOffset.UtcNow;
                if (remaining > TimeSpan.FromDays((double)cfg.renewalThresholdDays.GetValueOrDefault())) continue;

                var rl = await _rate.CheckAndRecordAsync(cfg.DnsZone, cfg.CertificateName, "auto-renew", correlationId);
                if (!rl.allowed)
                {
                    _log.LogWarning("CorrelationId={CorrelationId} rate limit hit during auto-renew for {Cert}", correlationId, cfg.CertificateName);
                    break; // stop further renewals this run
                }

                var orderResult = await _order.IssueCertificateAsync(
                    correlationId, cfg.Email, cfg.Staging, dryRun:false, cfg.CleanupDns,
                    cfg.PrimaryDomain, cfg.AdditionalNames, cfg.CertificateName,
                    cfg.SubscriptionId, cfg.ResourceGroup, cfg.DnsZone,
                    cfg.PropagationMinutes, cfg.ChallengeMinutes,
                    cfg.KeyVaultName, cfg.PfxPassword, null, null,
                    msg => _log.LogInformation(msg));

                if (orderResult.error != null)
                {
                    _log.LogError("CorrelationId={CorrelationId} renewal failed for {Cert}: {Code} {Message}",
                        correlationId, cfg.CertificateName, orderResult.error.Code, orderResult.error.Message);
                }
                else
                {
                    _log.LogInformation("CorrelationId={CorrelationId} renewed {Cert} newExpiry={Expiry}",
                        correlationId, cfg.CertificateName, orderResult.meta!.NotAfter);
                }
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "CorrelationId={CorrelationId} unexpected error renewing {Cert}", correlationId, cfg.CertificateName);
            }
        }
    }
}