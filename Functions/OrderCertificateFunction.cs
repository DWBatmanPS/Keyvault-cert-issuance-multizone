using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Keyvault_cert_issueance.Models;
using Keyvault_cert_issueance.Services;

namespace Keyvault_cert_issueance.Functions;

public class OrderCertificateFunction
{
    private readonly ILogger _log;
    private readonly ZoneConfigService _zones;
    private readonly CertificateOrderService _orders;
    private readonly RateLimiterService _rate;
    private readonly ResponseFactory _responses;

    public OrderCertificateFunction(
        ILoggerFactory lf,
        ZoneConfigService zones,
        CertificateOrderService orders,
        RateLimiterService rate,
        ResponseFactory responses)
    {
        _log = lf.CreateLogger<OrderCertificateFunction>();
        _zones = zones;
        _orders = orders;
        _rate = rate;
        _responses = responses;
    }

    // Bulk order all configured certificates (ignores renewal threshold; manual mass issuance).
    // Optional query overrides: ?staging=true|false&dryRun=true|false
    [Function("OrderAllCertificates")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = "order-all")] HttpRequestData req)
    {
        string correlationId = Guid.NewGuid().ToString("n");

        _log.LogInformation("OrderAllCertificates START correlationId={CorrelationId} method={Method} url={Url}", 
        correlationId, req.Method, req.Url);

        
        try
        {
            var qs = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
            bool? stagingOverride = ParseNullableBool(qs.Get("staging"));
            bool? dryRunOverride = ParseNullableBool(qs.Get("dryRun"));

            bool forceReload = ParseNullableBool(qs.Get("reload")) == true;
            if (forceReload)
            {
                _zones.Reload();
                _log.LogInformation("Config cache reloaded CorrelationId={CorrelationId}", correlationId);
            }

            var configs = _zones.GetAll().ToList();
            if (configs.Count == 0)
                return await Write(req, _responses.Success(correlationId, new
                {
                    message = "No zone/certificate configurations found.",
                    total = 0,
                    successes = 0,
                    failures = 0,
                    skippedRateLimit = 0,
                    results = Array.Empty<object>()
                }));

            _log.LogInformation("Bulk order start CorrelationId={CorrelationId} count={Count} stagingOverride={StagingOverride} dryRunOverride={DryRunOverride}",
                correlationId, configs.Count, stagingOverride, dryRunOverride);

            var results = new List<object>();
            int successes = 0;
            int failures = 0;
            int skippedRate = 0;

            foreach (var cfg in configs)
            {
                string itemCid = Guid.NewGuid().ToString("n");
                bool rawEnvDry = Environment.GetEnvironmentVariable("LE_DRY_RUN")
                    ?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false;
                bool staging = stagingOverride ?? cfg.Staging;
                bool dryRun = dryRunOverride ?? (cfg.DryRun ?? rawEnvDry);

                _log.LogInformation("EvalDryRun CorrelationId={CorrelationId} itemCid={ItemCid} cert={Cert} " +
                                        "override={Override} cfgDryRun={CfgDryRun} envDryRun={EnvDryRun} final={FinalDryRun}",
                        correlationId, itemCid, cfg.CertificateName, dryRunOverride, cfg.DryRun, rawEnvDry, dryRun);

                // Rate limit (skip if dry-run? Decide policy. Here we DO count; change if not desired.)
                var rl = await _rate.CheckAndRecordAsync(cfg.DnsZone, cfg.CertificateName, "bulk-order", itemCid);
                if (!rl.allowed)
                {
                    _log.LogWarning("Rate limit hit CorrelationId={CorrelationId} itemCid={ItemCid} cert={Cert} currentCount={Count}",
                        correlationId, itemCid, cfg.CertificateName, rl.currentCount);
                    skippedRate++;
                    // Stop further processing to avoid repeated denials.
                    results.Add(new
                    {
                        certificate = cfg.CertificateName,
                        zone = cfg.Zone,
                        itemCorrelationId = itemCid,
                        status = "skipped_rate_limit",
                        globalCount = rl.currentCount,
                        retryAfter = rl.retryAfter?.TotalSeconds
                    });
                    break;
                }

                var domainList = new[] { cfg.PrimaryDomain }
                    .Concat(cfg.AdditionalNames ?? Array.Empty<string>())
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                    if (string.IsNullOrWhiteSpace(cfg.PrimaryDomain))
                    {
                        _log.LogWarning("Skipping cert due to empty primaryDomain CorrelationId={CorrelationId} cert={Cert} zone={Zone}",
                            correlationId, cfg.CertificateName, cfg.Zone);
                        results.Add(new {
                            certificate = cfg.CertificateName,
                            zone = cfg.Zone,
                            itemCorrelationId = itemCid,
                            status = "skipped_missing_primary_domain"
                        });
                        continue;
                    }

                _log.LogInformation("Issuing CorrelationId={CorrelationId} itemCid={ItemCid} cert={Cert} domains={Domains} staging={Staging} dryRun={DryRun}",
                    correlationId, itemCid, cfg.CertificateName,
                    string.Join(",", domainList),
                    staging, dryRun);

                var globalEmail = Environment.GetEnvironmentVariable("LE_EMAIL");

                var issuance = await _orders.IssueCertificateAsync(
                    itemCid,
                    globalEmail ?? string.Empty, // shared ACME account email (blank allowed if already registered)
                    staging,
                    dryRun,
                    cfg.CleanupDns,
                    cfg.PrimaryDomain,
                    cfg.AdditionalNames ?? Array.Empty<string>(),
                    cfg.CertificateName,
                    cfg.SubscriptionId,
                    cfg.zoneResourceGroup,
                    cfg.DnsZone,
                    cfg.PropagationMinutes,
                    cfg.ChallengeMinutes,
                    cfg.KeyVaultName,
                    cfg.PfxPassword,
                    secretClient: null,
                    accountSecretName: null,
                    log: m => _log.LogInformation(m));

                if (issuance.error != null)
                {
                    failures++;
                    _log.LogWarning("Issuance failed CorrelationId={CorrelationId} itemCid={ItemCid} cert={Cert} code={Code} msg={Message}",
                        correlationId, itemCid, cfg.CertificateName, issuance.error.Code, issuance.error.Message);
                    results.Add(new
                    {
                        certificate = cfg.CertificateName,
                        zone = cfg.Zone,
                        itemCorrelationId = itemCid,
                        status = "failed",
                        errorCode = issuance.error.Code,
                        errorMessage = issuance.error.Message
                    });
                }
                else
                {
                    successes++;
                    results.Add(new
                    {
                        certificate = cfg.CertificateName,
                        zone = cfg.Zone,
                        itemCorrelationId = itemCid,
                        status = "success",
                        notBefore = issuance.meta!.NotBefore,
                        notAfter = issuance.meta.NotAfter,
                        domains = issuance.meta.Domains
                    });
                }
            }

            var payload = new
            {
                correlationId,
                total = configs.Count,
                successes,
                failures,
                skippedRateLimit = skippedRate,
                stagingOverride,
                dryRunOverride,
                results
            };

            return await Write(req, _responses.Success(correlationId, payload));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Bulk order unexpected error CorrelationId={CorrelationId}", correlationId);
            return await Write(req, _responses.Failure<object>(correlationId,
                _responses.Error("internal", "Unexpected error during bulk order.", ex.Message)));
        }
    }

    private static bool? ParseNullableBool(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        if (raw.Equals("true", StringComparison.OrdinalIgnoreCase)) return true;
        if (raw.Equals("false", StringComparison.OrdinalIgnoreCase)) return false;
        return null;
    }

    private async Task<HttpResponseData> Write<T>(HttpRequestData req, ApiResponse<T> payload)
    {
        var resp = req.CreateResponse(payload.HasError
            ? System.Net.HttpStatusCode.BadRequest
            : System.Net.HttpStatusCode.OK);
        await resp.WriteStringAsync(System.Text.Json.JsonSerializer.Serialize(
            payload,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return resp;
    }
}