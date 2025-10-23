using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Keyvault_cert_issueance.Models;
using Keyvault_cert_issueance.Services;

namespace Keyvault_cert_issueance.Functions;

public class IssueCertificateFunction
{
    private readonly ZoneConfigService _zones;
    private readonly CertificateOrderService _order;
    private readonly RateLimiterService _rate;
    private readonly ResponseFactory _responses;
    private readonly ILogger _log;

    public IssueCertificateFunction(
        ZoneConfigService zones,
        CertificateOrderService order,
        RateLimiterService rate,
        ResponseFactory responses,
        ILoggerFactory lf)
    {
        _zones = zones;
        _order = order;
        _rate = rate;
        _responses = responses;
        _log = lf.CreateLogger<IssueCertificateFunction>();
    }

    [Function("IssueCertificate")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        string cid = Guid.NewGuid().ToString("n");
        try
        {
            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var request = string.IsNullOrWhiteSpace(body) ? new IssueRequest() :
                JsonSerializer.Deserialize<IssueRequest>(body) ?? new IssueRequest();

            if (string.IsNullOrWhiteSpace(request.Zone) || string.IsNullOrWhiteSpace(request.CertificateName))
                return await Write(req, _responses.Failure<object>(cid, _responses.Error("validation", "Zone and CertificateName required")));

            var cfg = _zones.Get(request.Zone, request.CertificateName);
            if (cfg == null)
                return await Write(req, _responses.Failure<object>(cid, _responses.Error("not_found", "Config not found")));

            // Global + per-cert rate limiting integrated in RateLimiterService
            var rl = await _rate.CheckAndRecordAsync(cfg.DnsZone, cfg.CertificateName, "new", cid);
            if (!rl.allowed)
                return await Write(req, _responses.Failure<object>(cid,
                    _responses.Error("rate_limit", $"Limit reached ({rl.currentCount}/300). Retry after {rl.retryAfter}")));

            var result = await _order.IssueCertificateAsync(
                cid,
                cfg.Email,
                request.UseStaging ?? cfg.Staging,
                request.DryRun ?? false,
                cfg.CleanupDns,
                cfg.PrimaryDomain,
                cfg.AdditionalNames,
                cfg.CertificateName,
                cfg.SubscriptionId,
                cfg.ResourceGroup,
                cfg.DnsZone,
                cfg.PropagationMinutes,
                cfg.ChallengeMinutes,
                cfg.KeyVaultName,
                cfg.PfxPassword,
                secretClient: null,
                accountSecretName: null,
                log: m => _log.LogInformation(m));

            if (result.error != null)
                return await Write(req, _responses.Failure<object>(cid, result.error));

            return await Write(req, _responses.Success(cid, result.meta!));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "IssueCertificate unexpected error cid={Cid}", cid);
            return await Write(req, _responses.Failure<object>(cid,
                _responses.Error("internal", "Unexpected error", ex.Message)));
        }
    }

    private async Task<HttpResponseData> Write<T>(HttpRequestData req, ApiResponse<T> payload)
    {
        var resp = req.CreateResponse(payload.HasError
            ? System.Net.HttpStatusCode.BadRequest
            : System.Net.HttpStatusCode.OK);
        await resp.WriteStringAsync(JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        return resp;
    }
}