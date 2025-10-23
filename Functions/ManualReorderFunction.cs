using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Certificates;
using Azure.Identity;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Keyvault_cert_issueance.Models;
using Keyvault_cert_issueance.Services;

namespace Keyvault_cert_issueance.Functions;

public class ManualReorderFunction
{
    private readonly ZoneConfigService _zones;
    private readonly CertificateOrderService _order;
    private readonly RateLimiterService _rate;
    private readonly AcmeAccountService _account;
    private readonly KeyVaultService _kv;
    private readonly ResponseFactory _responses;
    private readonly RevocationService _revoke;
    private readonly DefaultAzureCredential _credential;
    private readonly ILogger _log;

    public ManualReorderFunction(
        ZoneConfigService zones,
        CertificateOrderService order,
        RateLimiterService rate,
        AcmeAccountService account,
        KeyVaultService kv,
        ResponseFactory responses,
        RevocationService revoke,
        DefaultAzureCredential credential,
        ILoggerFactory lf)
    {
        _zones = zones;
        _order = order;
        _rate = rate;
        _account = account;
        _kv = kv;
        _responses = responses;
        _revoke = revoke;
        _credential = credential;
        _log = lf.CreateLogger<ManualReorderFunction>();
    }

    [Function("ManualReorder")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        string correlationId = Guid.NewGuid().ToString("n");
        try
        {
            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var request = string.IsNullOrWhiteSpace(body)
                ? new ManualReorderRequest()
                : (JsonSerializer.Deserialize<ManualReorderRequest>(body) ?? new ManualReorderRequest());

            if (string.IsNullOrWhiteSpace(request.Zone) || string.IsNullOrWhiteSpace(request.CertificateName))
                return await Write(req, _responses.Failure<object>(correlationId,
                    _responses.Error("validation", "Zone and CertificateName required")));

            var cfg = _zones.Get(request.Zone, request.CertificateName);
            if (cfg == null)
                return await Write(req, _responses.Failure<object>(correlationId,
                    _responses.Error("not_found", "Zone/certificate config not found")));

            // Global + per-cert rate limit
            var rl = await _rate.CheckAndRecordAsync(cfg.DnsZone, cfg.CertificateName, "manual-reorder", correlationId);
            if (!rl.allowed)
                return await Write(req, _responses.Failure<object>(correlationId,
                    _responses.Error("rate_limit", $"Limit reached ({rl.currentCount}/300). Retry later.")));

            // Optional revoke previous certificate
            if (request.RevokePrevious == true)
            {
                try
                {
                    // Load existing certificate directly from Key Vault
                    var vaultUri = new Uri($"https://{cfg.KeyVaultName}.vault.azure.net/");
                    var certClient = new CertificateClient(vaultUri, _credential);
                    var certBundle = await certClient.GetCertificateAsync(cfg.CertificateName);
                    var x509 = new X509Certificate2(certBundle.Value.Cer);

                    var ensure = await _account.EnsureAccountAsync(cfg.Email, request.UseStaging ?? cfg.Staging,
                        secretClient: null, accountSecretName: null);
                    if (ensure.Error != null)
                        return await Write(req, _responses.Failure<object>(correlationId, ensure.Error));

                    var revokeErr = await _revoke.RevokeAsync(ensure.Context!, x509);
                    if (revokeErr != null)
                    {
                        _log.LogWarning("CorrelationId={CorrelationId} revocation failed code={Code}", correlationId, revokeErr.Code);
                    }
                    else
                    {
                        _log.LogInformation("CorrelationId={CorrelationId} previous certificate revoked.", correlationId);
                    }
                }
                catch (Exception rex)
                {
                    // Do not hard-fail reorder if revocation fails
                    _log.LogWarning(rex, "CorrelationId={CorrelationId} revocation attempt failed; continuing.", correlationId);
                }
            }

            // Dry-run support (ManualReorderRequest may not have DryRun; fallback to env)
            bool dryRun = (Environment.GetEnvironmentVariable("LE_DRY_RUN")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false);

            var issueResult = await _order.IssueCertificateAsync(
                correlationId,
                cfg.Email,
                request.UseStaging ?? cfg.Staging,
                dryRun,
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

            if (issueResult.error != null)
                return await Write(req, _responses.Failure<object>(correlationId, issueResult.error));

            return await Write(req, _responses.Success(correlationId, issueResult.meta!));
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "ManualReorder unexpected error CorrelationId={CorrelationId}", correlationId);
            return await Write(req, _responses.Failure<object>(correlationId,
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