using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;
using Certes;
using Certes.Acme;
using Certes.Pkcs;
using Keyvault_cert_issueance.Models;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Certes.Acme.Resource;

namespace Keyvault_cert_issueance.Services;

public class CertificateOrderService
{
    private readonly AcmeAccountService _accountService;
    private readonly DnsChallengeService _dnsService;
    private readonly KeyVaultService _kvService;
    private readonly ResponseFactory _responses;
    private readonly ILogger<CertificateOrderService> _logger;

    private static readonly ConcurrentDictionary<string, System.Threading.SemaphoreSlim> _locks = new();

    public CertificateOrderService(
        AcmeAccountService accountService,
        DnsChallengeService dnsService,
        KeyVaultService kvService,
        ResponseFactory responses,
        ILogger<CertificateOrderService> logger)
    {
        _accountService = accountService;
        _dnsService = dnsService;
        _kvService = kvService;
        _responses = responses;
        _logger = logger;
    }


public async Task<(CertificateMetadata? meta, ApiError? error)> IssueCertificateAsync(
    string correlationId,
    string email,
    bool staging,
    bool dryRun,
    bool cleanupDns,
    string primaryDomain,
    IEnumerable<string> additionalNames,
    string certificateName,
    string subscriptionId,
    string zoneResourceGroup,
    string dnsZone,
    int propagationMinutes,
    int challengeMinutes,
    string keyVaultName,
    string? pfxPassword,
    SecretClient? secretClient,
    string? accountSecretName,
    Action<string>? log)
{
    var allDomains = new List<string> { primaryDomain };
    allDomains.AddRange(additionalNames.Where(a => !string.Equals(a, primaryDomain, StringComparison.OrdinalIgnoreCase)));
    allDomains = allDomains.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    _logger.LogInformation("Certificate issuance START CorrelationId={CorrelationId} cert={CertName} domains={Domains} staging={Staging} dryRun={DryRun}", 
            correlationId, certificateName, string.Join(",", allDomains), staging, dryRun);

    log?.Invoke($"[{correlationId}] Preparing issuance cert='{certificateName}' zone='{dnsZone}' staging={staging} dryRun={dryRun} domains={string.Join(",", allDomains)}");

    var invalid = allDomains.Where(d =>
        !d.Equals(dnsZone, StringComparison.OrdinalIgnoreCase) &&
        !d.EndsWith("." + dnsZone, StringComparison.OrdinalIgnoreCase)).ToList();
    if (invalid.Any())
    {
        _logger.LogWarning("Domain validation failed CorrelationId={CorrelationId} dnsZone={DnsZone} invalidDomains={InvalidDomains}", 
                correlationId, dnsZone, string.Join(",", invalid));
        log?.Invoke($"[{correlationId}] Domain validation failed. dnsZone='{dnsZone}' primary='{primaryDomain}' " +
                        $"domains={string.Join(",", allDomains)} invalid={string.Join(",", invalid)}");

        return (null, _responses.Error("domain_validation", $"Domains outside zone '{dnsZone}'.", string.Join(", ", invalid)));

    }
    else
    {
        _logger.LogDebug("Domain validation passed CorrelationId={CorrelationId} dnsZone={DnsZone}", correlationId, dnsZone);
        log?.Invoke($"[{correlationId}] Domain validation passed for zone '{dnsZone}'.");
    }

    var sem = _locks.GetOrAdd(certificateName, _ => new System.Threading.SemaphoreSlim(1, 1));
    await sem.WaitAsync();
    try
    {
        var globalEmail = Environment.GetEnvironmentVariable("LE_EMAIL");
        var emailToUse = string.IsNullOrWhiteSpace(globalEmail) ? email : globalEmail;

        // Pass emailToUse instead of 'email' to EnsureAccountAsync:
        var acct = await _accountService.EnsureAccountAsync(emailToUse ?? "", staging, secretClient, accountSecretName);
        
        var acmeCtx = acct.Context;
        if (acct.Error != null) 
        {
                _logger.LogError("ACME account error CorrelationId={CorrelationId} error={Error}", correlationId, acct.Error.Message);
                return (null, acct.Error);
        }

        _logger.LogInformation("ACME account ready CorrelationId={CorrelationId} created={Created} staging={Staging}", 
                correlationId, acct.Created, staging);
            log?.Invoke($"[{correlationId}] ACME account {(acct.Created ? "created" : "loaded")} staging={staging}");

        if (dryRun)
        {
            _logger.LogInformation("Dry run completed CorrelationId={CorrelationId}", correlationId);
            return (new CertificateMetadata
            {
                CertificateName = certificateName,
                Version = "dry-run",
                NotBefore = DateTimeOffset.UtcNow,
                NotAfter = DateTimeOffset.UtcNow.AddDays(90),
                Domains = allDomains.ToArray(),
                Renewed = false
            }, null);
        }

        
        _logger.LogInformation("Creating ACME order CorrelationId={CorrelationId} domainCount={DomainCount}", 
                correlationId, allDomains.Count);
        log?.Invoke($"[{correlationId}] Creating ACME order for domains count={allDomains.Count}");

        // Order + DNS challenges
        var order = await acmeCtx!.NewOrder(allDomains);

        var initialOrderResource = await order.Resource();
        _logger.LogInformation("ACME order created CorrelationId={CorrelationId} orderStatus={OrderStatus} orderUri={OrderUri}", 
            correlationId, initialOrderResource.Status, order.Location);

        var authzContexts = await order.Authorizations();
        _logger.LogDebug("Authorization contexts retrieved CorrelationId={CorrelationId} authzCount={AuthzCount}", 
                correlationId, authzContexts.Count());
        log?.Invoke($"[{correlationId}] Authz contexts retrieved count={(await order.Authorizations()).Count()}");

        _logger.LogInformation("Starting DNS challenge fulfillment CorrelationId={CorrelationId} subscription={Sub} rg={RG} zone={Zone}", 
                correlationId, subscriptionId, zoneResourceGroup, dnsZone);
        log?.Invoke($"[{correlationId}] Starting DNS challenge fulfillment subscription='{subscriptionId}' rg='{zoneResourceGroup}' zone='{dnsZone}'");

        var dnsErr = await _dnsService.FulfillChallengesAsync(
            acmeCtx,
            authzContexts,
            subscriptionId,
            zoneResourceGroup,
            dnsZone,
            cleanupDns,
            propagationMinutes,
            challengeMinutes,
            log);

        log?.Invoke($"[{correlationId}] DNS challenges validated; proceeding to CSR generation.");

        if (dnsErr != null) return (null, dnsErr);

            _logger.LogInformation("DNS challenges completed CorrelationId={CorrelationId}", correlationId);
            log?.Invoke($"[{correlationId}] DNS challenges validated; proceeding to CSR generation.");

            // Check order status before proceeding to CSR
            var preCSROrderResource = await order.Resource();
            _logger.LogInformation("Order status before CSR CorrelationId={CorrelationId} status={Status}", 
                correlationId, preCSROrderResource.Status);

            if (preCSROrderResource.Status == OrderStatus.Invalid)
            {
                // Get detailed error information from the order
                var errorDetails = await GetOrderErrorDetailsAsync(order, correlationId);
                _logger.LogError("Order marked as invalid CorrelationId={CorrelationId} errors={Errors}", 
                    correlationId, errorDetails);
                
                return (null, _responses.Error("order_invalid", 
                    "Let's Encrypt marked the order as invalid", errorDetails));
            }

            if (preCSROrderResource.Status != OrderStatus.Ready)
            {
                _logger.LogWarning("Order not ready for finalization CorrelationId={CorrelationId} status={Status}", 
                    correlationId, preCSROrderResource.Status);
                
                // Wait a bit and check again
                await Task.Delay(TimeSpan.FromSeconds(5));
                var recheckOrderResource = await order.Resource();
                _logger.LogInformation("Order status after delay CorrelationId={CorrelationId} status={Status}", 
                    correlationId, recheckOrderResource.Status);

                if (recheckOrderResource.Status == OrderStatus.Invalid)
                {
                    var errorDetails = await GetOrderErrorDetailsAsync(order, correlationId);
                    _logger.LogError("Order became invalid during wait CorrelationId={CorrelationId} errors={Errors}", 
                        correlationId, errorDetails);
                    
                    return (null, _responses.Error("order_invalid", 
                        "Let's Encrypt order became invalid", errorDetails));
                }

                if (recheckOrderResource.Status != OrderStatus.Ready)
                {
                    var errorDetails = await GetOrderErrorDetailsAsync(order, correlationId);
                    return (null, _responses.Error("order_not_ready", 
                        $"Order not ready for finalization. Status: {recheckOrderResource.Status}", errorDetails));
                }
            }

        // CSR
        _logger.LogDebug("Generating CSR CorrelationId={CorrelationId}", correlationId);
        var csrKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
        var csrInfo = new CsrInfo { CommonName = primaryDomain };
        await order.Generate(csrInfo, csrKey);

        var postCSROrderResource = await order.Resource();
            _logger.LogInformation("Order status after CSR CorrelationId={CorrelationId} status={Status}", 
                correlationId, postCSROrderResource.Status);

            if (postCSROrderResource.Status == OrderStatus.Invalid)
            {
                var errorDetails = await GetOrderErrorDetailsAsync(order, correlationId);
                _logger.LogError("Order invalid after CSR CorrelationId={CorrelationId} errors={Errors}", 
                    correlationId, errorDetails);
                
                return (null, _responses.Error("order_invalid_post_csr", 
                    "Order became invalid after CSR submission", errorDetails));
            }

            // Wait for order to be processed
            var maxWaitTime = TimeSpan.FromMinutes(2);
            var startWait = DateTime.UtcNow;
            
            while (DateTime.UtcNow - startWait < maxWaitTime)
            {
                var currentOrderResource = await order.Resource();
                _logger.LogDebug("Polling order status CorrelationId={CorrelationId} status={Status} elapsed={Elapsed}ms", 
                    correlationId, currentOrderResource.Status, (DateTime.UtcNow - startWait).TotalMilliseconds);

                if (currentOrderResource.Status == OrderStatus.Valid)
                {
                    _logger.LogInformation("Order completed successfully CorrelationId={CorrelationId}", correlationId);
                    break;
                }
                else if (currentOrderResource.Status == OrderStatus.Invalid)
                {
                    var errorDetails = await GetOrderErrorDetailsAsync(order, correlationId);
                    _logger.LogError("Order failed during processing CorrelationId={CorrelationId} errors={Errors}", 
                        correlationId, errorDetails);
                    
                    return (null, _responses.Error("order_processing_failed", 
                        "Let's Encrypt order failed during processing", errorDetails));
                }
                else if (currentOrderResource.Status == OrderStatus.Processing)
                {
                    _logger.LogDebug("Order still processing CorrelationId={CorrelationId}", correlationId);
                    await Task.Delay(TimeSpan.FromSeconds(3));
                }
                else
                {
                    _logger.LogWarning("Unexpected order status CorrelationId={CorrelationId} status={Status}", 
                        correlationId, currentOrderResource.Status);
                    await Task.Delay(TimeSpan.FromSeconds(3));
                }
            }

            // Final status check
            var finalOrderResource = await order.Resource();
            if (finalOrderResource.Status != OrderStatus.Valid)
            {
                var errorDetails = await GetOrderErrorDetailsAsync(order, correlationId);
                _logger.LogError("Order not valid after processing CorrelationId={CorrelationId} finalStatus={Status} errors={Errors}", 
                    correlationId, finalOrderResource.Status, errorDetails);
                
                return (null, _responses.Error("order_timeout", 
                    $"Order did not complete successfully. Final status: {finalOrderResource.Status}", errorDetails));
            }

            // Download chain
            _logger.LogDebug("Downloading certificate chain CorrelationId={CorrelationId}", correlationId);
            var certChain = await order.Download(); // CertificateChain (leaf + issuers as IEncodable)
            var leafDer = certChain.Certificate.ToDer();
            var issuerDers = certChain.Issuers?.Select(i => i.ToDer()).ToList() ?? new List<byte[]>();

        // Subject logging (best effort)
        string TrySubject(byte[] der)
        {
            try { return new X509Certificate2(der).Subject; }
            catch { return "<unparseable>"; }
        }

        _logger.LogInformation("Certificate chain downloaded CorrelationId={CorrelationId} leaf={Leaf} issuerCount={IssuerCount}", 
                correlationId, TrySubject(leafDer), issuerDers.Count);
        log?.Invoke($"[{correlationId}] Leaf='{TrySubject(leafDer)}' Issuers='{string.Join(" | ", issuerDers.Select(TrySubject))}' Count={issuerDers.Count}");

        byte[] pfxBytes;
        bool chainBuiltNormally = false;
        bool leafFallbackUsed = false;
        bool allowLeafFallback = (Environment.GetEnvironmentVariable("LEAF_ONLY_FALLBACK")?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false);

        // Primary (standard) path
        try
        {
            var pfxBuilder = certChain.ToPfx(csrKey); // lets Certes assemble chain
            pfxBytes = pfxBuilder.Build(certificateName, pfxPassword);
            chainBuiltNormally = true;
            _logger.LogDebug("PFX built via standard method CorrelationId={CorrelationId}", correlationId);
            log?.Invoke($"[{correlationId}] PFX built via certChain.ToPfx.");
        }
        catch (Exception standardEx)
        {
            _logger.LogWarning(standardEx, "Standard PFX build failed CorrelationId={CorrelationId}", correlationId);
            log?.Invoke($"[{correlationId}] Standard PFX build failed: {standardEx.Message}; attempting manual chain.");

            try
            {
                var manualBuilder = new PfxBuilder(leafDer, csrKey);
                foreach (var issuerDer in issuerDers)
                {
                    try
                    {
                        manualBuilder.AddIssuer(issuerDer);
                    }
                    catch (Exception addEx)
                    {
                        _logger.LogWarning(addEx, "Failed to add issuer CorrelationId={CorrelationId} issuer={Issuer}",
                            correlationId, TrySubject(issuerDer));
                        log?.Invoke($"[{correlationId}] Issuer add failed for '{TrySubject(issuerDer)}': {addEx.Message}");
                    }
                }
                pfxBytes = manualBuilder.Build(certificateName, pfxPassword);
                log?.Invoke($"[{correlationId}] PFX built via manual issuer addition.");
            }
            catch (Exception manualEx)
            {
                _logger.LogError(manualEx, "Manual PFX build failed CorrelationId={CorrelationId}", correlationId);
                log?.Invoke($"[{correlationId}] Manual chain build failed: {manualEx.Message}");

                if (allowLeafFallback)
                {
                    try
                    {
                        var leafBuilder = new PfxBuilder(leafDer, csrKey);
                        pfxBytes = leafBuilder.Build(certificateName, pfxPassword);
                        leafFallbackUsed = true;
                        _logger.LogWarning("Using leaf-only fallback CorrelationId={CorrelationId}", correlationId);
                        log?.Invoke($"[{correlationId}] Leaf-only fallback succeeded.");
                    }
                    catch (Exception leafEx)
                    {
                        _logger.LogError(leafEx, "Leaf-only fallback failed CorrelationId={CorrelationId}", correlationId);
                        return (null, _responses.Error(
                            "chain_error",
                            "Certificate chain assembly failed (leaf fallback also failed).",
                            $"{standardEx.Message} | {manualEx.Message} | {leafEx.Message}"));
                    }
                }
                else
                {
                    return (null, _responses.Error(
                        "chain_error",
                        "Certificate chain assembly failed.",
                        $"{standardEx.Message} | {manualEx.Message}"));
                }
            }
        }

        // Import to Key Vault
        _logger.LogDebug("Importing certificate to Key Vault CorrelationId={CorrelationId} keyVault={KeyVault}", 
            correlationId, keyVaultName);
        var importResult = await _kvService.ImportCertificateVersionAsync(
            keyVaultName,
            certificateName,
            pfxBytes,
            pfxPassword,
            allDomains.ToArray(),
            renewed: false);

        if (importResult.error != null) 
        {
                _logger.LogError("Key Vault import failed CorrelationId={CorrelationId} error={Error}", 
                    correlationId, importResult.error.Message);
                return (null, importResult.error);
            }

            _logger.LogInformation("Certificate issuance SUCCESS CorrelationId={CorrelationId} cert={CertName} chainMethod={ChainMethod}", 
                correlationId, certificateName, 
                chainBuiltNormally ? "standard" : leafFallbackUsed ? "leaf-only" : "manual");

            if (!chainBuiltNormally && leafFallbackUsed)
                log?.Invoke($"[{correlationId}] Imported leaf-only certificate (intermediate(s) missing).");

            return (importResult.meta, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during certificate issuance CorrelationId={CorrelationId} cert={CertName} innerException={InnerException}", 
                correlationId, certificateName, ex.InnerException?.Message);
            
            // Enhanced error details for debugging
            var errorDetails = new List<string> { ex.Message };
            if (ex.InnerException != null)
                errorDetails.Add($"Inner: {ex.InnerException.Message}");
            
            return (null, _responses.Error("order_error", "Unexpected failure during issuance.", errorDetails.ToArray()));
        }
        finally
        {
            sem.Release();
        }
    }

    private async Task<string> GetOrderErrorDetailsAsync(IOrderContext order, string correlationId)
    {
        try
        {
            var orderResource = await order.Resource();
            var authzContexts = await order.Authorizations();
            var errorDetails = new List<string>();

            errorDetails.Add($"Order Status: {orderResource.Status}");
            
            if (orderResource.Error != null)
        {
            var errorType = orderResource.Error.GetType().GetProperty("Type")?.GetValue(orderResource.Error)?.ToString() ?? "Unknown";
            var errorDetail = orderResource.Error.GetType().GetProperty("Detail")?.GetValue(orderResource.Error)?.ToString() ?? "No details";
            errorDetails.Add($"Order Error: {errorType} - {errorDetail}");
        }

            foreach (var authz in authzContexts)
            {
                try
                {
                    var authzResource = await authz.Resource();
                    var domain = authzResource.Identifier.Value;
                    
                    if (authzResource.Status == AuthorizationStatus.Invalid)
                    {
                        errorDetails.Add($"Domain {domain}: Authorization INVALID");
                        
                        var challenges = await authz.Challenges();
                        foreach (var challenge in challenges)
                        {
                            var challengeResource = await challenge.Resource();
                            if (challengeResource.Status == ChallengeStatus.Invalid && challengeResource.Error != null)
                            {
                                // Fix: Properly handle the Challenge Error object with null checking and safe casting
                                var challengeErrorType = challengeResource.Error.GetType().GetProperty("Type")?.GetValue(challengeResource.Error)?.ToString() ?? "Unknown";
                                var challengeErrorDetail = challengeResource.Error.GetType().GetProperty("Detail")?.GetValue(challengeResource.Error)?.ToString() ?? "No details";
                                errorDetails.Add($"Domain {domain} Challenge {challenge.Type}: {challengeErrorType} - {challengeErrorDetail}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to get authorization details CorrelationId={CorrelationId}", correlationId);
                    errorDetails.Add($"Failed to get auth details: {ex.Message}");
                }
            }

            return string.Join(" | ", errorDetails);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get order error details CorrelationId={CorrelationId}", correlationId);
            return $"Failed to get error details: {ex.Message}";
        }
    }
}