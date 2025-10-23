using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Certes;
using Certes.Acme;
using Keyvault_cert_issueance.Models;

namespace Keyvault_cert_issueance.Services;

public class AcmeAccountService
{
    private readonly ResponseFactory _responses;
    private static readonly ConcurrentDictionary<string, AcmeContext> _cache = new(StringComparer.OrdinalIgnoreCase);

    public AcmeAccountService(ResponseFactory responses)
    {
        _responses = responses;
    }

    private Uri GetServer(bool staging) =>
        staging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;

    public async Task<(AcmeContext? Context, ApiError? Error, bool Created)> EnsureAccountAsync(
        string email,
        bool staging,
        SecretClient? secretClient,
        string? accountSecretName)
    {
        if (string.IsNullOrWhiteSpace(email))
            return (null, _responses.Error("validation", "Email is required."), false);

        if (secretClient == null)
            return (null, _responses.Error("config", "SecretClient (Key Vault) not configured."), false);

        // Resolve secret name precedence:
        // 1. Explicit parameter
        // 2. Environment variable ACCOUNT_KEY_SECRET_NAME(_STAGING)
        // 3. Conventional fallback
        string envName = staging
            ? Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME_STAGING") ?? ""
            : Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME") ?? "";

        string secretName = accountSecretName
            ?? (string.IsNullOrWhiteSpace(envName)
                ? $"acme-account{(staging ? "-staging" : "-prod")}"
                : envName);

        if (_cache.TryGetValue(secretName, out var cached))
            return (cached, null, false);

        var server = GetServer(staging);

        try
        {
            // Try existing secret
            KeyVaultSecret existing = await secretClient.GetSecretAsync(secretName);
            var key = KeyFactory.FromPem(existing.Value);
            var ctx = new AcmeContext(server, key);
            // Light validation
            _ = await ctx.Account();
            _cache[secretName] = ctx;
            return (ctx, null, false);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            // Need to create new account
            try
            {
                var ctx = new AcmeContext(server);
                await ctx.NewAccount(email, true);
                var pem = ctx.AccountKey.ToPem();
                await secretClient.SetSecretAsync(new KeyVaultSecret(secretName, pem));
                _cache[secretName] = ctx;
                return (ctx, null, true);
            }
            catch (Exception inner)
            {
                return (null, _responses.Error("acme_account_create", "Failed creating ACME account.", inner.Message), false);
            }
        }
        catch (Exception ex)
        {
            return (null, _responses.Error("acme_account_load", "Failed loading ACME account.", ex.Message), false);
        }
    }
}