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

    // Cache contexts by a composite key (secretName or fallback key).
    private static readonly ConcurrentDictionary<string, AcmeContext> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public AcmeAccountService(ResponseFactory responses)
    {
        _responses = responses;
    }

    private static Uri GetServer(bool staging) =>
        staging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;

    /// <summary>
    /// Ensures an ACME account exists (and returns its context).
    /// </summary>
    /// <param name="email">Account email (required).</param>
    /// <param name="staging">Use staging server if true.</param>
    /// <param name="secretClient">Key Vault secret client (optional; if null, an in-memory account is used).</param>
    /// <param name="accountSecretName">Explicit secret name override.</param>
    /// <returns>(Context, Error, Created)</returns>
    public async Task<(AcmeContext? Context, ApiError? Error, bool Created)> EnsureAccountAsync(
        string email,
        bool staging,
        SecretClient? secretClient,
        string? accountSecretName)
    {
        if (string.IsNullOrWhiteSpace(email))
            return (null, _responses.Error("validation", "Email is required."), false);

        var server = GetServer(staging);

        // If Key Vault not supplied: ephemeral in-memory account (still cached for reuse during process lifetime).
        if (secretClient == null)
        {
            string ephemeralKey = $"ephemeral::{(staging ? "staging" : "prod")}::{email}";
            if (_cache.TryGetValue(ephemeralKey, out var cached))
                return (cached, null, false);

            try
            {
                var ctx = new AcmeContext(server);
                await ctx.NewAccount(email, true);
                _cache[ephemeralKey] = ctx;
                return (ctx, null, true);
            }
            catch (Exception ex)
            {
                return (null, _responses.Error("acme_account_create", "Failed creating ephemeral ACME account.", ex.Message), false);
            }
        }

        // Resolve secret name precedence: explicit parameter > env > default
        string envName = staging
            ? Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME_STAGING") ?? ""
            : Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME") ?? "";

        string secretName = accountSecretName
            ?? (string.IsNullOrWhiteSpace(envName)
                ? $"acme-account{(staging ? "-staging" : "-prod")}"
                : envName);

        // Return cached if available.
        if (_cache.TryGetValue(secretName, out var cachedCtx))
            return (cachedCtx, null, false);

        // Attempt load existing secret.
        try
        {
            KeyVaultSecret existing = await secretClient.GetSecretAsync(secretName);
            var key = KeyFactory.FromPem(existing.Value);
            var ctx = new AcmeContext(server, key);
            // Light validation to ensure account key is valid.
            _ = await ctx.Account();
            _cache[secretName] = ctx;
            return (ctx, null, false);
        }
        catch (RequestFailedException rfEx) when (rfEx.Status == 404)
        {
            // Need to create a new account and store key.
            try
            {
                var ctx = new AcmeContext(server);
                await ctx.NewAccount(email, true);
                var pem = ctx.AccountKey.ToPem();
                await secretClient.SetSecretAsync(new KeyVaultSecret(secretName, pem));
                _cache[secretName] = ctx;
                return (ctx, null, true);
            }
            catch (Exception createEx)
            {
                return (null, _responses.Error("acme_account_create", "Failed creating ACME account.", createEx.Message), false);
            }
        }
        catch (Exception ex)
        {
            return (null, _responses.Error("acme_account_load", "Failed loading ACME account.", ex.Message), false);
        }
    }
}