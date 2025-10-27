using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Certes;
using Certes.Acme;
using Keyvault_cert_issueance.Models;
using Azure.Identity;

namespace Keyvault_cert_issueance.Services;

public class AcmeAccountService
{
    private readonly ResponseFactory _responses;
    private readonly SecretClient? _defaultSecretClient;

    // Cache contexts by secret name or ephemeral composite key.
    private static readonly ConcurrentDictionary<string, AcmeContext> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public AcmeAccountService(ResponseFactory responses, DefaultAzureCredential credential)
    {
        _responses = responses;

        var kvName = Environment.GetEnvironmentVariable("KEYVAULT_NAME");
        if (!string.IsNullOrWhiteSpace(kvName))
        {
            _defaultSecretClient = new SecretClient(new Uri($"https://{kvName}.vault.azure.net/"), credential);
        }
    }

    private static Uri GetServer(bool staging) =>
        staging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;

    private string ResolveAccountSecretName(bool staging, string? overrideName)
    {
        if (!string.IsNullOrWhiteSpace(overrideName))
            return overrideName;

        // Priority: explicit staging/prod env names > base env name > default fallback
        if (staging)
        {
            var stagingEnv = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME_STAGING");
            if (!string.IsNullOrWhiteSpace(stagingEnv)) return stagingEnv;
        }
        else
        {
            var prodEnv = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME_PROD");
            if (!string.IsNullOrWhiteSpace(prodEnv)) return prodEnv;
        }

        var baseEnv = Environment.GetEnvironmentVariable("ACCOUNT_KEY_SECRET_NAME");
        if (!string.IsNullOrWhiteSpace(baseEnv))
            return staging ? $"{baseEnv}-staging" : baseEnv; // if using a single base name, append suffix for staging

        return staging ? "acme-account-staging" : "acme-account-prod";
    }

    private async Task<KeyVaultSecret?> TryGetSecretAsync(SecretClient? client, string name)
    {
        if (client == null) return null;
        try
        {
            return await client.GetSecretAsync(name);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    /// <summary>
    /// Ensures a shared ACME account exists. If the secret exists, email may be blank.
    /// If creating new (no secret found), email is required.
    /// </summary>
    public async Task<(AcmeContext? Context, ApiError? Error, bool Created)> EnsureAccountAsync(
        string email,
        bool staging,
        SecretClient? secretClient,
        string? accountSecretName)
    {
        var sc = secretClient ?? _defaultSecretClient;
        var server = GetServer(staging);
        var secretName = ResolveAccountSecretName(staging, accountSecretName);

        // If we already cached context for this secret, reuse.
        if (_cache.TryGetValue(secretName, out var cachedCtx))
            return (cachedCtx, null, false);

        // Attempt to load existing secret (if we have a client).
        var existingSecret = await TryGetSecretAsync(sc, secretName);
        if (existingSecret != null)
        {
            var acctKey = KeyFactory.FromPem(existingSecret.Value);
            var ctxLoaded = new AcmeContext(server, acctKey);
            _cache[secretName] = ctxLoaded;
            return (ctxLoaded, null, false);
        }

        // No stored account key. Need email to create account.
        if (string.IsNullOrWhiteSpace(email))
        {
            return (null, _responses.Error(
                "account_email_missing",
                "ACME account email required for initial registration.",
                "Provide email to RegisterAccount function or set LE_EMAIL/ACME_ACCOUNT_EMAIL."), false);
        }

        // If no SecretClient (local dev or intentionally ephemeral) -> ephemeral context
        if (sc == null)
        {
            string ephemeralKey = $"ephemeral::{(staging ? "stg" : "prod")}::{email}";
            if (_cache.TryGetValue(ephemeralKey, out var ephCtx))
                return (ephCtx, null, false);

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

        // Create + persist new account key
        try
        {
            var ctx = new AcmeContext(server);
            await ctx.NewAccount(email, true);
            var pem = ctx.AccountKey.ToPem();
            await sc.SetSecretAsync(new KeyVaultSecret(secretName, pem));
            _cache[secretName] = ctx;
            return (ctx, null, true);
        }
        catch (Exception ex)
        {
            return (null, _responses.Error("acme_account_create", "Failed creating ACME account.", ex.Message), false);
        }
    }
}