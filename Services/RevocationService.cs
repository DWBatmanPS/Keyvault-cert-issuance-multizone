using System;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Certes;
using Certes.Acme;
using Keyvault_cert_issueance.Models;

namespace Keyvault_cert_issueance.Services;

public class RevocationService
{
    private readonly ResponseFactory _responses;
    public RevocationService(ResponseFactory responses) => _responses = responses;

    // Fully-qualified enum reference helps if namespace resolution was the issue.
    public async Task<ApiError?> RevokeAsync(
        AcmeContext ctx,
        X509Certificate2 x509,
        Certes.Acme.Resource.RevocationReason reason = Certes.Acme.Resource.RevocationReason.Unspecified)
    {
        try
        {
            await ctx.RevokeCertificate(x509.RawData, reason, ctx.AccountKey);
            return null;
        }
        catch (Exception ex)
        {
            return _responses.Error("revoke_error", "Failed revoking certificate.", ex.Message);
        }
    }
}