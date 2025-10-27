namespace Keyvault_cert_issueance.Models;

public class OrderRequest
{
    public string? Zone { get; set; }              // Zone identifier used to look up config
    public string? CertificateName { get; set; }   // Certificate config key within the zone
    public bool? UseStaging { get; set; }          // Optional override
    public bool? DryRun { get; set; }              // Optional override
    public bool? CleanupDns { get; set; }          // Optional override (otherwise cfg.CleanupDns)
    // Optional future fields; primary/additional now come from config, so they’re omitted.
}