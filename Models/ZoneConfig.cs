//// filepath: Models/ZoneConfig.cs
namespace Keyvault_cert_issueance.Models;

public class ZoneConfig
{
    public string Zone { get; set; } = "";
    public string CertificateName { get; set; } = "";
    public string KeyVaultName { get; set; } = "";
    public string DnsZone { get; set; } = "";
    public string PrimaryDomain { get; set; } = "";
    public string[] AdditionalNames { get; set; } = Array.Empty<string>();
    public string Email { get; set; } = "";
    public bool Staging { get; set; }
    public bool CleanupDns { get; set; }
    public int PropagationMinutes { get; set; } = 2;
    public int ChallengeMinutes { get; set; } = 5;
    public string SubscriptionId { get; set; } = ""; // Interpreted as Key Vault subscription
    // If you later need a different subscription for the DNS zone, add: public string? DnsSubscriptionId { get; set; }
    public string ResourceGroup { get; set; } = "";
    public string? PfxPassword { get; set; }
    public int? renewalThresholdDays { get; set; } = 15;
    public bool? DryRun { get; set; }
}