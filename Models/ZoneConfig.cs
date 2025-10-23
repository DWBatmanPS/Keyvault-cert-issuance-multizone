public class ZoneConfig
{
    public string DnsZone { get; set; } = "";
    public string CertificateName { get; set; } = "";
    public string SubscriptionId { get; set; } = "";
    public string ResourceGroup { get; set; } = "";
    public string KeyVaultName { get; set; } = "";
    public string PrimaryDomain { get; set; } = "";
    public IEnumerable<string> AdditionalNames { get; set; } = Array.Empty<string>();
    public string Email { get; set; } = "";
    public bool Staging { get; set; }
    public bool CleanupDns { get; set; } = true;
    public int RenewalThresholdDays { get; set; } = 20;
    public int PropagationMinutes { get; set; } = 2;
    public int ChallengeMinutes { get; set; } = 5;
    public string? PfxPassword { get; set; }
}