public class IssueRequest
{
    public string Zone { get; set; } = "";
    public string CertificateName { get; set; } = "";
    public bool? UseStaging { get; set; }
    public bool? DryRun { get; set; }
}