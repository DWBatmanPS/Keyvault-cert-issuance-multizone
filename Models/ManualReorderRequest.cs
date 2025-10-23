public class ManualReorderRequest
{
    public string Zone { get; set; } = "";
    public string CertificateName { get; set; } = "";
    public bool? RevokePrevious { get; set; }
    public bool? UseStaging { get; set; }
    public bool? Force { get; set; } // reserved for future override logic
}