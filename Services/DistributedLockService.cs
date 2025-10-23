using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Specialized;

public class DistributedLockService
{
    private readonly BlobServiceClient _blobService;
    private readonly string _containerName;

    public DistributedLockService(BlobServiceClient blobService)
    {
        _blobService = blobService;
        _containerName = Environment.GetEnvironmentVariable("LOCKS_CONTAINER") ?? "locks";
    }

    public async Task<(bool acquired, BlobLeaseClient? lease)> AcquireAsync(string zone, string certName, TimeSpan hold)
    {
        var container = _blobService.GetBlobContainerClient(_containerName);
        var blob = container.GetBlobClient($"{zone}--{certName}.lock");
        await blob.UploadAsync(new BinaryData(Array.Empty<byte>()), overwrite: true);
        var leaseClient = blob.GetBlobLeaseClient();
        try
        {
            var lease = await leaseClient.AcquireAsync(hold);
            return (true, leaseClient);
        }
        catch
        {
            return (false, null);
        }
    }

    public async Task ReleaseAsync(BlobLeaseClient? lease)
    {
        if (lease == null) return;
        try { await lease.ReleaseAsync(); } catch { /* swallow */ }
    }
}