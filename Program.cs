using System;
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Data.Tables;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Functions.Worker;
using Keyvault_cert_issueance.Services;

namespace Keyvault_cert_issueance;

public static class Program
{
    public static void Main(string[] args)
    {
        var host = new HostBuilder()
            .ConfigureFunctionsWorkerDefaults()
            .ConfigureServices(services =>
            {
                services.AddSingleton(new DefaultAzureCredential());

                services.AddSingleton(sp =>
                {
                    var account = Environment.GetEnvironmentVariable("TABLE_STORAGE_ACCOUNT_NAME")
                        ?? throw new InvalidOperationException("TABLE_STORAGE_ACCOUNT_NAME not set.");
                    var uri = new Uri($"https://{account}.table.core.windows.net/");
                    return new TableServiceClient(uri, sp.GetRequiredService<DefaultAzureCredential>());
                });

                services.AddSingleton(sp =>
                {
                    var svc = sp.GetRequiredService<TableServiceClient>();
                    var cfgName = Environment.GetEnvironmentVariable("ZONE_CONFIG_TABLE") ?? "zoneconfigs";
                    svc.CreateTableIfNotExists(cfgName);
                    return svc.GetTableClient(cfgName);
                });

                services.AddSingleton(sp =>
                {
                    var svc = sp.GetRequiredService<TableServiceClient>();
                    var evtName = Environment.GetEnvironmentVariable("RATE_LIMIT_TABLE") ?? "issuanceevents";
                    svc.CreateTableIfNotExists(evtName);
                    return svc.GetTableClient(evtName);
                });

                services.AddSingleton(sp =>
                {
                    var account = Environment.GetEnvironmentVariable("TABLE_STORAGE_ACCOUNT_NAME")
                        ?? throw new InvalidOperationException("TABLE_STORAGE_ACCOUNT_NAME not set.");
                    var blobEndpoint = new Uri($"https://{account}.blob.core.windows.net/");
                    var blobSvc = new BlobServiceClient(blobEndpoint, sp.GetRequiredService<DefaultAzureCredential>());
                    var container = blobSvc.GetBlobContainerClient(
                        Environment.GetEnvironmentVariable("LOCKS_CONTAINER") ?? "locks");
                    container.CreateIfNotExists();
                    return blobSvc;
                });

                // Services
                services.AddSingleton<ZoneConfigService>();
                services.AddSingleton<RateLimiterService>();
                services.AddSingleton<DistributedLockService>();
                services.AddSingleton<ResponseFactory>();
                services.AddSingleton<KeyVaultService>();
                services.AddSingleton<DnsChallengeService>();
                services.AddSingleton<AcmeAccountService>();
                services.AddSingleton<CertificateOrderService>();
                services.AddSingleton<RevocationService>();

                services.AddLogging(lb => lb.SetMinimumLevel(LogLevel.Information));
            })
            .Build();

        host.Run();
    }
}