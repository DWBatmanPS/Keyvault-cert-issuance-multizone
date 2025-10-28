using System;
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Data.Tables;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.ApplicationInsights;
using Microsoft.Extensions.Logging.ApplicationInsights;
using Keyvault_cert_issueance.Services;
using Azure.ResourceManager;

namespace Keyvault_cert_issueance;

public static class Program
{
    public static void Main(string[] args)
    {
        var verbose = (Environment.GetEnvironmentVariable("LE_VERBOSE") ?? "")
            .Equals("true", StringComparison.OrdinalIgnoreCase);

        var host = new HostBuilder()
            .ConfigureFunctionsWorkerDefaults() // no lambda -> avoids WorkerOptions mismatch
            .ConfigureLogging(logging =>
            {
                logging.AddApplicationInsights(); // requires APPLICATIONINSIGHTS_CONNECTION_STRING
                logging.SetMinimumLevel(verbose ? LogLevel.Trace : LogLevel.Information);
                logging.AddFilter<ApplicationInsightsLoggerProvider>("", verbose ? LogLevel.Trace : LogLevel.Information);
                logging.AddFilter("Keyvault_cert_issueance.Services.DnsChallengeService", LogLevel.Trace);
                logging.AddFilter("Keyvault_cert_issueance.Services.CertificateOrderService", LogLevel.Trace);
                logging.AddFilter("Keyvault_cert_issueance.Services.AcmeAccountService", LogLevel.Trace);
            })
            .ConfigureServices(services =>
            {

                services.AddSingleton(new DefaultAzureCredential());

                services.AddSingleton(sp =>
                {
                    var cred = sp.GetRequiredService<DefaultAzureCredential>();
                    var sub = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID")
                        ?? throw new InvalidOperationException("AZURE_SUBSCRIPTION_ID not set.");
                    return new ArmClient(cred, sub);
                });

                services.AddSingleton(sp =>
                {
                    var account = Environment.GetEnvironmentVariable("TABLE_STORAGE_ACCOUNT_NAME")
                        ?? throw new InvalidOperationException("TABLE_STORAGE_ACCOUNT_NAME not set.");
                    var uri = new Uri($"https://{account}.table.core.windows.net/");
                    return new TableServiceClient(uri, sp.GetRequiredService<DefaultAzureCredential>());
                });

                services.AddSingleton<ZoneConfigTableProvider>(sp =>
                {
                    var svc = sp.GetRequiredService<TableServiceClient>();
                    var name = Environment.GetEnvironmentVariable("ZONE_CONFIG_TABLE") ?? "zoneconfigs";
                    svc.CreateTableIfNotExists(name);
                    return new ZoneConfigTableProvider(svc.GetTableClient(name));
                });

                services.AddSingleton<RateEventsTableProvider>(sp =>
                {
                    var svc = sp.GetRequiredService<TableServiceClient>();
                    var name = Environment.GetEnvironmentVariable("RATE_LIMIT_TABLE") ?? "issuanceevents";
                    svc.CreateTableIfNotExists(name);
                    return new RateEventsTableProvider(svc.GetTableClient(name));
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

                services.AddSingleton<ZoneConfigService>();
                services.AddSingleton<RateLimiterService>();
                services.AddSingleton<DistributedLockService>();
                services.AddSingleton<ResponseFactory>();
                services.AddSingleton<KeyVaultService>();
                services.AddSingleton<DnsChallengeService>();
                services.AddSingleton<AcmeAccountService>();
                services.AddSingleton<CertificateOrderService>();
                services.AddSingleton<RevocationService>();
            })
            .Build();

        host.Run();
    }
}

public sealed class ZoneConfigTableProvider
{
    public TableClient Table { get; }
    public ZoneConfigTableProvider(TableClient table) => Table = table;
}

public sealed class RateEventsTableProvider
{
    public TableClient Table { get; }
    public RateEventsTableProvider(TableClient table) => Table = table;
}