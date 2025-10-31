using KSeF.Client.Api.Services;
using KSeF.Client.Clients;
using KSeF.Client.Core.Infrastructure.Rest;
using KSeF.Client.Core.Interfaces;
using KSeF.Client.Core.Interfaces.Clients;
using KSeF.Client.Core.Interfaces.Rest;
using KSeF.Client.Core.Interfaces.Services;
using KSeF.Client.Core.Models.Certificates;
using KSeF.Client.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Net.Http.Headers;
namespace KSeF.Client.DI;

/// <summary>
/// Extension methods do rejestracji KSeF SDK w kontenerze DI.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Rejestruje wszystkie potrzebne serwisy do korzystania z KSeF
    /// </summary>
    /// <param name="services">Rozszerzany interfejs</param>
    /// <param name="configure">Opcje klienta KSeF</param>
    /// <param name="pemCertificatesFetcher">Delegat służący do pobrania publicznych certyfikatów KSeF</param>
    /// <exception cref="ArgumentException"></exception>
    public static IServiceCollection AddKSeFClient(this IServiceCollection services,
        Action<KSeFClientOptions> configure)
    {
        KSeFClientOptions options = new KSeFClientOptions();
        configure(options);
        if (string.IsNullOrEmpty(options.BaseUrl))
            throw new ArgumentException("BaseUrl musi być poprawnym URL.", nameof(options.BaseUrl));

        services.AddSingleton(options);
        
        services
            .AddHttpClient<IRestClient, RestClient>(http =>
            {
                http.BaseAddress = new Uri(options.BaseUrl);
                if (options.CustomHeaders != null && options.CustomHeaders.Count > 0)
                {
                    foreach (KeyValuePair<string, string> header in options.CustomHeaders)
                        http.DefaultRequestHeaders.Add(header.Key, header.Value);
                }
                http.DefaultRequestHeaders.Accept.Add(
                    new MediaTypeWithQualityHeaderValue("application/json"));
            })
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                HttpClientHandler handler = new HttpClientHandler();
                if (options.WebProxy != null)
                {
                    handler.Proxy = options.WebProxy;
                    handler.UseProxy = true;
                }
                return handler;
            });

        services.AddSingleton<IRouteBuilder>(sp =>
        {            
            return new RouteBuilder(options.ApiConfiguration.ApiPrefix, options.ApiConfiguration.ApiVersion);
        });
        services.AddScoped<IKSeFClient, KSeFClient>();
        services.AddScoped<ITestDataClient, TestDataClient>();
        services.AddScoped<IAuthCoordinator, AuthCoordinator>();
        services.AddScoped<ILimitsClient, LimitsClient>();
        
        services.AddScoped<ISignatureService, SignatureService>();
        services.AddScoped<IQrCodeService, QrCodeService>();
        services.AddSingleton<IPersonTokenService, PersonTokenService>();
        services.AddScoped<IVerificationLinkService, VerificationLinkService>();

        services.AddLocalization(options =>
        {
            options.ResourcesPath = "Resources";
        });

        services.Configure<RequestLocalizationOptions>(options =>
        {
            options.SetDefaultCulture("pl-PL")
                .AddSupportedCultures("pl-PL", "en-US")
                .AddSupportedUICultures("pl-PL", "en-US");
        });

        return services;
    }

    /// <summary>
    /// Rejestruje wszystkie potrzebne serwisy do korzystania z klienta kryptograficznego.
    /// </summary>
    /// <param name="services">Rozszerzany interfejs</param>
    /// <param name="warmupMode">Tryb "rozgrzewania" usługi. Domyślnie: Blocking.</param>
    /// <param name="pemCertificatesFetcher">Delegat służący do pobrania publicznych certyfikatów KSeF</param>
    /// <exception cref="ArgumentException"></exception>
    public static IServiceCollection AddCryptographyClient(this IServiceCollection services,
        Func<CancellationToken, Task<ICollection<PemCertificateInfo>>> pemCertificatesFetcher = null,
        CryptographyServiceWarmupMode warmupMode = CryptographyServiceWarmupMode.Blocking)
        {

        // 1. Rejestracja klienta kryptograficznego jako singleton
        services.TryAddSingleton<ICryptographyClient, CryptographyClient>();

        // 2. Rejestracja serwisu kryptograficznego z użyciem delegata
        services.AddSingleton<ICryptographyService, CryptographyService>(serviceProvider =>
        {
            // Definicja domyślnego delegata, jeśli nie został dostarczony
            Func<CancellationToken, Task<ICollection<PemCertificateInfo>>> finalFetcher
            = pemCertificatesFetcher ?? (async (cancellationToken) =>
            {
                using IServiceScope scope = serviceProvider.CreateScope();
                ICryptographyClient cryptographyClient = scope.ServiceProvider.GetRequiredService<ICryptographyClient>();
                return await cryptographyClient.GetPublicCertificatesAsync(cancellationToken);
            });

            return new CryptographyService(finalFetcher);
        });

        // 3. Rejestracja usługi hostowanej (Hosted Service) z wybranym trybem startu
        services.AddHostedService(provider =>
        {
            ICryptographyService cryptographyService = provider.GetRequiredService<ICryptographyService>();
            return new CryptographyWarmupHostedService(cryptographyService, warmupMode);
        });

        return services;
    }
}
