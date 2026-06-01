namespace ServiceControl.Hosting.Commands
{
    using System;
    using System.IO;
    using System.Threading.Tasks;
    using Infrastructure.WebApi;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.Extensions.DependencyInjection;
    using NServiceBus;
    using Particular.ServiceControl;
    using Particular.ServiceControl.Hosting;
    using ServiceBus.Management.Infrastructure.Settings;
    using ServiceControl;
    using ServiceControl.Hosting.Auth;
    using ServiceControl.Hosting.Https;
    using ServiceControl.Infrastructure.CustomIndexes;
    using ServiceControl.Infrastructure.WebApi.Auth;
    using ServicePulse;

    class RunCommand : AbstractCommand
    {
        public override async Task Execute(HostArguments args, Settings settings)
        {
            var endpointConfiguration = new EndpointConfiguration(settings.InstanceName);
            var assemblyScanner = endpointConfiguration.AssemblyScanner();
            assemblyScanner.ExcludeAssemblies("ServiceControl.Plugin");

            settings.RunCleanupBundle = true;

            // Custom-index spike: load extract-headers.yaml once at host startup so
            // DatabaseSetup and the WebApi can both read it from the static accessor.
            // Path resolution mirrors RbacPolicyFile.
            var extractHeadersFile = Path.IsPathRooted("extract-headers.yaml")
                ? "extract-headers.yaml"
                : Path.Combine(AppContext.BaseDirectory, "extract-headers.yaml");
            var customIndexConfig = CustomIndexLoader.LoadFromFile(extractHeadersFile);
            CustomIndexConfig.SetActive(customIndexConfig);

            var hostBuilder = WebApplication.CreateBuilder();

            hostBuilder.Services.AddSingleton(customIndexConfig);

            hostBuilder.AddServiceControlAuthentication(settings.OpenIdConnectSettings);
            hostBuilder.AddServiceControlAuthorization(settings.OpenIdConnectSettings);
            hostBuilder.AddServiceControlS3Authorization(settings.OpenIdConnectSettings);
            hostBuilder.AddServiceControlHttps(settings.HttpsSettings);
            hostBuilder.AddServiceControl(settings, endpointConfiguration);
            hostBuilder.AddServiceControlApi(settings.CorsSettings);

            var app = hostBuilder.Build();
            app.UseServiceControl(settings.ForwardedHeadersSettings, settings.HttpsSettings);
            if (settings.EnableIntegratedServicePulse)
            {
                app.UseServicePulse(settings.ServicePulseSettings);
            }
            app.UseServiceControlAuthentication(settings.OpenIdConnectSettings.Enabled);

            await app.RunAsync(settings.RootUrl);
        }
    }
}
