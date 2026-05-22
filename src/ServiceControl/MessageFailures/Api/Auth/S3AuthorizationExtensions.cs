#nullable enable
namespace ServiceControl.MessageFailures.Api.Auth;

using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ServiceControl.Infrastructure;
using ServiceControl.Infrastructure.Auth.Rbac;
using ServiceControl.MessageFailures;

/// <summary>
/// Registers the S3 resource-based authorization handlers and the dynamic permission policy provider.
/// Call this immediately after <c>AddServiceControlAuthorization</c> in the host setup.
/// Early-returns when OIDC is disabled (same guard as <c>AddServiceControlAuthorization</c>).
/// </summary>
public static class S3AuthorizationExtensions
{
    public static void AddServiceControlS3Authorization(
        this IHostApplicationBuilder hostBuilder,
        OpenIdConnectSettings oidcSettings)
    {
        if (!oidcSettings.Enabled)
        {
            return;
        }

        var services = hostBuilder.Services;

        // Replace the default IAuthorizationPolicyProvider with one that generates
        // policies dynamically for permission strings (e.g. "messages:retry").
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();

        // Verb-level handler: PermissionRequirement with no resource (fires from [Authorize(Policy=...)])
        services.AddSingleton<IAuthorizationHandler, PermissionVerbHandler>();

        // Resource-scope handler: PermissionRequirement + FailedMessage (fires from explicit AuthorizeAsync call)
        services.AddSingleton<IAuthorizationHandler, FailedMessageAuthorizationHandler>();
    }
}
