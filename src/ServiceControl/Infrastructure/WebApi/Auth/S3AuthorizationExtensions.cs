#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ServiceControl.Infrastructure;
using ServiceControl.MessageFailures;
using ServiceControl.Recoverability;

/// <summary>
/// Registers the S3 resource-based authorization handlers and the dynamic permission policy provider.
/// <para>
/// The <see cref="PermissionPolicyProvider"/> is registered unconditionally so that
/// <c>[Authorize(Policy = "messages:retry")]</c> attributes do not cause "policy not found"
/// errors when OIDC is disabled. When OIDC is disabled, it returns allow-all policies.
/// </para>
/// <para>
/// When OIDC is disabled, an <see cref="AllowAllResourceHandler"/> is also registered so that
/// explicit <c>IAuthorizationService.AuthorizeAsync(user, resource, requirement)</c> calls
/// in controllers pass unconditionally — preserving the pre-RBAC behaviour (spec §4).
/// </para>
/// <para>
/// Call this after <c>AddServiceControlAuthentication</c> in the host setup.
/// </para>
/// </summary>
public static class S3AuthorizationExtensions
{
    public static void AddServiceControlS3Authorization(
        this IHostApplicationBuilder hostBuilder,
        OpenIdConnectSettings oidcSettings)
    {
        var services = hostBuilder.Services;

        // Register PermissionPolicyProvider unconditionally so [Authorize(Policy=...)] attributes
        // do not throw "policy not found" errors regardless of OIDC being enabled or disabled.
        // When oidcEnabled=false it returns allow-all policies; when true, real policies.
        // Note: AddAuthorization() is intentionally NOT called here — ASP.NET Core's
        // WebApplication builder registers IAuthorizationService by default, and calling
        // AddAuthorization() when OIDC is disabled triggers endpoint metadata side-effects
        // that break tests accessing EndpointDataSource after host disposal.
        services.AddSingleton<IAuthorizationPolicyProvider>(sp =>
            new PermissionPolicyProvider(
                sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>(),
                oidcSettings.Enabled));

        if (!oidcSettings.Enabled)
        {
            // OIDC is disabled: register an allow-all handler for explicit resource-scope checks.
            // Controllers call AuthorizeAsync(user, resource, requirement) explicitly — without
            // a registered handler, that call would return failure (no handler succeeded).
            services.AddSingleton<IAuthorizationHandler, AllowAllResourceHandler>();
            return;
        }

        // Verb-level handler: PermissionRequirement with no resource (fires from [Authorize(Policy=...)])
        services.AddSingleton<IAuthorizationHandler, PermissionVerbHandler>();

        // Resource-scope handler: PermissionRequirement + FailedMessage (fires from explicit AuthorizeAsync call)
        services.AddSingleton<IAuthorizationHandler, FailedMessageAuthorizationHandler>();

        // Resource-scope handler: PermissionRequirement + FailureGroupView
        // Groups span multiple queues; fail-closed for scoped users (see FailureGroupAuthorizationHandler).
        services.AddSingleton<IAuthorizationHandler, FailureGroupAuthorizationHandler>();
    }

    /// <summary>
    /// Succeeds any <see cref="PermissionRequirement"/> regardless of resource or user claims.
    /// Used when OIDC is disabled to preserve the pre-RBAC "allow everything" behaviour
    /// for explicit resource-scope authorization calls in controllers.
    /// </summary>
    sealed class AllowAllResourceHandler : IAuthorizationHandler
    {
        public Task HandleAsync(AuthorizationHandlerContext context)
        {
            foreach (var requirement in context.PendingRequirements)
            {
                if (requirement is PermissionRequirement)
                {
                    context.Succeed(requirement);
                }
            }

            return Task.CompletedTask;
        }
    }
}
