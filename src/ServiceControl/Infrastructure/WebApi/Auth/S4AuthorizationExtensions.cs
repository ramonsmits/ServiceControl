#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System;
using Casbin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ServiceControl.Infrastructure;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// Registers the S4 (Casbin-backed) authorization services.
///
/// <para>
/// Wiring overview:
/// <list type="bullet">
///   <item><see cref="PermissionPolicyProvider"/> — generates ASP.NET Core policies for
///     <c>[Authorize(Policy = "messages:retry")]</c> attributes (mechanism-agnostic, shared with S3).</item>
///   <item><see cref="IEnforcer"/> (singleton) — the Casbin enforcer built from the embedded
///     model and the compiled <c>rbac.yaml</c> policy. Rebuilt if policy reload is implemented.</item>
///   <item><see cref="CasbinPermissionVerbHandler"/> — evaluates the coarse verb-level check
///     ("does this user hold the permission for any resource?") via Casbin's implicit permission API.</item>
///   <item><see cref="ICasbinResourceScopeChecker"/> — post-load resource check that controllers
///     call after loading the resource to enforce the fine-grained queue-address scope.</item>
/// </list>
/// </para>
///
/// <para>
/// When OIDC is disabled, all components are replaced with allow-all surrogates so the
/// pre-RBAC behaviour is preserved (spec §4 non-breaking guarantee).
/// </para>
/// </summary>
public static class S4AuthorizationExtensions
{
    /// <summary>
    /// Registers S4 Casbin-backed authorization in the host.
    /// Must be called after <c>AddServiceControlAuthorization</c> (which registers the policy factory).
    /// </summary>
    public static void AddServiceControlS4Authorization(
        this IHostApplicationBuilder hostBuilder,
        OpenIdConnectSettings oidcSettings)
    {
        var services = hostBuilder.Services;

        // Register PermissionPolicyProvider unconditionally so [Authorize(Policy=...)] attributes
        // do not throw "policy not found" errors regardless of OIDC being enabled or disabled.
        // When oidcEnabled=false it returns allow-all policies; when true, real policies.
        services.AddSingleton<IAuthorizationPolicyProvider>(sp =>
            new PermissionPolicyProvider(
                sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>(),
                oidcSettings.Enabled));

        if (!oidcSettings.Enabled)
        {
            // OIDC disabled: register allow-all surrogates so controllers that call
            // ICasbinResourceScopeChecker.EnforceAsync unconditionally pass.
            services.AddSingleton<ICasbinResourceScopeChecker, AllowAllScopeChecker>();
            return;
        }

        // Build the Casbin enforcer from the embedded model + compiled rbac.yaml policy.
        // The enforcer is a singleton — it is built lazily on first use, reading the policy
        // from the Func<RbacPolicy> registered by AddServiceControlAuthorization.
        services.AddSingleton<IEnforcer>(sp =>
        {
            var policyFactory = sp.GetRequiredService<Func<RbacPolicy>>();
            return CasbinEnforcerFactory.Build(policyFactory());
        });

        // Verb-level handler: evaluates [Authorize(Policy="messages:retry")] before the action.
        services.AddSingleton<IAuthorizationHandler, CasbinPermissionVerbHandler>();

        // Resource-scope checker: called explicitly by controllers after loading the resource.
        services.AddSingleton<ICasbinResourceScopeChecker, CasbinResourceScopeChecker>();
    }
}
