namespace ServiceControl.Hosting.Auth;

using System;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ServiceControl.Infrastructure;
using ServiceControl.Infrastructure.Auth.Rbac;
using ServiceControl.Infrastructure.Auth.Tenants;

/// <summary>
/// Registers the ServiceControl RBAC authorization services.
/// Mirrors <see cref="HostApplicationBuilderExtensions.AddServiceControlAuthentication"/> —
/// early-returns when OIDC is disabled so existing deployments are byte-for-byte unchanged.
/// </summary>
public static class AuthorizationHostApplicationBuilderExtensions
{
    /// <summary>
    /// Registers the ServiceControl authorization services.
    /// Does nothing when <paramref name="oidcSettings"/>.Enabled is <see langword="false"/>.
    /// </summary>
    public static void AddServiceControlAuthorization(
        this IHostApplicationBuilder hostBuilder,
        OpenIdConnectSettings oidcSettings)
    {
        if (!oidcSettings.Enabled)
        {
            return;
        }

        // Note: the authenticated-user FallbackPolicy (spec §5.5) is intentionally NOT registered
        // here — it is already wired up by AddServiceControlAuthentication via AddAuthorization()
        // in HostApplicationBuilderExtensions. Duplicating it here would be redundant.

        // The policy is loaded once at startup (reloading is a later enhancement).
        // We capture the load time so the descriptor endpoint can expose it as the 'version' field.
        var policyFilePath = ResolveRbacPolicyPath(oidcSettings.RbacPolicyFile);
        var policy = RbacPolicyLoader.LoadFromFile(policyFilePath);

        // Register as a singleton factory so Phase 1 can swap the policy at runtime.
        hostBuilder.Services.AddSingleton<Func<RbacPolicy>>(() => policy);

        hostBuilder.Services.AddSingleton<IPermissionEvaluator>(sp =>
            new PermissionEvaluator(sp.GetRequiredService<Func<RbacPolicy>>()));

        hostBuilder.Services.AddSingleton<IAuthorizationAuditLog, AuthorizationAuditLog>();

        // IdP-managed authorization data: the tenant set lives on the JWT, not in rbac.yaml.
        // Reads the claim configured by Authentication.TenantsClaim (default: "tenants").
        var tenantsClaim = oidcSettings.TenantsClaim;
        hostBuilder.Services.AddSingleton<IUserTenantsProvider>(
            new ClaimBasedUserTenantsProvider(tenantsClaim));

        // Ensure the claims transformation runs for every request so the IdP-supplied
        // role/group values are flattened into canonical 'role' / 'group' claims before
        // authorization is evaluated. The claim paths are configurable for IdP portability:
        //   Keycloak (default)      Authentication.RolesClaim=realm_access.roles  Authentication.GroupsClaim=groups
        //   Microsoft Entra ID      Authentication.RolesClaim=roles               Authentication.GroupsClaim=groups
        //   AWS Cognito             Authentication.RolesClaim=cognito:groups      Authentication.GroupsClaim=cognito:groups
        hostBuilder.Services.AddSingleton<Microsoft.AspNetCore.Authentication.IClaimsTransformation>(
            new RolesAndGroupsClaimsTransformation(
                rolesClaimPath: oidcSettings.RolesClaim,
                groupsClaimPath: oidcSettings.GroupsClaim));
    }

    /// <summary>
    /// Resolves the RBAC policy file path. If the configured path is not absolute,
    /// resolve it relative to the directory containing the host assembly (i.e. the output folder).
    /// </summary>
    static string ResolveRbacPolicyPath(string configuredPath)
    {
        if (Path.IsPathRooted(configuredPath))
        {
            return configuredPath;
        }

        var baseDir = AppContext.BaseDirectory;
        return Path.Combine(baseDir, configuredPath);
    }
}
