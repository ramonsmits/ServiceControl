#nullable enable
namespace ServiceControl.MessageFailures.Api.Auth;

using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// A dynamic <see cref="IAuthorizationPolicyProvider"/> that generates verb-level
/// authorization policies from permission strings (e.g. <c>messages:retry</c>).
/// <para>
/// When the MVC pipeline evaluates <c>[Authorize(Policy = "messages:retry")]</c>, this provider
/// generates a policy containing a <see cref="PermissionRequirement"/> for that permission.
/// The <see cref="FailedMessageAuthorizationHandler"/> (for resource-scope checks) handles
/// the same requirement — but with a resource object — when called explicitly via
/// <see cref="IAuthorizationService.AuthorizeAsync"/> in the controller.
/// </para>
/// <para>
/// Policy names that are not permission strings (e.g., names registered via
/// <see cref="AuthorizationOptions"/>) return <see langword="null"/> so the framework
/// falls back to its default policy resolution.
/// </para>
/// </summary>
public sealed class PermissionPolicyProvider(IOptions<AuthorizationOptions> authorizationOptions)
    : IAuthorizationPolicyProvider
{
    // The verb-level handler that uses IPermissionEvaluator.HasPermission.
    // Registered as a singleton alongside the resource-based handler.
    //
    // Note: this policy uses the PermissionRequirement, but the
    // PermissionVerbHandler (not FailedMessageAuthorizationHandler) handles it
    // at the verb level (no resource is in scope at this point).
    //
    // A permission string is "resource:action" — it contains a colon.
    // Standard policy names (like "AuthenticatedUser") don't contain a colon.
    static bool IsPermission(string policyName) =>
        policyName.Contains(':');

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (!IsPermission(policyName))
        {
            return Task.FromResult<AuthorizationPolicy?>(null);
        }

        // Build a policy dynamically: it contains one PermissionRequirement for this permission.
        // The verb-level PermissionVerbHandler evaluates HasPermission() for this requirement
        // when no resource is present (i.e., at the [Authorize] attribute level).
        var policy = new AuthorizationPolicyBuilder()
            .AddRequirements(new PermissionRequirement(policyName))
            .Build();

        return Task.FromResult<AuthorizationPolicy?>(policy);
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
    {
        // Delegate to the options-based default policy (RequireAuthenticatedUser).
        var defaultPolicy = authorizationOptions.Value.DefaultPolicy
            ?? new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        return Task.FromResult(defaultPolicy);
    }

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
    {
        var fallbackPolicy = authorizationOptions.Value.FallbackPolicy;
        return Task.FromResult(fallbackPolicy);
    }
}
