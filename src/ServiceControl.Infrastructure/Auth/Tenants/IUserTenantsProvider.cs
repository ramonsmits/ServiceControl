#nullable enable
namespace ServiceControl.Infrastructure.Auth.Tenants;

using System.Collections.Generic;
using System.Security.Claims;

/// <summary>
/// Returns the set of tenants the authenticated user is authorized to access.
/// </summary>
/// <remarks>
/// This is a deliberate counterpoint to <see cref="Rbac.IPermissionEvaluator"/>:
/// the RBAC evaluator answers "what can this user do?" using a policy artifact that the
/// <strong>application</strong> owns (rbac.yaml, the PAP). The tenants provider answers "which
/// tenants does this user belong to?" using a claim the <strong>identity provider</strong> emits
/// on every token. The trade-off is a design choice — see
/// <c>research/platform-authorization/idp-managed-vs-app-managed-authz-data.md</c>
/// in the GeneralPlatformExperience repo for when each is appropriate.
/// </remarks>
public interface IUserTenantsProvider
{
    /// <summary>
    /// Returns the user's authorized tenants. Empty if the user has no tenant claim.
    /// </summary>
    IReadOnlyList<string> GetTenants(ClaimsPrincipal user);

    /// <summary>
    /// Returns true if the user is authorized to access the given tenant.
    /// </summary>
    bool HasAccess(ClaimsPrincipal user, string tenant);
}
