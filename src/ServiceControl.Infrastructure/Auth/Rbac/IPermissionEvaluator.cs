#nullable enable
namespace ServiceControl.Infrastructure.Auth.Rbac;

using System.Security.Claims;

/// <summary>
/// Evaluates a user's permissions against the loaded RBAC policy.
/// </summary>
/// <remarks>
/// In XACML reference-architecture terms this is the <strong>PDP (Policy Decision Point)</strong>:
/// it consumes the rules loaded from the <strong>PAP</strong> (the <c>rbac.yaml</c> loader) plus the subject
/// attributes (claims) and the resource, and returns permit/deny — it never calls out to the database
/// or to HTTP itself. The <c>[Authorize(Policy=...)]</c> attribute and the explicit
/// <c>AuthorizeAsync(...)</c> call sites in controllers are the <strong>PEPs (Policy Enforcement Points)</strong>;
/// the claims transformation and the resource loaders that hand attributes to this evaluator are the
/// <strong>PIPs (Policy Information Points)</strong>. See
/// <c>research/platform-authorization/xacml-vocabulary.md</c> in the GeneralPlatformExperience repo for the full mapping.
/// </remarks>
public interface IPermissionEvaluator
{
    /// <summary>
    /// Returns true if the user has the specified permission (regardless of resource scope).
    /// A wildcard (<c>*</c>) grant satisfies any permission.
    /// </summary>
    bool HasPermission(ClaimsPrincipal user, string permission);

    /// <summary>
    /// Returns true if the user has the specified permission for the given resource.
    /// A grant without a scope (null Scope) is in scope for all resources.
    /// A wildcard (<c>*</c>) grant is in scope for all permissions and all resources.
    /// </summary>
    bool IsInScope(ClaimsPrincipal user, string permission, Resource resource);

    /// <summary>
    /// Returns true if the user holds at least one unrestricted (null-scope) grant for the
    /// given permission. An unrestricted grant means the user can access all resources.
    /// A wildcard (<c>*</c>) permission grant satisfies any named permission.
    /// </summary>
    bool HasUnrestrictedGrant(ClaimsPrincipal user, string permission);

    /// <summary>
    /// Resolves the full set of effective permissions for the user based on their claims
    /// and the current RBAC policy.
    /// </summary>
    EffectivePermissions Resolve(ClaimsPrincipal user);

    /// <summary>
    /// Returns the resolved queue scope for the user's grants for the given permission,
    /// or <see langword="null"/> if the user has an unrestricted grant.
    /// Used by the data layer to push scope filtering into the query before paging.
    /// </summary>
    ResourceScope? ResolveQueueScope(ClaimsPrincipal user, string permission);
}
