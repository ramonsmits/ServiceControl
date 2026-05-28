#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Casbin;
using Microsoft.AspNetCore.Authorization;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// S4 verb-level authorization handler for <see cref="PermissionRequirement"/>.
///
/// <para>
/// This handler fires when ASP.NET Core evaluates an <c>[Authorize(Policy = "permission")]</c>
/// attribute — i.e., before the controller action runs and before any resource is loaded.
/// It answers the coarse question: "does this user hold the permission for at least one resource?"
/// </para>
///
/// <para>
/// <b>Subject mapping:</b> ServiceControl does not maintain per-user Casbin entries.
/// Role membership is expressed via IdP <c>role</c> claims (already flattened by
/// <c>RealmAccessClaimsTransformation</c>). The Casbin policy uses <c>role:X</c> as the
/// policy subject; each <c>role</c> claim value is prefixed to produce a Casbin subject.
/// The verb check succeeds if <em>any</em> of the user's roles holds the permission.
/// </para>
///
/// <para>
/// The fine-grained resource-scope check (which specific queue?) is performed by
/// <see cref="CasbinResourceScopeChecker"/> after the failed message is loaded.
/// </para>
/// </summary>
public sealed class CasbinPermissionVerbHandler(
    IEnforcer enforcer,
    IAuthorizationAuditLog auditLog)
    : AuthorizationHandler<PermissionRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        // When the resource is a domain object (explicit resource-scope check), skip here.
        // The AuthorizationMiddleware sets context.Resource to the HttpContext for verb-gate
        // evaluations; explicit IAuthorizationService.AuthorizeAsync calls set it to the domain entity.
        if (context.Resource is not null and not Microsoft.AspNetCore.Http.HttpContext)
        {
            return Task.CompletedTask;
        }

        var subject = AuthorizationHelpers.GetSubject(context.User);
        var permission = requirement.Permission;

        // Get the user's Casbin subjects from their role claims.
        // role claim "sc-operator" → Casbin subject "role:sc-operator", matching the policy's p-subject.
        var casbinSubjects = GetCasbinSubjects(context.User);

        // Verb-level check: does ANY of the user's roles hold the permission for any resource?
        // Uses GetImplicitPermissionsForUser per role subject to resolve role inheritance.
        // deny-only lines are excluded here — the resource-scope check handles deny at scope time.
        var holdsPermission = casbinSubjects.Any(casbinSub =>
        {
            var implicitPerms = enforcer.GetImplicitPermissionsForUser(casbinSub);
            return implicitPerms.Any(rule => HoldsPermission(rule.ToList(), permission));
        });

        if (holdsPermission)
        {
            auditLog.Decision(
                subject,
                permission,
                resource: null,
                allowed: true,
                reason: $"S4 verb-level check (Casbin): user holds '{permission}'");

            context.Succeed(requirement);
        }
        else
        {
            auditLog.Decision(
                subject,
                permission,
                resource: null,
                allowed: false,
                reason: $"S4 verb-level check (Casbin): user does not hold '{permission}'");

            context.Fail(new AuthorizationFailureReason(
                this,
                $"User '{subject}' does not hold permission '{permission}' (Casbin)"));
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Extracts Casbin policy subjects from the user's <c>role</c> claims.
    /// Each <c>role</c> claim value <c>X</c> produces the Casbin subject <c>role:X</c>,
    /// matching the <c>p, role:X, ...</c> policy lines compiled from <c>rbac.yaml</c>.
    /// </summary>
    internal static IEnumerable<string> GetCasbinSubjects(ClaimsPrincipal user) =>
        user.FindAll("role").Select(c => $"role:{c.Value}");

    /// <summary>
    /// Returns true if the materialized policy rule grants (not denies) the specified permission.
    /// Rule layout from the Casbin p-definition: [0]=role/sub, [1]=perm, [2]=res, [3]=eft.
    /// Wildcard permission <c>*</c> in the policy satisfies any requested permission.
    /// </summary>
    static bool HoldsPermission(IReadOnlyList<string> rule, string permission)
    {
        if (rule.Count < 4)
        {
            return false;
        }

        var perm = rule[1]; // policy permission column
        var eft = rule[3];  // policy effect column

        return (perm == permission || perm == "*") && eft != "deny";
    }
}
