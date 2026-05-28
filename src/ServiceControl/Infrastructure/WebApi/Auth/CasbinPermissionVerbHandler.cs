#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Linq;
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
/// The check uses <see cref="IEnforcer.GetImplicitPermissionsForUser"/> rather than
/// <c>Enforce(sub, perm, "*")</c> because the wildcard resource test would fail for users
/// with scoped grants (e.g. Sales.* only — they hold <c>messages:retry</c> but not for <c>*</c>).
/// The implicit-permissions approach is the honest "does this user hold this permission anywhere"
/// question, without prejudicing the specific resource.
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

        // Resolve the user's implicit permissions via Casbin's role-inheritance graph.
        // Each rule is a sequence: [role, perm, res, eft] matching the p-definition columns.
        // We consider the user to hold the permission if at least one allow line exists
        // for it (deny-only lines are ignored at the verb gate — resource scope handles those).
        var implicitPerms = enforcer.GetImplicitPermissionsForUser(subject);
        var holdsPermission = implicitPerms.Any(rule => HoldsPermission(rule.ToList(), permission));

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
    /// Returns true if the materialized policy rule grants (not denies) the specified permission.
    /// Rule layout from the Casbin p-definition: [0]=role/sub, [1]=perm, [2]=res, [3]=eft.
    /// Wildcard permission <c>*</c> in the policy satisfies any requested permission.
    /// </summary>
    static bool HoldsPermission(System.Collections.Generic.IReadOnlyList<string> rule, string permission)
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
