#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using ServiceControl.Infrastructure.Auth.Rbac;
using ServiceControl.Recoverability;

/// <summary>
/// S3 resource-based authorization handler for <see cref="FailureGroupView"/>.
/// <para>
/// Failure groups aggregate messages across multiple queues (e.g. by exception type or endpoint),
/// so they cannot be scope-checked against a single queue address the same way a
/// <see cref="Microsoft.ServiceControl.MessageFailures.FailedMessage"/> can.
/// </para>
/// <para>
/// This handler grants access when the user holds an unrestricted (un-scoped) grant for the
/// permission. If the user's only grants for this permission are scope-restricted, the handler
/// denies access fail-closed: a user who may only view Sales.* messages should not be able to
/// operate on a group that may include messages from queues outside their scope.
/// </para>
/// <para>
/// The verb-level permission check (<see cref="IPermissionEvaluator.HasPermission"/>) is
/// already performed by <see cref="PermissionVerbHandler"/> before the action runs.
/// This handler performs only the resource-scope decision and logs it.
/// </para>
/// </summary>
public sealed class FailureGroupAuthorizationHandler(
    IPermissionEvaluator permissionEvaluator,
    IAuthorizationAuditLog auditLog)
    : AuthorizationHandler<PermissionRequirement, FailureGroupView>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement,
        FailureGroupView resource)
    {
        var subject = AuthorizationHelpers.GetSubject(context.User);
        var permission = requirement.Permission;
        var groupId = resource.Id ?? "(unknown-group)";

        // Resolve the user's effective permissions to determine whether any grant
        // for this permission is unrestricted (null scope or unrestricted scope).
        var effective = permissionEvaluator.Resolve(context.User);

        var hasUnrestrictedGrant = effective.Grants
            .Any(g =>
                // Wildcard permission satisfies everything
                (g.Permission == "*" || g.Permission == permission)
                // No scope restriction → unrestricted
                && g.Scope == null);

        if (hasUnrestrictedGrant)
        {
            auditLog.Decision(
                subject,
                permission,
                resource: groupId,
                allowed: true,
                reason: $"Resource-scope check: user holds unrestricted '{permission}' — allowing group '{groupId}'");

            context.Succeed(requirement);
        }
        else
        {
            // Only scoped grants are held: fail-closed because we cannot map the group
            // to a single queue to validate whether it is within the user's scope.
            auditLog.Decision(
                subject,
                permission,
                resource: groupId,
                allowed: false,
                reason: $"Resource-scope check: user's '{permission}' grants are scope-restricted; " +
                        $"cannot verify that all messages in group '{groupId}' are in scope — denying fail-closed");

            context.Fail(new AuthorizationFailureReason(
                this,
                $"User '{subject}' has only scope-restricted '{permission}' grants; " +
                $"group '{groupId}' cannot be scope-verified — access denied fail-closed"));
        }

        return Task.CompletedTask;
    }
}
