#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using ServiceControl.Infrastructure.Auth.Rbac;
using ServiceControl.MessageFailures;

/// <summary>
/// S3 resource-based authorization handler for <see cref="FailedMessage"/>.
/// <para>
/// Performs <em>only</em> the resource-scope check (<see cref="IPermissionEvaluator.IsInScope"/>)
/// against the <see cref="FailedMessage"/>'s queue address.
/// The verb-level permission check (<see cref="IPermissionEvaluator.HasPermission"/>) is
/// already performed by <see cref="PermissionVerbHandler"/> when the <c>[Authorize(Policy=...)]</c>
/// attribute is evaluated — this handler must not repeat it to avoid double-logging.
/// </para>
/// <para>
/// Every scope decision — allow and deny — is logged via <see cref="IAuthorizationAuditLog"/> under
/// the <c>ServiceControl.Audit</c> logger category.
/// </para>
/// </summary>
public sealed class FailedMessageAuthorizationHandler(
    IPermissionEvaluator permissionEvaluator,
    IAuthorizationAuditLog auditLog)
    : AuthorizationHandler<PermissionRequirement, FailedMessage>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement,
        FailedMessage resource)
    {
        var subjectId = AuthorizationHelpers.RequireSubjectId(context.User);
        var subjectName = AuthorizationHelpers.RequireSubjectName(context.User);
        var permission = requirement.Permission;

        // Resolve the queue address from the most recent processing attempt.
        var queueAddress = resource.ProcessingAttempts
            .LastOrDefault()
            ?.FailureDetails
            ?.AddressOfFailingEndpoint;

        // Fail closed: a message with no resolvable queue cannot be scope-checked.
        if (string.IsNullOrEmpty(queueAddress))
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permission,
                resource: null,
                allowed: false,
                reason: $"Resource-scope check: failed message has no resolvable queue address — denying '{permission}' fail-closed");

            context.Fail(new AuthorizationFailureReason(
                this,
                $"User '{subjectId}' cannot '{permission}': message has no resolvable queue address"));

            return Task.CompletedTask;
        }

        // Resource-scope check: is this specific message's queue in scope for this user?
        if (!permissionEvaluator.IsInScope(context.User, permission, queueAddress))
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permission,
                resource: queueAddress,
                allowed: false,
                reason: $"Resource-scope check: queue '{queueAddress}' is out of scope for permission '{permission}'");

            context.Fail(new AuthorizationFailureReason(
                this,
                $"User '{subjectId}' cannot '{permission}' on queue '{queueAddress}' — out of scope"));

            return Task.CompletedTask;
        }

        auditLog.Decision(
            subjectId,
            subjectName,
            permission,
            resource: queueAddress,
            allowed: true,
            reason: $"Resource-scope check: user holds '{permission}' and queue '{queueAddress}' is in scope");

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
