#nullable enable
namespace ServiceControl.MessageFailures.Api.Auth;

using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using ServiceControl.Infrastructure.Auth.Rbac;
using ServiceControl.MessageFailures;

/// <summary>
/// S3 resource-based authorization handler for <see cref="FailedMessage"/>.
/// <para>
/// Checks both the verb-level permission (<see cref="IPermissionEvaluator.HasPermission"/>) and
/// the resource scope (<see cref="IPermissionEvaluator.IsInScope"/>) against the
/// <see cref="FailedMessage"/>'s queue address.
/// </para>
/// <para>
/// Every decision — allow and deny — is logged via <see cref="IAuthorizationAuditLog"/> under
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
        var subject = context.User.FindFirst("sub")?.Value
                   ?? context.User.Identity?.Name
                   ?? "unknown";

        var queueAddress = resource.ProcessingAttempts
            .LastOrDefault()
            ?.FailureDetails
            ?.AddressOfFailingEndpoint
            ?? string.Empty;

        var permission = requirement.Permission;

        // Verb-level check: does the user hold this permission at all?
        if (!permissionEvaluator.HasPermission(context.User, permission))
        {
            auditLog.Decision(
                subject,
                permission,
                queueAddress,
                allowed: false,
                reason: $"User does not hold permission '{permission}'");

            context.Fail(new AuthorizationFailureReason(
                this,
                $"User '{subject}' does not hold permission '{permission}'"));

            return Task.CompletedTask;
        }

        // Resource-scope check: is this specific message's queue in scope?
        if (!permissionEvaluator.IsInScope(context.User, permission, queueAddress))
        {
            auditLog.Decision(
                subject,
                permission,
                queueAddress,
                allowed: false,
                reason: $"Queue address '{queueAddress}' is out of scope for permission '{permission}'");

            context.Fail(new AuthorizationFailureReason(
                this,
                $"User '{subject}' cannot '{permission}' on queue '{queueAddress}' — out of scope"));

            return Task.CompletedTask;
        }

        auditLog.Decision(
            subject,
            permission,
            queueAddress,
            allowed: true,
            reason: $"User holds '{permission}' and queue '{queueAddress}' is in scope");

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
