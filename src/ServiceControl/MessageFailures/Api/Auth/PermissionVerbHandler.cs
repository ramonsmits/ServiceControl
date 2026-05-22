#nullable enable
namespace ServiceControl.MessageFailures.Api.Auth;

using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// S3 verb-level authorization handler for <see cref="PermissionRequirement"/>.
/// <para>
/// This handler fires when ASP.NET Core evaluates an <c>[Authorize(Policy = "permission")]</c>
/// attribute — i.e., before the controller action runs and before any resource is loaded.
/// It answers the coarse question: "does this user hold the permission at all?"
/// </para>
/// <para>
/// The fine-grained resource-scope check (which specific record?) is performed by
/// <see cref="FailedMessageAuthorizationHandler"/> after the record is loaded.
/// </para>
/// </summary>
public sealed class PermissionVerbHandler(
    IPermissionEvaluator permissionEvaluator,
    IAuthorizationAuditLog auditLog)
    : AuthorizationHandler<PermissionRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        // When a typed resource is present, the resource-based handler (e.g.,
        // FailedMessageAuthorizationHandler) owns the decision — including the verb check.
        // Skip here to avoid double logging and double evaluation.
        if (context.Resource != null)
        {
            return Task.CompletedTask;
        }

        var subject = context.User.FindFirst("sub")?.Value
                   ?? context.User.Identity?.Name
                   ?? "unknown";
        var permission = requirement.Permission;

        if (permissionEvaluator.HasPermission(context.User, permission))
        {
            auditLog.Decision(
                subject,
                permission,
                resource: null,
                allowed: true,
                reason: $"Verb-level check: user holds '{permission}'");

            context.Succeed(requirement);
        }
        else
        {
            auditLog.Decision(
                subject,
                permission,
                resource: null,
                allowed: false,
                reason: $"Verb-level check: user does not hold '{permission}'");

            context.Fail(new AuthorizationFailureReason(
                this,
                $"User '{subject}' does not hold permission '{permission}'"));
        }

        return Task.CompletedTask;
    }
}
