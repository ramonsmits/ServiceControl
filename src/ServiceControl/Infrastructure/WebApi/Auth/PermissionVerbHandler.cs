#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

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
/// the domain-specific resource handler (e.g. <c>FailedMessageAuthorizationHandler</c>)
/// after the record is loaded.
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
        // When the resource is a domain object (i.e., an explicit resource-scope check via
        // IAuthorizationService.AuthorizeAsync(user, resource, requirement)), the domain-specific
        // handler owns the entire decision — skip here to avoid double-logging the verb gate.
        // The AuthorizationMiddleware sets context.Resource to the HttpContext; explicit calls
        // set it to the domain entity. We only own the verb-level (HttpContext or null) case.
        if (context.Resource is not null and not Microsoft.AspNetCore.Http.HttpContext)
        {
            return Task.CompletedTask;
        }

        // If the user is not authenticated, do not log a decision — the fallback policy
        // (RequireAuthenticatedUser) will produce the 401. Logging here would throw because
        // sub and display-name claims are absent for anonymous principals.
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return Task.CompletedTask;
        }

        var subjectId = AuthorizationHelpers.RequireSubjectId(context.User);
        var subjectName = AuthorizationHelpers.RequireSubjectName(context.User);
        var permission = requirement.Permission;

        if (permissionEvaluator.HasPermission(context.User, permission))
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permission,
                resource: null,
                allowed: true,
                reason: $"Verb-level check: user holds '{permission}'");

            context.Succeed(requirement);
        }
        else
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permission,
                resource: null,
                allowed: false,
                reason: $"Verb-level check: user does not hold '{permission}'");

            context.Fail(new AuthorizationFailureReason(
                this,
                $"User '{subjectId}' does not hold permission '{permission}'"));
        }

        return Task.CompletedTask;
    }
}
