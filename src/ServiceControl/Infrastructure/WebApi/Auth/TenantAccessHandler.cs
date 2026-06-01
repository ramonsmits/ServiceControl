#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using ServiceControl.Infrastructure.Auth.Rbac;
using ServiceControl.Infrastructure.Auth.Tenants;

/// <summary>
/// Authorization handler that resolves <see cref="TenantAccessRequirement"/> by consulting
/// <see cref="IUserTenantsProvider"/> — i.e. the IdP-supplied <c>tenants</c> JWT claim.
/// The resource passed to <c>AuthorizeAsync</c> must be the tenant identifier (string).
/// </summary>
/// <remarks>
/// This is a deliberate contrast to <see cref="FailedMessageAuthorizationHandler"/>: that
/// handler asks the RBAC PDP (<see cref="IPermissionEvaluator"/>) which loads its rules from
/// <c>rbac.yaml</c> (PAP). This handler asks an IdP-driven PIP — there is no PAP at all
/// for the tenant decision, because the source of truth for "which tenants does this user
/// belong to" lives in the identity provider.
/// </remarks>
public sealed class TenantAccessHandler(
    IUserTenantsProvider tenantsProvider,
    IAuthorizationAuditLog auditLog)
    : AuthorizationHandler<TenantAccessRequirement, string>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        TenantAccessRequirement requirement,
        string tenantId)
    {
        var subjectId = AuthorizationHelpers.RequireSubjectId(context.User);
        var subjectName = AuthorizationHelpers.RequireSubjectName(context.User);
        const string permissionLabel = "tenant:access";

        if (string.IsNullOrWhiteSpace(tenantId))
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permissionLabel,
                resource: null,
                allowed: false,
                reason: "Tenant-access check: empty tenant id");

            context.Fail(new AuthorizationFailureReason(this, "Tenant id is required"));
            return Task.CompletedTask;
        }

        if (!tenantsProvider.HasAccess(context.User, tenantId))
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permissionLabel,
                resource: tenantId,
                allowed: false,
                reason: $"Tenant-access check: tenant '{tenantId}' is not in the user's IdP-supplied tenants claim");

            context.Fail(new AuthorizationFailureReason(
                this,
                $"User '{subjectId}' is not a member of tenant '{tenantId}'"));

            return Task.CompletedTask;
        }

        auditLog.Decision(
            subjectId,
            subjectName,
            permissionLabel,
            resource: tenantId,
            allowed: true,
            reason: $"Tenant-access check: tenant '{tenantId}' present in user's IdP-supplied tenants claim");

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
