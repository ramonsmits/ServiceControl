#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// S2-specific contract for inline resource-scope checking.
/// <para>
/// In S2 the controller calls <see cref="EnforceAsync"/> after loading the resource,
/// passing a typed <see cref="Resource"/> (e.g. <see cref="QueueResource"/>). The checker
/// handles deny (writes the structured-403 body and returns a non-null result to
/// short-circuit) and allow (logs and returns null).
/// </para>
/// </summary>
public interface IResourceScopeChecker
{
    /// <summary>
    /// Checks whether <paramref name="user"/> is permitted to perform <paramref name="permission"/>
    /// on the given <paramref name="resource"/>.
    /// </summary>
    /// <param name="user">The authenticated user principal.</param>
    /// <param name="permission">The permission being enforced (e.g. <c>messages:retry</c>).</param>
    /// <param name="resource">
    /// The typed resource. When <see langword="null"/> the check fails closed (deny).
    /// </param>
    /// <param name="context">The HTTP context, used to write the structured 403 body on deny.</param>
    /// <returns>
    /// <see langword="null"/> when access is allowed; a non-null <see cref="IActionResult"/>
    /// when access is denied (the 403 body has already been written to <paramref name="context"/>).
    /// </returns>
    Task<IActionResult?> EnforceAsync(
        ClaimsPrincipal user,
        string permission,
        Resource? resource,
        HttpContext context);
}

/// <summary>
/// Default implementation of <see cref="IResourceScopeChecker"/>.
/// </summary>
public sealed class ResourceScopeChecker(
    IPermissionEvaluator permissionEvaluator,
    IAuthorizationAuditLog auditLog) : IResourceScopeChecker
{
    public async Task<IActionResult?> EnforceAsync(
        ClaimsPrincipal user,
        string permission,
        Resource? resource,
        HttpContext context)
    {
        var subjectId = AuthorizationHelpers.RequireSubjectId(user);
        var subjectName = AuthorizationHelpers.RequireSubjectName(user);

        // Fail closed: a resource with no resolvable queue address cannot be scope-checked.
        if (resource == null)
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permission,
                resource: null,
                allowed: false,
                reason: $"Resource-scope check: resource has no resolvable queue address — denying '{permission}' fail-closed");

            await AuthorizationHelpers.WriteScopeDenied403(context.Response, permission, queueAddress: null);
            return new EmptyResult();
        }

        // Resource-scope check: is this resource's queue address in scope for the user?
        if (!permissionEvaluator.IsInScope(user, permission, resource))
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permission,
                resource: resource.Name,
                allowed: false,
                reason: $"Resource-scope check: queue '{resource.Name}' is out of scope for permission '{permission}'");

            await AuthorizationHelpers.WriteScopeDenied403(context.Response, permission, resource.Name);
            return new EmptyResult();
        }

        auditLog.Decision(
            subjectId,
            subjectName,
            permission,
            resource: resource.Name,
            allowed: true,
            reason: $"Resource-scope check: user holds '{permission}' and queue '{resource.Name}' is in scope");

        return null; // Access allowed — controller proceeds.
    }
}
