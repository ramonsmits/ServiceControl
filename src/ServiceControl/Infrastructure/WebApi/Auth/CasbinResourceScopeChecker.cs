#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Casbin;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// S4 resource-scope checker. Performs the post-load resource authorization check
/// using the Casbin enforcer.
///
/// <para>
/// This is the S4 equivalent of S3's <c>FailedMessageAuthorizationHandler</c>. Rather than
/// implementing <see cref="Microsoft.AspNetCore.Authorization.IAuthorizationHandler"/>, it
/// exposes a direct <see cref="EnforceAsync"/> method that controllers call after loading
/// the resource. This avoids the need for a resource-type-specific handler per domain type.
/// </para>
///
/// <para>
/// <b>Subject mapping:</b> Casbin policy subjects are <c>role:X</c> strings matching the
/// compiled p-lines from <c>rbac.yaml</c>. The check calls <c>Enforce("role:X", perm, res)</c>
/// for each of the user's <c>role</c> claims — access is granted if ANY role allows it
/// and NO role denies it (the deny-override model).
/// </para>
///
/// <para>
/// <b>Fail-closed:</b> a null resource is denied. A message with no resolvable
/// queue address cannot be scope-checked, so it is safest to deny.
/// </para>
/// </summary>
public interface ICasbinResourceScopeChecker
{
    /// <summary>
    /// Enforces the resource-scope check for the current request.
    /// </summary>
    /// <param name="user">The current user.</param>
    /// <param name="permission">The permission being enforced (e.g. <c>messages:retry</c>).</param>
    /// <param name="resource">The typed resource being acted on. Null triggers fail-closed (deny).</param>
    /// <param name="httpContext">The current HTTP context (used to write the 403 body).</param>
    /// <returns>
    /// <see langword="null"/> if access is allowed; an <see cref="IActionResult"/> (HTTP 403)
    /// that the controller should return if access is denied.
    /// </returns>
    Task<IActionResult?> EnforceAsync(
        ClaimsPrincipal user,
        string permission,
        Resource? resource,
        HttpContext httpContext);
}

/// <summary>
/// Casbin-backed implementation of <see cref="ICasbinResourceScopeChecker"/>.
/// </summary>
public sealed class CasbinResourceScopeChecker(
    IEnforcer enforcer,
    IAuthorizationAuditLog auditLog)
    : ICasbinResourceScopeChecker
{
    public async Task<IActionResult?> EnforceAsync(
        ClaimsPrincipal user,
        string permission,
        Resource? resource,
        HttpContext httpContext)
    {
        var subjectId = AuthorizationHelpers.RequireSubjectId(user);
        var subjectName = AuthorizationHelpers.RequireSubjectName(user);

        // Fail closed: no resolvable queue address means we cannot scope-check.
        if (resource == null)
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permission,
                resource: null,
                allowed: false,
                reason: $"S4 resource-scope check (Casbin): failed message has no resolvable queue address — denying '{permission}' fail-closed");

            await AuthorizationHelpers.WriteScopeDenied403(httpContext.Response, permission, queueAddress: null);
            return new EmptyResult();
        }

        // Casbin enforcer still operates on the string name — do not change the wire format.
        var queueAddress = resource.Name;

        // Ask Casbin: does ANY of the user's roles allow this permission for this specific queue?
        // Casbin's deny-override model handles cases where one role allows and another denies.
        var casbinSubjects = CasbinPermissionVerbHandler.GetCasbinSubjects(user).ToList();
        var allowed = casbinSubjects.Any(casbinSub =>
            enforcer.Enforce(casbinSub, permission, queueAddress));

        if (allowed)
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permission,
                resource: queueAddress,
                allowed: true,
                reason: $"S4 resource-scope check (Casbin): user holds '{permission}' and queue '{queueAddress}' is in scope");

            return null; // allowed
        }
        else
        {
            auditLog.Decision(
                subjectId,
                subjectName,
                permission,
                resource: queueAddress,
                allowed: false,
                reason: $"S4 resource-scope check (Casbin): queue '{queueAddress}' is out of scope for permission '{permission}'");

            await AuthorizationHelpers.WriteScopeDenied403(httpContext.Response, permission, queueAddress);
            return new EmptyResult();
        }
    }
}

/// <summary>
/// Allow-all surrogate registered when OIDC is disabled.
/// Preserves the pre-RBAC behaviour: all resource-scope checks pass unconditionally.
/// </summary>
public sealed class AllowAllScopeChecker : ICasbinResourceScopeChecker
{
    public Task<IActionResult?> EnforceAsync(
        ClaimsPrincipal user,
        string permission,
        Resource? resource,
        HttpContext httpContext)
    {
        return Task.FromResult<IActionResult?>(null); // always allow
    }
}
