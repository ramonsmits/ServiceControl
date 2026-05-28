#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

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
/// <b>Fail-closed:</b> a null or empty queue address is denied. A message with no resolvable
/// queue address cannot be scope-checked, so it is safest to deny.
/// </para>
///
/// <para>
/// <b>OIDC disabled:</b> this class is not registered when OIDC is off. Controllers must guard
/// with a null-check or use the injected <see cref="IAllowAllScopeChecker"/> surrogate.
/// In practice the DI container returns an <see cref="AllowAllScopeChecker"/> when OIDC is off.
/// </para>
/// </summary>
public interface ICasbinResourceScopeChecker
{
    /// <summary>
    /// Enforces the resource-scope check for the current request.
    /// </summary>
    /// <param name="user">The current user.</param>
    /// <param name="permission">The permission being enforced (e.g. <c>messages:retry</c>).</param>
    /// <param name="queueAddress">The concrete queue address of the resource being acted on.</param>
    /// <param name="httpContext">The current HTTP context (used to write the 403 body).</param>
    /// <returns>
    /// <see langword="null"/> if access is allowed; an <see cref="IActionResult"/> (HTTP 403)
    /// that the controller should return if access is denied.
    /// </returns>
    Task<IActionResult?> EnforceAsync(
        System.Security.Claims.ClaimsPrincipal user,
        string permission,
        string? queueAddress,
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
        System.Security.Claims.ClaimsPrincipal user,
        string permission,
        string? queueAddress,
        HttpContext httpContext)
    {
        var subject = AuthorizationHelpers.GetSubject(user);

        // Fail closed: no resolvable queue address means we cannot scope-check.
        if (string.IsNullOrEmpty(queueAddress))
        {
            auditLog.Decision(
                subject,
                permission,
                resource: null,
                allowed: false,
                reason: $"S4 resource-scope check (Casbin): failed message has no resolvable queue address — denying '{permission}' fail-closed");

            await AuthorizationHelpers.WriteScopeDenied403(httpContext.Response, permission, queueAddress: null);
            return new EmptyResult();
        }

        // Ask Casbin: does this user hold the permission for this specific queue?
        var allowed = await enforcer.EnforceAsync(subject, permission, queueAddress);

        if (allowed)
        {
            auditLog.Decision(
                subject,
                permission,
                resource: queueAddress,
                allowed: true,
                reason: $"S4 resource-scope check (Casbin): user holds '{permission}' and queue '{queueAddress}' is in scope");

            return null; // allowed
        }
        else
        {
            auditLog.Decision(
                subject,
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
        System.Security.Claims.ClaimsPrincipal user,
        string permission,
        string? queueAddress,
        HttpContext httpContext)
    {
        return Task.FromResult<IActionResult?>(null); // always allow
    }
}
