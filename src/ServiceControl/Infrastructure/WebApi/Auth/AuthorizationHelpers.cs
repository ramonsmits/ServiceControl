#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// Shared helpers for the S3 authorization mechanism.
/// Centralises patterns that are replicated across every handler.
/// </summary>
public static class AuthorizationHelpers
{
    /// <summary>
    /// Extracts a human-readable subject identifier from the principal.
    /// Prefers the <c>sub</c> claim; falls back to <see cref="System.Security.Principal.IIdentity.Name"/>; then "unknown".
    /// </summary>
    public static string GetSubject(ClaimsPrincipal user) =>
        user.FindFirst("sub")?.Value
        ?? user.Identity?.Name
        ?? "unknown";

    /// <summary>
    /// Returns true if the user holds at least one unrestricted (null-scope) grant for the given permission.
    /// A wildcard (<c>*</c>) permission satisfies any permission name.
    /// Delegates to <see cref="IPermissionEvaluator.HasUnrestrictedGrant"/> to avoid duplicating the logic.
    /// </summary>
    public static bool HasUnrestrictedGrant(IPermissionEvaluator permissionEvaluator, ClaimsPrincipal user, string permission) =>
        permissionEvaluator.HasUnrestrictedGrant(user, permission);

    /// <summary>
    /// Writes a structured JSON 403 body to the HTTP response.
    /// Use this whenever a resource-scope check denies access to a single resource,
    /// then return <c>Empty</c> from the controller action.
    /// </summary>
    /// <param name="response">The current <see cref="HttpResponse"/>.</param>
    /// <param name="permission">The permission that was evaluated.</param>
    /// <param name="queueAddress">The queue address of the resource, or <see langword="null"/> if unknown.</param>
    public static async Task WriteScopeDenied403(HttpResponse response, string permission, string? queueAddress)
    {
        response.ContentType = "application/json";
        response.StatusCode = StatusCodes.Status403Forbidden;
        await response.WriteAsJsonAsync(new
        {
            error = "forbidden",
            permission,
            resource = queueAddress,
            reason = string.IsNullOrEmpty(queueAddress)
                ? "Message has no resolvable queue address"
                : $"Queue '{queueAddress}' is out of scope for permission '{permission}'"
        });
    }
}
