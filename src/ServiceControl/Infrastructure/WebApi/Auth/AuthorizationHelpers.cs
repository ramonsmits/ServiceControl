#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Shared helpers for the S4 authorization mechanism.
/// Centralises patterns that are replicated across every handler.
/// </summary>
public static class AuthorizationHelpers
{
    /// <summary>
    /// Returns the stable subject identifier from the <c>sub</c> claim.
    /// Throws <see cref="InvalidOperationException"/> if the claim is absent — this is intentional
    /// fail-fast behaviour: a JWT without a <c>sub</c> claim is malformed and should never reach
    /// the authorization layer.
    /// </summary>
    public static string RequireSubjectId(ClaimsPrincipal user) =>
        user.FindFirst("sub")?.Value
        ?? throw new InvalidOperationException("Missing 'sub' claim on principal. The JWT must carry a non-empty 'sub' claim.");

    /// <summary>
    /// Returns the human-readable display name from <see cref="System.Security.Principal.IIdentity.Name"/>
    /// (which is set to the configured <c>SubjectDisplayClaim</c> value by JwtBearer's
    /// <c>NameClaimType</c> wiring).
    /// Throws <see cref="InvalidOperationException"/> if the value is absent or empty — this confirms
    /// that the IdP is emitting the required display claim.
    /// </summary>
    public static string RequireSubjectName(ClaimsPrincipal user)
    {
        var name = user.Identity?.Name;
        return !string.IsNullOrEmpty(name)
            ? name
            : throw new InvalidOperationException("Missing display-name claim on principal. Ensure the IdP emits the claim configured as Authentication.SubjectDisplayClaim (default: preferred_username).");
    }

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
