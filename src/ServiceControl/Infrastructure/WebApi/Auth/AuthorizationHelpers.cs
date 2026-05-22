#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System.Security.Claims;

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
}
