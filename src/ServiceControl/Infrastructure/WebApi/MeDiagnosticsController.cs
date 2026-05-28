#nullable enable
namespace ServiceControl.Infrastructure.WebApi;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// Exposes a diagnostic snapshot of the calling user's identity, raw claims, and per-permission state.
/// Intended for troubleshooting authentication and authorization configuration: the caller can see
/// exactly which claims arrived from the IdP (Identity Provider), which ones were produced by
/// <see cref="ServiceControl.Hosting.Auth.RealmAccessClaimsTransformation"/>, and the resulting
/// permission evaluation against the loaded RBAC (Role-Based Access Control) policy.
/// <para>
/// When OIDC is disabled, <see cref="IPermissionEvaluator"/> is not registered in DI and this
/// endpoint returns <c>404 Not Found</c>, preserving the non-breaking guarantee (spec §4).
/// </para>
/// </summary>
[ApiController]
[Route("api")]
[AuthenticatedOnly]
public class MeDiagnosticsController(IServiceProvider serviceProvider) : ControllerBase
{
    /// <summary>
    /// Returns a diagnostic snapshot for the currently authenticated user.
    /// </summary>
    /// <response code="200">The user's identity, claims, and per-permission state.</response>
    /// <response code="401">No valid bearer token was provided.</response>
    /// <response code="404">OIDC / authorization is disabled — this endpoint does not exist in this deployment.</response>
    [HttpGet]
    [Route("me/diagnostics")]
    public ActionResult<DiagnosticsDescriptor> GetMyDiagnostics()
    {
        // Resolve optionally: IPermissionEvaluator is only registered when OIDC is enabled.
        // Return 404 when auth is disabled so the endpoint is effectively absent (spec §4).
        var permissionEvaluator = serviceProvider.GetService<IPermissionEvaluator>();
        var policyFactory = serviceProvider.GetService<Func<RbacPolicy>>();

        if (permissionEvaluator == null || policyFactory == null)
        {
            return NotFound();
        }

        var policy = policyFactory();
        var effective = permissionEvaluator.Resolve(User);

        var identity = BuildIdentityDescriptor(User);
        var claims = BuildClaimDescriptors(User);
        var permissions = BuildPermissionDescriptors(effective);
        var policyInfo = new PolicyDescriptor(policy.LoadedAt);

        return Ok(new DiagnosticsDescriptor(identity, claims, permissions, policyInfo));
    }

    static IdentityDescriptor BuildIdentityDescriptor(ClaimsPrincipal user)
    {
        var claimsIdentity = user.Identity as ClaimsIdentity;

        var subject = user.FindFirst("sub")?.Value
            ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? user.Identity?.Name
            ?? "unknown";

        var name = user.FindFirst("preferred_username")?.Value
            ?? user.FindFirst(ClaimTypes.Name)?.Value
            ?? user.Identity?.Name
            ?? "unknown";

        return new IdentityDescriptor(
            Subject: subject,
            Name: name,
            IsAuthenticated: user.Identity?.IsAuthenticated ?? false,
            AuthenticationType: claimsIdentity?.AuthenticationType ?? string.Empty);
    }

    static IReadOnlyList<ClaimDescriptor> BuildClaimDescriptors(ClaimsPrincipal user)
    {
        // Flatten all claims across all identities so the caller can see every claim,
        // including those added by RealmAccessClaimsTransformation.
        return user.Claims
            .Select(c => new ClaimDescriptor(c.Type, c.Value, c.Issuer))
            .ToList();
    }

    static IReadOnlyList<PermissionDiagnosticEntry> BuildPermissionDescriptors(EffectivePermissions effective)
    {
        // Check for a wildcard grant: if any grant has permission "*", the user is effectively an admin.
        var hasWildcard = effective.Grants.Any(g => g.Permission == "*");

        var result = new List<PermissionDiagnosticEntry>();

        foreach (var permission in Permissions.All.Where(p => p != "*").OrderBy(p => p, StringComparer.Ordinal))
        {
            PermissionDiagnosticEntry entry;

            if (hasWildcard)
            {
                // Wildcard grant means every permission is unrestricted.
                entry = new PermissionDiagnosticEntry(permission, PermissionStatus.Allowed, Scope: null);
            }
            else
            {
                var grantsForPermission = effective.Grants
                    .Where(g => g.Permission == permission)
                    .ToList();

                if (grantsForPermission.Count == 0)
                {
                    entry = new PermissionDiagnosticEntry(permission, PermissionStatus.NotGranted, Scope: null);
                }
                else if (grantsForPermission.Any(g => g.Scope == null))
                {
                    // At least one unrestricted grant → allowed with no scope constraint.
                    entry = new PermissionDiagnosticEntry(permission, PermissionStatus.Allowed, Scope: null);
                }
                else
                {
                    // All grants are scoped — union the allow and deny patterns across grants for display.
                    var unionAllow = grantsForPermission
                        .SelectMany(g => g.Scope!.Allow)
                        .Distinct(StringComparer.Ordinal)
                        .OrderBy(p => p, StringComparer.Ordinal)
                        .ToList();

                    var unionDeny = grantsForPermission
                        .SelectMany(g => g.Scope!.Deny)
                        .Distinct(StringComparer.Ordinal)
                        .OrderBy(p => p, StringComparer.Ordinal)
                        .ToList();

                    entry = new PermissionDiagnosticEntry(
                        permission,
                        PermissionStatus.Scoped,
                        Scope: new DiagnosticScopeDescriptor(unionAllow, unionDeny));
                }
            }

            result.Add(entry);
        }

        return result;
    }
}

/// <summary>The JSON shape returned by <c>GET /api/me/diagnostics</c>.</summary>
public sealed record DiagnosticsDescriptor(
    IdentityDescriptor Identity,
    IReadOnlyList<ClaimDescriptor> Claims,
    IReadOnlyList<PermissionDiagnosticEntry> Permissions,
    PolicyDescriptor Policy);

/// <summary>Identity summary derived from the authenticated principal.</summary>
public sealed record IdentityDescriptor(
    string Subject,
    string Name,
    bool IsAuthenticated,
    string AuthenticationType);

/// <summary>A single claim from the principal, including its issuer.</summary>
public sealed record ClaimDescriptor(string Type, string Value, string Issuer);

/// <summary>A permission from the catalogue with its evaluated status.</summary>
public sealed record PermissionDiagnosticEntry(
    string Permission,
    PermissionStatus Status,
    DiagnosticScopeDescriptor? Scope);

/// <summary>The union of scope patterns across all grants for a scoped permission.</summary>
public sealed record DiagnosticScopeDescriptor(
    IReadOnlyList<string> Allow,
    IReadOnlyList<string> Deny);

/// <summary>Whether the permission is granted, scoped, or absent.</summary>
public enum PermissionStatus
{
    /// <summary>The user has an unrestricted (unscoped) grant for this permission.</summary>
    Allowed,
    /// <summary>The user has at least one scoped grant but no unrestricted grant.</summary>
    Scoped,
    /// <summary>The user has no grant for this permission.</summary>
    NotGranted
}

/// <summary>Metadata about the loaded RBAC policy.</summary>
public sealed record PolicyDescriptor(DateTimeOffset LoadedAt);
