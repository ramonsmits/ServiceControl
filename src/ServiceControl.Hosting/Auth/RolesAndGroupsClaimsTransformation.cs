#nullable enable
namespace ServiceControl.Hosting.Auth;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

/// <summary>
/// An <see cref="IClaimsTransformation"/> that flattens the JWT's IdP-supplied role and group
/// values into individual <c>role</c> / <c>group</c> claims so the RBAC evaluator can match them
/// uniformly regardless of the IdP shape.
/// </summary>
/// <remarks>
/// <para>
/// The claim path to read each set from is configurable via the two settings
/// <c>Authentication.RolesClaim</c> and <c>Authentication.GroupsClaim</c>. Two shapes are
/// supported per setting, distinguished by whether the configured value contains a dot:
/// </para>
/// <list type="bullet">
///   <item>
///     <strong>Dotted path</strong> (e.g. <c>realm_access.roles</c>) — top-level claim is a JSON
///     object whose property at the remaining path is an array of strings. Each array element
///     is emitted as one <c>role</c> claim. Used by <strong>Keycloak</strong> (default).
///   </item>
///   <item>
///     <strong>Flat claim name</strong> (e.g. <c>roles</c>, <c>cognito:groups</c>) — the JWT either
///     repeats the claim once per value (typical for ASP.NET Core's JWT parser when
///     <c>MapInboundClaims</c> is false) or carries it as a single JSON array. Both are unpacked
///     and each value is emitted as one <c>role</c> claim. Covers
///     <strong>Microsoft Entra ID</strong>'s <c>roles</c> and <strong>AWS Cognito</strong>'s
///     <c>cognito:groups</c>.
///   </item>
/// </list>
/// <para>
/// The transformation is idempotent — values already present as <c>role</c>/<c>group</c> claims
/// are not added again.
/// </para>
/// </remarks>
public class RolesAndGroupsClaimsTransformation(string rolesClaimPath, string groupsClaimPath) : IClaimsTransformation
{
    const string RoleClaimType = "role";
    const string GroupClaimType = "group";

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var claimsToAdd = new List<Claim>();
        Append(principal, rolesClaimPath, RoleClaimType, claimsToAdd);
        Append(principal, groupsClaimPath, GroupClaimType, claimsToAdd);

        if (claimsToAdd.Count == 0)
        {
            return Task.FromResult(principal);
        }

        var identity = new ClaimsIdentity(principal.Identity);
        identity.AddClaims(claimsToAdd);
        return Task.FromResult(new ClaimsPrincipal(identity));
    }

    static void Append(
        ClaimsPrincipal principal,
        string configuredPath,
        string canonicalClaimType,
        List<Claim> sink)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return;
        }

        var values = ExtractValues(principal, configuredPath);
        if (values.Count == 0)
        {
            return;
        }

        var existing = new HashSet<string>(
            principal.FindAll(canonicalClaimType).Select(c => c.Value),
            StringComparer.Ordinal);

        foreach (var v in values)
        {
            if (existing.Add(v))
            {
                sink.Add(new Claim(canonicalClaimType, v));
            }
        }
    }

    static List<string> ExtractValues(ClaimsPrincipal principal, string configuredPath)
    {
        var dotIdx = configuredPath.IndexOf('.', StringComparison.Ordinal);
        if (dotIdx > 0)
        {
            // Dotted path: top-level JSON-blob claim + JSON property path
            var rootClaimType = configuredPath.Substring(0, dotIdx);
            var jsonPath = configuredPath.Substring(dotIdx + 1);
            var rootClaim = principal.FindFirst(rootClaimType);
            return rootClaim is null
                ? []
                : ExtractFromJsonBlob(rootClaim.Value, jsonPath);
        }

        // Flat claim: each occurrence is one value; OR a single JSON-array string.
        return ExtractFromFlatClaim(principal, configuredPath);
    }

    static List<string> ExtractFromFlatClaim(ClaimsPrincipal principal, string claimType)
    {
        List<string> result = [];
        foreach (var claim in principal.FindAll(claimType))
        {
            // Try JSON array first (Entra/Cognito can serialize a multi-valued claim as a JSON array)
            var v = claim.Value;
            if (v.Length > 0 && v[0] == '[')
            {
                var parsed = TryParseJsonArray(v);
                if (parsed != null)
                {
                    result.AddRange(parsed);
                    continue;
                }
            }
            result.Add(v);
        }
        return result;
    }

    static List<string> ExtractFromJsonBlob(string json, string jsonPath)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var current = doc.RootElement;
            foreach (var segment in jsonPath.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(segment, out var next))
                {
                    return [];
                }
                current = next;
            }
            if (current.ValueKind != JsonValueKind.Array)
            {
                return [];
            }
            List<string> result = [];
            foreach (var el in current.EnumerateArray())
            {
                var s = el.GetString();
                if (!string.IsNullOrEmpty(s))
                {
                    result.Add(s);
                }
            }
            return result;
        }
        catch (JsonException)
        {
            return [];
        }
    }

    static List<string>? TryParseJsonArray(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return null;
            }
            List<string> result = [];
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var s = el.GetString();
                if (!string.IsNullOrEmpty(s))
                {
                    result.Add(s);
                }
            }
            return result;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
