#nullable enable
namespace ServiceControl.Infrastructure.Auth.Tenants;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

/// <summary>
/// Default <see cref="IUserTenantsProvider"/>: reads the tenant set straight off the JWT.
/// The IdP is the source of truth — the application stores no tenant-to-user mapping.
/// </summary>
/// <remarks>
/// The claim type defaults to <c>tenants</c> but is configurable via
/// <see cref="OpenIdConnectSettings.TenantsClaim"/>. Keycloak's
/// <c>oidc-usermodel-attribute-mapper</c> with <c>Multivalued = true</c> emits one claim per
/// tenant when the user attribute has multiple values; this implementation collects all claims
/// matching <see cref="claimType"/> and returns their distinct values (case-insensitive).
/// </remarks>
public sealed class ClaimBasedUserTenantsProvider(string claimType) : IUserTenantsProvider
{
    public IReadOnlyList<string> GetTenants(ClaimsPrincipal user)
    {
        if (user?.Identity?.IsAuthenticated != true)
        {
            return Array.Empty<string>();
        }

        return user.FindAll(claimType)
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public bool HasAccess(ClaimsPrincipal user, string tenant)
    {
        if (string.IsNullOrWhiteSpace(tenant))
        {
            return false;
        }

        return GetTenants(user).Contains(tenant, StringComparer.OrdinalIgnoreCase);
    }
}
