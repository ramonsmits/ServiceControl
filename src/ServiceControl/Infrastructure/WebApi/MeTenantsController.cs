#nullable enable
namespace ServiceControl.Infrastructure.WebApi;

using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using ServiceControl.Infrastructure.Auth.Tenants;

/// <summary>
/// Exposes the calling user's authorized tenants, as supplied by the identity provider.
/// </summary>
/// <remarks>
/// Counterpoint to <see cref="MePermissionsController"/>: that descriptor returns the user's
/// permissions according to the application-owned <c>rbac.yaml</c> (PAP). This descriptor
/// returns the tenant list straight from the IdP-issued JWT — the application does not store
/// a tenant-to-user mapping. See
/// <c>research/platform-authorization/idp-managed-vs-app-managed-authz-data.md</c>
/// for the design trade-off.
/// <para>
/// When OIDC is disabled, <see cref="IUserTenantsProvider"/> is not registered and this endpoint
/// returns <c>404 Not Found</c>, preserving the non-breaking guarantee.
/// </para>
/// </remarks>
[ApiController]
[Route("api")]
[AuthenticatedOnly]
public class MeTenantsController(IServiceProvider serviceProvider) : ControllerBase
{
    /// <summary>
    /// Returns the tenants the currently authenticated user is authorized to access.
    /// </summary>
    /// <response code="200">The user's tenant set (possibly empty).</response>
    /// <response code="401">No valid bearer token was provided.</response>
    /// <response code="404">OIDC / authorization is disabled — this endpoint does not exist in this deployment.</response>
    [HttpGet]
    [Route("me/tenants")]
    public ActionResult<TenantsDescriptor> GetMyTenants()
    {
        var tenantsProvider = serviceProvider.GetService<IUserTenantsProvider>();
        if (tenantsProvider == null)
        {
            return NotFound();
        }

        var tenants = tenantsProvider.GetTenants(User);
        return Ok(new TenantsDescriptor(
            Source: TenantsDescriptor.IdpClaim,
            Tenants: tenants));
    }
}

/// <summary>The JSON shape returned by <c>GET /api/me/tenants</c>.</summary>
public sealed record TenantsDescriptor(string Source, IReadOnlyList<string> Tenants)
{
    /// <summary>The tenant list was read directly from a JWT claim issued by the IdP.</summary>
    public const string IdpClaim = "idp-claim";
}
