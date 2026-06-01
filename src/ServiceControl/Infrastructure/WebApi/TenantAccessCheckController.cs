#nullable enable
namespace ServiceControl.Infrastructure.WebApi;

using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ServiceControl.Infrastructure.WebApi.Auth;

/// <summary>
/// Sample endpoint that demonstrates IdP-claim-driven authorization.
/// </summary>
/// <remarks>
/// Returns 200 if the calling user has access to the given tenant (i.e. the tenant is in the
/// JWT's <c>tenants</c> claim, surfaced via <see cref="ServiceControl.Infrastructure.Auth.Tenants.IUserTenantsProvider"/>),
/// 403 otherwise. The decision logs to the authorization audit log under the synthetic
/// permission label <c>tenant:access</c>.
/// <para>
/// This is intentionally a thin demo endpoint — it exists so the design dimension
/// "authorization data in the IdP vs in the app" is concretely testable end-to-end. No
/// business logic depends on it.
/// </para>
/// </remarks>
[ApiController]
[Route("api")]
[AuthenticatedOnly]
public sealed class TenantAccessCheckController(IAuthorizationService authorizationService) : ControllerBase
{
    /// <summary>
    /// Confirms whether the calling user is a member of the requested tenant.
    /// </summary>
    /// <param name="tenant">Tenant identifier from the URL.</param>
    [HttpGet]
    [Route("tenants/{tenant}/access-check")]
    public async Task<IActionResult> CheckAccess(string tenant)
    {
        var result = await authorizationService.AuthorizeAsync(User, tenant, new TenantAccessRequirement());

        if (!result.Succeeded)
        {
            return Forbid();
        }

        return Ok(new { tenant, granted = true });
    }
}
