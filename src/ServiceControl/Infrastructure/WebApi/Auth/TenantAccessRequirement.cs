#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using Microsoft.AspNetCore.Authorization;

/// <summary>
/// Authorization requirement: the calling user must be authorized for the tenant
/// passed as the resource to <c>IAuthorizationService.AuthorizeAsync</c>.
/// </summary>
/// <remarks>
/// In XACML terms this requirement is the *question* the PEP asks; the matching
/// <see cref="TenantAccessHandler"/> is the PDP that answers it; the
/// <see cref="ServiceControl.Infrastructure.Auth.Tenants.IUserTenantsProvider"/> is the PIP
/// that reads the IdP-supplied claim. There is intentionally no PAP (no rbac.yaml entry)
/// because the tenant→user mapping lives in the IdP, not in this application's state.
/// </remarks>
public sealed class TenantAccessRequirement : IAuthorizationRequirement
{
}
