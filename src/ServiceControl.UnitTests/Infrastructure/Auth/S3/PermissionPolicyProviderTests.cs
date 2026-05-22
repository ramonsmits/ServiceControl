#nullable enable
namespace ServiceControl.UnitTests.Infrastructure.Auth.S3;

using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using ServiceControl.Infrastructure.WebApi.Auth;

/// <summary>
/// Tests the dynamic policy provider that generates verb-level policies from permission strings.
/// When OIDC is enabled: generates a real PermissionRequirement policy for known permissions.
/// When OIDC is disabled: generates a permissive allow-all policy for known permissions.
/// Unknown policy names return null in both modes.
/// </summary>
[TestFixture]
public class PermissionPolicyProviderTests
{
    static PermissionPolicyProvider BuildProvider(bool oidcEnabled = true)
    {
        var authOptions = new AuthorizationOptions();
        return new PermissionPolicyProvider(Options.Create(authOptions), oidcEnabled);
    }

    [Test]
    public async Task Provider_returns_non_null_policy_for_known_permission_when_oidc_enabled()
    {
        var provider = BuildProvider(oidcEnabled: true);
        var policy = await provider.GetPolicyAsync("messages:retry");
        Assert.That(policy, Is.Not.Null, "Provider must return a policy for a known permission string");
    }

    [Test]
    public async Task Provider_policy_contains_PermissionRequirement_when_oidc_enabled()
    {
        var provider = BuildProvider(oidcEnabled: true);
        var policy = await provider.GetPolicyAsync("messages:retry");
        Assert.That(policy, Is.Not.Null);
        Assert.That(policy!.Requirements, Has.Some.InstanceOf<PermissionRequirement>(),
            "Policy should contain a PermissionRequirement when OIDC is enabled");
        var permReq = (PermissionRequirement)policy.Requirements.First(r => r is PermissionRequirement);
        Assert.That(permReq.Permission, Is.EqualTo("messages:retry"));
    }

    [Test]
    public async Task Provider_returns_allow_all_policy_for_known_permission_when_oidc_disabled()
    {
        var provider = BuildProvider(oidcEnabled: false);
        var policy = await provider.GetPolicyAsync("messages:retry");
        Assert.That(policy, Is.Not.Null, "Provider must return an allow-all policy when OIDC is disabled");
        // Allow-all: RequireAssertion(_ => true) — no DenyAnonymous requirement
        Assert.That(policy!.Requirements, Has.None.InstanceOf<PermissionRequirement>(),
            "Allow-all policy must not contain a PermissionRequirement");
    }

    [Test]
    public async Task Provider_returns_null_for_non_permission_policy_name()
    {
        var provider = BuildProvider();
        // Standard policy names (e.g., registered via AddAuthorization) should fall through
        // to the default provider. Returning null signals "I don't own this policy name".
        var policy = await provider.GetPolicyAsync("SomeOtherPolicy");
        Assert.That(policy, Is.Null);
    }

    [Test]
    public async Task Provider_returns_null_for_unknown_colon_name()
    {
        // A name that contains ':' but is not a known permission must not silently get a policy.
        var provider = BuildProvider(oidcEnabled: true);
        var policy = await provider.GetPolicyAsync("unknown:action");
        Assert.That(policy, Is.Null, "Unknown permission-shaped names must not silently generate a policy");
    }

    [Test]
    public async Task Provider_default_policy_is_authenticated_user()
    {
        var provider = BuildProvider();
        var policy = await provider.GetDefaultPolicyAsync();
        Assert.That(policy, Is.Not.Null);
        Assert.That(policy.Requirements, Has.Some.InstanceOf<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>(),
            "Default policy should require authenticated user");
    }
}
