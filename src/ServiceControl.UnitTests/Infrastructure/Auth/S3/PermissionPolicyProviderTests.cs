#nullable enable
namespace ServiceControl.UnitTests.Infrastructure.Auth.S3;

using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using ServiceControl.MessageFailures.Api.Auth;

/// <summary>
/// Tests the dynamic policy provider that generates verb-level policies from permission strings.
/// The provider generates a policy for any permission string and returns null for other policy names.
/// </summary>
[TestFixture]
public class PermissionPolicyProviderTests
{
    static PermissionPolicyProvider BuildProvider()
    {
        var authOptions = new AuthorizationOptions();
        return new PermissionPolicyProvider(Options.Create(authOptions));
    }

    [Test]
    public async Task Provider_returns_non_null_policy_for_permission_string()
    {
        var provider = BuildProvider();
        var policy = await provider.GetPolicyAsync("messages:retry");
        Assert.That(policy, Is.Not.Null, "Provider must return a policy for a permission string");
    }

    [Test]
    public async Task Provider_policy_contains_PermissionRequirement()
    {
        var provider = BuildProvider();
        var policy = await provider.GetPolicyAsync("messages:retry");
        Assert.That(policy, Is.Not.Null);
        Assert.That(policy!.Requirements, Has.Some.InstanceOf<PermissionRequirement>(),
            "Policy should contain a PermissionRequirement");
        var permReq = (PermissionRequirement)policy.Requirements.First(r => r is PermissionRequirement);
        Assert.That(permReq.Permission, Is.EqualTo("messages:retry"));
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
    public async Task Provider_default_policy_is_authenticated_user()
    {
        var provider = BuildProvider();
        var policy = await provider.GetDefaultPolicyAsync();
        Assert.That(policy, Is.Not.Null);
        Assert.That(policy.Requirements, Has.Some.InstanceOf<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>(),
            "Default policy should require authenticated user");
    }
}
