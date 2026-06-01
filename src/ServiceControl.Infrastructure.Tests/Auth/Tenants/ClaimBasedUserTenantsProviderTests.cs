#nullable enable
namespace ServiceControl.Infrastructure.Tests.Auth.Tenants;

using System.Security.Claims;
using NUnit.Framework;
using ServiceControl.Infrastructure.Auth.Tenants;

[TestFixture]
public class ClaimBasedUserTenantsProviderTests
{
    [Test]
    public void GetTenants_returns_empty_for_unauthenticated_user()
    {
        var provider = new ClaimBasedUserTenantsProvider("tenants");
        var user = new ClaimsPrincipal(new ClaimsIdentity()); // no AuthenticationType => unauthenticated

        Assert.That(provider.GetTenants(user), Is.Empty);
    }

    [Test]
    public void GetTenants_returns_empty_when_claim_absent()
    {
        var provider = new ClaimBasedUserTenantsProvider("tenants");
        var user = AuthenticatedUserWith();

        Assert.That(provider.GetTenants(user), Is.Empty);
    }

    [Test]
    public void GetTenants_returns_distinct_values_across_multiple_claims_of_same_type()
    {
        // Keycloak's oidc-usermodel-attribute-mapper with Multivalued=true emits ONE claim per value.
        var provider = new ClaimBasedUserTenantsProvider("tenants");
        var user = AuthenticatedUserWith(
            new Claim("tenants", "acme"),
            new Claim("tenants", "globex"),
            new Claim("tenants", "ACME"));   // duplicate, case-insensitive

        Assert.That(provider.GetTenants(user), Is.EquivalentTo(new[] { "acme", "globex" }));
    }

    [Test]
    public void GetTenants_ignores_blank_values()
    {
        var provider = new ClaimBasedUserTenantsProvider("tenants");
        var user = AuthenticatedUserWith(
            new Claim("tenants", "acme"),
            new Claim("tenants", ""),
            new Claim("tenants", "   "));

        Assert.That(provider.GetTenants(user), Is.EquivalentTo(new[] { "acme" }));
    }

    [Test]
    public void GetTenants_respects_configured_claim_type()
    {
        var provider = new ClaimBasedUserTenantsProvider("custom-tenants");
        var user = AuthenticatedUserWith(
            new Claim("tenants", "wrong"),
            new Claim("custom-tenants", "right"));

        Assert.That(provider.GetTenants(user), Is.EquivalentTo(new[] { "right" }));
    }

    [TestCase("acme", true)]
    [TestCase("ACME", true)]   // case-insensitive
    [TestCase("contoso", false)]
    [TestCase("", false)]
    [TestCase("   ", false)]
    public void HasAccess_matches_case_insensitively(string requested, bool expected)
    {
        var provider = new ClaimBasedUserTenantsProvider("tenants");
        var user = AuthenticatedUserWith(new Claim("tenants", "acme"), new Claim("tenants", "globex"));

        Assert.That(provider.HasAccess(user, requested), Is.EqualTo(expected));
    }

    static ClaimsPrincipal AuthenticatedUserWith(params Claim[] claims)
    {
        var identity = new ClaimsIdentity(claims, authenticationType: "Test");
        return new ClaimsPrincipal(identity);
    }
}
