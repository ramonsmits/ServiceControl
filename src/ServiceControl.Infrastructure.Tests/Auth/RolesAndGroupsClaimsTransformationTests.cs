namespace ServiceControl.Infrastructure.Tests.Auth;

using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using NUnit.Framework;
using ServiceControl.Hosting.Auth;

[TestFixture]
public class RolesAndGroupsClaimsTransformationTests
{
    // ── Keycloak shape: dotted path, nested JSON-blob claim ──────────────────────

    [Test]
    public async Task Keycloak_dotted_path_flattens_realm_access_roles()
    {
        var transformation = new RolesAndGroupsClaimsTransformation(
            rolesClaimPath: "realm_access.roles",
            groupsClaimPath: "groups");

        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("realm_access", """{"roles":["sc-admin","sc-operator"]}""", JsonClaimValueTypes.Json));
        var principal = new ClaimsPrincipal(identity);

        var result = await transformation.TransformAsync(principal);

        var roles = result.FindAll("role").Select(c => c.Value).ToArray();
        Assert.That(roles, Is.EquivalentTo(new[] { "sc-admin", "sc-operator" }));
    }

    [Test]
    public async Task Keycloak_dotted_path_with_no_matching_property_yields_no_roles()
    {
        var transformation = new RolesAndGroupsClaimsTransformation("realm_access.roles", "groups");
        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("realm_access", """{"something_else":[]}""", JsonClaimValueTypes.Json));

        var result = await transformation.TransformAsync(new ClaimsPrincipal(identity));

        Assert.That(result.FindAll("role"), Is.Empty);
    }

    // ── Entra ID shape: flat claim, repeated once per value ──────────────────────

    [Test]
    public async Task Entra_flat_claim_repeated_once_per_value_is_unpacked()
    {
        var transformation = new RolesAndGroupsClaimsTransformation(
            rolesClaimPath: "roles",
            groupsClaimPath: "groups");

        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("roles", "sc-admin"));
        identity.AddClaim(new Claim("roles", "sc-operator"));
        var principal = new ClaimsPrincipal(identity);

        var result = await transformation.TransformAsync(principal);

        var roles = result.FindAll("role").Select(c => c.Value).ToArray();
        Assert.That(roles, Is.EquivalentTo(new[] { "sc-admin", "sc-operator" }));
    }

    [Test]
    public async Task Flat_claim_with_json_array_value_is_unpacked()
    {
        var transformation = new RolesAndGroupsClaimsTransformation("roles", "groups");
        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("roles", """["sc-admin","sc-viewer"]"""));

        var result = await transformation.TransformAsync(new ClaimsPrincipal(identity));

        var roles = result.FindAll("role").Select(c => c.Value).ToArray();
        Assert.That(roles, Is.EquivalentTo(new[] { "sc-admin", "sc-viewer" }));
    }

    // ── Cognito shape: colon-bearing flat claim ──────────────────────────────────

    [Test]
    public async Task Cognito_groups_flat_claim_with_colon_in_name()
    {
        var transformation = new RolesAndGroupsClaimsTransformation(
            rolesClaimPath: "cognito:groups",
            groupsClaimPath: "cognito:groups");

        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("cognito:groups", "sc-admin"));
        identity.AddClaim(new Claim("cognito:groups", "sc-operator"));

        var result = await transformation.TransformAsync(new ClaimsPrincipal(identity));

        Assert.That(result.FindAll("role").Select(c => c.Value), Is.EquivalentTo(new[] { "sc-admin", "sc-operator" }));
        Assert.That(result.FindAll("group").Select(c => c.Value), Is.EquivalentTo(new[] { "sc-admin", "sc-operator" }));
    }

    // ── Groups path independently configurable ───────────────────────────────────

    [Test]
    public async Task Groups_path_independently_extracts_group_claims()
    {
        var transformation = new RolesAndGroupsClaimsTransformation(
            rolesClaimPath: "realm_access.roles",
            groupsClaimPath: "groups");

        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("realm_access", """{"roles":["sc-admin"]}""", JsonClaimValueTypes.Json));
        identity.AddClaim(new Claim("groups", "/Sysadmins"));
        identity.AddClaim(new Claim("groups", "/DevOps"));

        var result = await transformation.TransformAsync(new ClaimsPrincipal(identity));

        Assert.That(result.FindAll("role").Select(c => c.Value), Is.EquivalentTo(new[] { "sc-admin" }));
        Assert.That(result.FindAll("group").Select(c => c.Value), Is.EquivalentTo(new[] { "/Sysadmins", "/DevOps" }));
    }

    // ── Idempotence ──────────────────────────────────────────────────────────────

    [Test]
    public async Task Does_not_duplicate_on_repeated_transformation()
    {
        var transformation = new RolesAndGroupsClaimsTransformation("realm_access.roles", "groups");
        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("realm_access", """{"roles":["sc-admin"]}""", JsonClaimValueTypes.Json));
        var principal = new ClaimsPrincipal(identity);

        var first = await transformation.TransformAsync(principal);
        var second = await transformation.TransformAsync(first);

        Assert.That(second.FindAll("role").Select(c => c.Value), Has.Exactly(1).EqualTo("sc-admin"));
    }

    // ── Edge cases ───────────────────────────────────────────────────────────────

    [Test]
    public async Task Principal_with_no_matching_claims_is_returned_unchanged()
    {
        var transformation = new RolesAndGroupsClaimsTransformation("realm_access.roles", "groups");
        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("sub", "user123"));

        var result = await transformation.TransformAsync(new ClaimsPrincipal(identity));

        Assert.That(result.FindAll("role"), Is.Empty);
        Assert.That(result.FindAll("group"), Is.Empty);
    }

    [Test]
    public async Task Malformed_json_blob_is_treated_as_no_roles()
    {
        var transformation = new RolesAndGroupsClaimsTransformation("realm_access.roles", "groups");
        var identity = new ClaimsIdentity("Bearer");
        identity.AddClaim(new Claim("realm_access", "not-json-at-all"));

        var result = await transformation.TransformAsync(new ClaimsPrincipal(identity));

        Assert.That(result.FindAll("role"), Is.Empty);
    }
}
