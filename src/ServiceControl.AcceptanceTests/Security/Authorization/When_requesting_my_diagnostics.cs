namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Text.Json;
    using System.Threading.Tasks;
    using AcceptanceTesting;
    using AcceptanceTesting.OpenIdConnect;
    using NServiceBus.AcceptanceTesting;
    using NUnit.Framework;
    using ServiceControl.Infrastructure.Auth.Rbac;

    /// <summary>
    /// Acceptance tests for the <c>GET /api/me/diagnostics</c> endpoint.
    /// The endpoint exposes the calling user's IdP (Identity Provider) identity, all post-transformation
    /// claims, and per-permission state against the loaded RBAC (Role-Based Access Control) policy.
    /// </summary>
    class When_requesting_my_diagnostics : AcceptanceTest
    {
        OpenIdConnectTestConfiguration configuration;
        MockOidcServer mockOidcServer;

        const string TestAudience = "api://test-audience";
        const string TestClientId = "test-client-id";
        const string TestApiScopes = "api://test-audience/.default";

        [SetUp]
        public void ConfigureAuth()
        {
            mockOidcServer = new MockOidcServer(audience: TestAudience);
            mockOidcServer.Start();

            configuration = new OpenIdConnectTestConfiguration(ServiceControlInstanceType.Primary)
                .WithConfigurationValidationDisabled()
                .WithAuthenticationEnabled()
                .WithAuthority(mockOidcServer.Authority)
                .WithAudience(TestAudience)
                .WithServicePulseClientId(TestClientId)
                .WithServicePulseApiScopes(TestApiScopes)
                .WithRequireHttpsMetadata(false);
        }

        [TearDown]
        public void CleanupAuth()
        {
            configuration?.Dispose();
            mockOidcServer?.Dispose();
        }

        [Test]
        public async Task Operator_receives_200_with_full_identity_claims_and_permission_catalogue()
        {
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    // Issue a token with realm_access.roles = ["sc-operator"] and a known subject.
                    var token = mockOidcServer.GenerateTokenWithRealmRoles(
                        subject: "alice-abc",
                        realmRoles: ["sc-operator"]);

                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient,
                        HttpMethod.Get,
                        "/api/me/diagnostics",
                        token);

                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "Authenticated sc-operator should receive 200");

            var body = await response.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            // ── identity ────────────────────────────────────────────────────────────
            Assert.That(root.TryGetProperty("identity", out var identityProp), Is.True,
                "Response must contain 'identity' object");

            Assert.That(identityProp.TryGetProperty("subject", out var subjectProp), Is.True,
                "identity must contain 'subject'");
            Assert.That(subjectProp.GetString(), Is.EqualTo("alice-abc"),
                "identity.subject must equal the token's sub claim");

            Assert.That(identityProp.TryGetProperty("is_authenticated", out var isAuthProp), Is.True,
                "identity must contain 'is_authenticated'");
            Assert.That(isAuthProp.GetBoolean(), Is.True);

            Assert.That(identityProp.TryGetProperty("authentication_type", out _), Is.True,
                "identity must contain 'authentication_type'");

            // ── claims ──────────────────────────────────────────────────────────────
            Assert.That(root.TryGetProperty("claims", out var claimsProp), Is.True,
                "Response must contain 'claims' array");
            Assert.That(claimsProp.ValueKind, Is.EqualTo(JsonValueKind.Array));

            var claimsArray = claimsProp.EnumerateArray().ToArray();

            // The original realm_access JSON claim must be present (raw form from IdP).
            var hasRealmAccessClaim = claimsArray.Any(c =>
                c.TryGetProperty("type", out var t) && t.GetString() == "realm_access");
            Assert.That(hasRealmAccessClaim, Is.True,
                "Claims must include the raw 'realm_access' claim from the IdP");

            // The flattened 'role' claim with value 'sc-operator' must be present
            // (produced by RealmAccessClaimsTransformation — the key diagnostic value).
            var hasRoleClaim = claimsArray.Any(c =>
                c.TryGetProperty("type", out var t) && t.GetString() == "role" &&
                c.TryGetProperty("value", out var v) && v.GetString() == "sc-operator");
            Assert.That(hasRoleClaim, Is.True,
                "Claims must include a flattened 'role' claim with value 'sc-operator' (added by RealmAccessClaimsTransformation)");

            // Each claim entry must carry an 'issuer' field.
            Assert.That(claimsArray.All(c => c.TryGetProperty("issuer", out _)), Is.True,
                "Every claim entry must include an 'issuer' field");

            // ── permissions ─────────────────────────────────────────────────────────
            Assert.That(root.TryGetProperty("permissions", out var permsProp), Is.True,
                "Response must contain 'permissions' array");
            Assert.That(permsProp.ValueKind, Is.EqualTo(JsonValueKind.Array));

            var permsArray = permsProp.EnumerateArray().ToArray();

            // Every catalogue constant except "*" must appear.
            var catalogue = Permissions.All.Where(p => p != "*").ToHashSet();
            var returnedPerms = permsArray
                .Where(p => p.TryGetProperty("permission", out _))
                .Select(p => p.GetProperty("permission").GetString()!)
                .ToHashSet();
            Assert.That(returnedPerms, Is.SupersetOf(catalogue),
                "permissions[] must contain an entry for every catalogue permission");

            // messages:retry must be 'allowed' for sc-operator (per rbac.yaml).
            var retryEntry = permsArray.FirstOrDefault(p =>
                p.TryGetProperty("permission", out var pn) && pn.GetString() == "messages:retry");
            Assert.That(retryEntry.ValueKind, Is.Not.EqualTo(JsonValueKind.Undefined),
                "permissions[] must include messages:retry");
            Assert.That(retryEntry.GetProperty("status").GetString(), Is.EqualTo("allowed"),
                "messages:retry must be 'allowed' for sc-operator");

            // licensing:manage is NOT in sc-operator's grants → must be 'notGranted'.
            // The enum serializer uses JsonNamingPolicy.CamelCase, so NotGranted → "notGranted".
            var licenseEntry = permsArray.FirstOrDefault(p =>
                p.TryGetProperty("permission", out var pn) && pn.GetString() == "licensing:manage");
            Assert.That(licenseEntry.ValueKind, Is.Not.EqualTo(JsonValueKind.Undefined),
                "permissions[] must include licensing:manage");
            Assert.That(licenseEntry.GetProperty("status").GetString(), Is.EqualTo("notGranted"),
                "licensing:manage must be 'notGranted' for sc-operator (enum uses camelCase: notGranted)");

            // ── policy ──────────────────────────────────────────────────────────────
            Assert.That(root.TryGetProperty("policy", out var policyProp), Is.True,
                "Response must contain 'policy' object");
            Assert.That(policyProp.TryGetProperty("loaded_at", out _), Is.True,
                "policy must contain 'loaded_at' timestamp");
        }

        [Test]
        public async Task Admin_receives_all_permissions_as_allowed()
        {
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    // sc-admin has the wildcard "*" grant — every permission should be 'allowed'.
                    var token = mockOidcServer.GenerateTokenWithRealmRoles(
                        subject: "bob-admin",
                        realmRoles: ["sc-admin"]);

                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient,
                        HttpMethod.Get,
                        "/api/me/diagnostics",
                        token);

                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "Authenticated sc-admin should receive 200");

            var body = await response.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(body);
            var permsArray = doc.RootElement.GetProperty("permissions").EnumerateArray().ToArray();

            // Every single entry must be 'allowed' — wildcard grant covers everything.
            Assert.That(permsArray.All(p =>
                p.TryGetProperty("status", out var s) && s.GetString() == "allowed"),
                Is.True,
                "sc-admin should have all permissions as 'allowed' due to wildcard grant");

            // Scope must be null (not_granted has no scope either, but for Allowed it means unrestricted).
            Assert.That(permsArray.All(p =>
                !p.TryGetProperty("scope", out var s) || s.ValueKind == JsonValueKind.Null),
                Is.True,
                "All entries for sc-admin must have null scope");
        }

        [Test]
        public async Task Unauthenticated_request_receives_401()
        {
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient,
                        HttpMethod.Get,
                        "/api/me/diagnostics");

                    return response != null;
                })
                .Run();

            OpenIdConnectAssertions.AssertUnauthorized(response);
        }

        class Context : ScenarioContext;
    }
}
