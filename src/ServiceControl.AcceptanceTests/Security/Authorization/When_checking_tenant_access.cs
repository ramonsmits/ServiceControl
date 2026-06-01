namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Text.Json;
    using System.Threading.Tasks;
    using AcceptanceTesting;
    using AcceptanceTesting.OpenIdConnect;
    using NServiceBus.AcceptanceTesting;
    using NUnit.Framework;

    /// <summary>
    /// Acceptance tests for the tenant-access gate (IdP-claim-driven authorization, as a
    /// counterpoint to the RBAC PDP). Tenants come from the JWT 'tenants' claim; the
    /// application stores no tenant-to-user mapping. See
    /// research/platform-authorization/idp-managed-vs-app-managed-authz-data.md.
    /// </summary>
    class When_checking_tenant_access : AcceptanceTest
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
        public async Task GET_me_tenants_returns_claim_values()
        {
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateToken(
                        subject: "alice",
                        additionalClaims:
                        [
                            new Claim("tenants", "acme"),
                            new Claim("tenants", "globex")
                        ]);

                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/me/tenants", token);

                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var body = await response.Content.ReadAsStringAsync();
            var root = JsonDocument.Parse(body).RootElement;

            Assert.That(root.GetProperty("source").GetString(), Is.EqualTo("idp-claim"));
            var tenants = root.GetProperty("tenants");
            Assert.That(tenants.ValueKind, Is.EqualTo(JsonValueKind.Array));
            Assert.That(tenants.GetArrayLength(), Is.EqualTo(2));
        }

        [Test]
        public async Task Access_check_returns_200_when_tenant_is_in_claim()
        {
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateToken(
                        subject: "alice",
                        additionalClaims: [new Claim("tenants", "acme"), new Claim("tenants", "globex")]);

                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/tenants/acme/access-check", token);

                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }

        [Test]
        public async Task Access_check_returns_403_when_tenant_is_not_in_claim()
        {
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateToken(
                        subject: "victor",
                        additionalClaims: [new Claim("tenants", "acme")]);

                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/tenants/contoso/access-check", token);

                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        }

        [Test]
        public async Task Access_check_returns_403_when_no_tenants_claim_present()
        {
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateToken(subject: "no-tenants-user");

                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/tenants/acme/access-check", token);

                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        }

        class Context : ScenarioContext;
    }
}
