namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;
    using AcceptanceTesting;
    using AcceptanceTesting.Auth;
    using AcceptanceTesting.OpenIdConnect;
    using Microsoft.Extensions.DependencyInjection;
    using NServiceBus.AcceptanceTesting;
    using NUnit.Framework;

    /// <summary>
    /// Acceptance tests for S4 RBAC enforcement (Casbin) on recoverability group endpoints:
    ///   GET    api/recoverability/groups/{classifier?}                  (recoverabilitygroups:view)
    ///   GET    api/recoverability/groups/{groupId}/errors               (recoverabilitygroups:view)
    ///   HEAD   api/recoverability/groups/{groupId}/errors               (recoverabilitygroups:view)
    ///   POST   api/recoverability/groups/{groupId}/comment              (recoverabilitygroups:view — fail-closed scoped)
    ///   DELETE api/recoverability/groups/{groupId}/comment              (recoverabilitygroups:view — fail-closed scoped)
    ///   GET    api/recoverability/groups/id/{groupId}                   (recoverabilitygroups:view)
    ///   GET    api/recoverability/classifiers                           (recoverabilitygroups:view)
    ///   GET    api/recoverability/history                               (recoverabilitygroups:view)
    ///   POST   api/recoverability/groups/{groupId}/errors/retry         (recoverabilitygroups:retry — fail-closed)
    ///   POST   api/recoverability/groups/{groupId}/errors/archive       (recoverabilitygroups:archive — fail-closed)
    ///   POST   api/recoverability/groups/{groupId}/errors/unarchive     (recoverabilitygroups:unarchive — fail-closed)
    ///   DELETE api/recoverability/unacknowledgedgroups/{groupId}        (recoverabilitygroups:view)
    /// </summary>
    class When_accessing_recoverability_groups : AcceptanceTest
    {
        const string TestAudience = "api://test-audience";
        const string TestClientId = "test-client-id";
        const string TestApiScopes = "api://test-audience/.default";

        OpenIdConnectTestConfiguration configuration;
        MockOidcServer mockOidcServer;

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

        // -----------------------------------------------------------------------
        // GET api/recoverability/groups/{classifier?}
        // -----------------------------------------------------------------------

        [Test]
        public async Task GetAllGroups_operator_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/recoverability/groups", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-operator should receive 200 for GET api/recoverability/groups");
        }

        [Test]
        public async Task GetAllGroups_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/recoverability/groups", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer (has recoverabilitygroups:view) should receive 200");
        }

        [Test]
        public async Task GetAllGroups_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/recoverability/groups");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        // -----------------------------------------------------------------------
        // GET api/recoverability/classifiers
        // -----------------------------------------------------------------------

        [Test]
        public async Task GetClassifiers_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/recoverability/classifiers", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/recoverability/classifiers");
        }

        [Test]
        public async Task GetClassifiers_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/recoverability/classifiers");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        // -----------------------------------------------------------------------
        // GET api/recoverability/history
        // -----------------------------------------------------------------------

        [Test]
        public async Task GetRetryHistory_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/recoverability/history", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/recoverability/history");
        }

        // -----------------------------------------------------------------------
        // POST api/recoverability/groups/{groupId}/errors/retry (recoverabilitygroups:retry)
        // -----------------------------------------------------------------------

        [Test]
        public async Task GroupRetry_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/test-group-id/errors/retry", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator (has recoverabilitygroups:retry unrestricted) should receive 202");
        }

        [Test]
        public async Task GroupRetry_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/test-group-id/errors/retry", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer (no recoverabilitygroups:retry) should receive 403");
        }

        [Test]
        public async Task GroupRetry_deny_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-denied", ["sc-viewer"]);
                    await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/test-group-id/errors/retry", token);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("recoverabilitygroups:retry") && e.Message.Contains("deny")),
                "A deny decision for recoverabilitygroups:retry must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // POST api/recoverability/groups/{groupId}/errors/archive (recoverabilitygroups:archive)
        // -----------------------------------------------------------------------

        [Test]
        public async Task GroupArchive_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/test-group-id/errors/archive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator (has recoverabilitygroups:archive unrestricted) should receive 202");
        }

        [Test]
        public async Task GroupArchive_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/test-group-id/errors/archive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for group archive");
        }

        // -----------------------------------------------------------------------
        // POST api/recoverability/groups/{groupId}/errors/unarchive (recoverabilitygroups:unarchive)
        // -----------------------------------------------------------------------

        [Test]
        public async Task GroupUnarchive_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/test-group-id/errors/unarchive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator (has recoverabilitygroups:unarchive unrestricted) should receive 202");
        }

        [Test]
        public async Task GroupUnarchive_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/test-group-id/errors/unarchive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for group unarchive");
        }

        // -----------------------------------------------------------------------
        // POST/DELETE api/recoverability/groups/{groupId}/comment (recoverabilitygroups:view)
        // -----------------------------------------------------------------------

        [Test]
        public async Task EditComment_viewer_receives_202()
        {
            // sc-viewer has unrestricted recoverabilitygroups:view → comment write allowed
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post,
                        "/api/recoverability/groups/test-group-id/comment?comment=test", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-viewer (has unrestricted recoverabilitygroups:view) should receive 202 for POST comment");
        }

        [Test]
        public async Task EditComment_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Post,
                        "/api/recoverability/groups/test-group-id/comment?comment=test");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        class Context : ScenarioContext;
    }
}
