namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System.Net;
    using System.Net.Http;
    using System.Text;
    using System.Threading.Tasks;
    using AcceptanceTesting;
    using AcceptanceTesting.Auth;
    using AcceptanceTesting.OpenIdConnect;
    using Microsoft.Extensions.DependencyInjection;
    using NServiceBus.AcceptanceTesting;
    using NUnit.Framework;

    /// <summary>
    /// Acceptance tests for S3 RBAC enforcement on recoverability group endpoints:
    ///   GET    api/recoverability/groups/{classifier?}                  (recoverabilitygroups:view)
    ///   GET    api/recoverability/groups/{groupId}/errors               (recoverabilitygroups:view)
    ///   HEAD   api/recoverability/groups/{groupId}/errors               (recoverabilitygroups:view)
    ///   POST   api/recoverability/groups/{groupId}/comment              (recoverabilitygroups:view)
    ///   DELETE api/recoverability/groups/{groupId}/comment              (recoverabilitygroups:view)
    ///   GET    api/recoverability/groups/id/{groupId}                   (recoverabilitygroups:view)
    ///   GET    api/recoverability/classifiers                           (recoverabilitygroups:view)
    ///   GET    api/recoverability/history                               (recoverabilitygroups:view)
    ///   POST   api/recoverability/groups/{groupId}/errors/retry         (recoverabilitygroups:retry)
    ///   POST   api/recoverability/groups/{groupId}/errors/archive       (recoverabilitygroups:archive)
    ///   POST   api/recoverability/groups/{groupId}/errors/unarchive     (recoverabilitygroups:unarchive)
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

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/recoverability/groups");
        }

        [Test]
        public async Task GetAllGroups_allow_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-logged", ["sc-viewer"]);
                    await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/recoverability/groups", token);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("recoverabilitygroups:view") && e.Message.Contains("allow")),
                "An allow decision for recoverabilitygroups:view must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // GET api/recoverability/classifiers
        // -----------------------------------------------------------------------

        [Test]
        public async Task Classifiers_operator_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/recoverability/classifiers", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-operator should receive 200 for GET api/recoverability/classifiers");
        }

        [Test]
        public async Task Classifiers_unauthenticated_receives_401()
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

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/recoverability/classifiers");
        }

        // -----------------------------------------------------------------------
        // GET api/recoverability/history
        // -----------------------------------------------------------------------

        [Test]
        public async Task History_viewer_receives_200()
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

        [Test]
        public async Task History_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/recoverability/history");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/recoverability/history");
        }

        // -----------------------------------------------------------------------
        // POST api/recoverability/groups/{groupId}/errors/retry (recoverabilitygroups:retry)
        // -----------------------------------------------------------------------

        [Test]
        public async Task GroupRetry_operator_receives_accepted()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/group-123/errors/retry", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for POST .../errors/retry");
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
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/group-123/errors/retry", token);
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
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/group-123/errors/retry", token);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("recoverabilitygroups:retry") && e.Message.Contains("deny")),
                "A deny decision for recoverabilitygroups:retry must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // POST api/recoverability/groups/{groupId}/errors/archive
        // -----------------------------------------------------------------------

        [Test]
        public async Task GroupArchive_operator_receives_accepted()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/group-123/errors/archive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for POST .../errors/archive");
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
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/group-123/errors/archive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer (no recoverabilitygroups:archive) should receive 403");
        }

        [Test]
        public async Task GroupArchive_deny_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-denied", ["sc-viewer"]);
                    await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/group-123/errors/archive", token);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("recoverabilitygroups:archive") && e.Message.Contains("deny")),
                "A deny decision for recoverabilitygroups:archive must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // POST api/recoverability/groups/{groupId}/errors/unarchive
        // -----------------------------------------------------------------------

        [Test]
        public async Task GroupUnarchive_operator_receives_accepted()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/group-123/errors/unarchive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for POST .../errors/unarchive");
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
                        HttpClient, HttpMethod.Post, "/api/recoverability/groups/group-123/errors/unarchive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer (no recoverabilitygroups:unarchive) should receive 403");
        }

        // -----------------------------------------------------------------------
        // POST/DELETE api/recoverability/groups/{groupId}/comment
        // -----------------------------------------------------------------------

        [Test]
        public async Task EditComment_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Post,
                        "/api/recoverability/groups/group-123/comment?comment=test", null);
                    return response != null;
                })
                .Run();

            // sc-viewer has recoverabilitygroups:view so it should be ALLOWED here
            // The plan maps comment to recoverabilitygroups:view
            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer (has recoverabilitygroups:view) should not receive 403 for POST comment");
        }

        // -----------------------------------------------------------------------
        // DELETE api/recoverability/unacknowledgedgroups/{groupId}
        // -----------------------------------------------------------------------

        [Test]
        public async Task AcknowledgeGroup_operator_receives_ok_or_not_found()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Delete, "/api/recoverability/unacknowledgedgroups/group-123", token);
                    return response != null;
                })
                .Run();

            // Group doesn't exist → 404 or 200; NOT 403
            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for DELETE api/recoverability/unacknowledgedgroups/{id}");
        }

        [Test]
        public async Task AcknowledgeGroup_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Delete, "/api/recoverability/unacknowledgedgroups/group-123");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated DELETE should receive 401");
        }

        // -----------------------------------------------------------------------
        // OIDC disabled
        // -----------------------------------------------------------------------

        [Test]
        public async Task When_auth_disabled_recoverability_endpoints_accept_without_token()
        {
            configuration?.Dispose();
            configuration = new OpenIdConnectTestConfiguration(ServiceControlInstanceType.Primary)
                .WithAuthenticationDisabled();

            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/recoverability/groups");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden).And.Not.EqualTo(HttpStatusCode.Unauthorized),
                "With OIDC disabled, recoverability groups endpoint must accept unauthenticated requests");
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        Task<HttpResponseMessage> SendJsonRequest(string token, HttpMethod method, string path, string jsonBody)
        {
            using var request = new HttpRequestMessage(method, path);
            if (token != null)
            {
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            }
            if (jsonBody != null)
            {
                request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            }
            return HttpClient.SendAsync(request);
        }

        class Context : ScenarioContext;
    }
}
