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
    /// Acceptance tests for S3 RBAC enforcement on pending-retry endpoints:
    ///   POST  api/pendingretries/retry               (messages:retry)
    ///   POST  api/pendingretries/queues/retry        (messages:retry)
    ///   PATCH api/pendingretries/resolve             (messages:retry)
    ///   PATCH api/pendingretries/queues/resolve      (messages:retry)
    /// </summary>
    class When_resolving_and_viewing_pending_retries : AcceptanceTest
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
        // POST api/pendingretries/retry
        // -----------------------------------------------------------------------

        [Test]
        public async Task PendingRetriesRetry_operator_receives_accepted()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Post,
                        "/api/pendingretries/retry", "[]");
                    return response != null;
                })
                .Run();

            // Empty list → Accepted or UnprocessableEntity; either way NOT 403
            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for POST api/pendingretries/retry");
        }

        [Test]
        public async Task PendingRetriesRetry_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Post,
                        "/api/pendingretries/retry", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/pendingretries/retry");
        }

        [Test]
        public async Task PendingRetriesRetry_deny_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-denied", ["sc-viewer"]);
                    await SendJsonRequest(token, HttpMethod.Post, "/api/pendingretries/retry", "[]");
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:retry") && e.Message.Contains("deny")),
                "A deny decision for messages:retry must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // POST api/pendingretries/queues/retry
        // -----------------------------------------------------------------------

        [Test]
        public async Task PendingRetriesQueueRetry_operator_receives_accepted()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Post,
                        "/api/pendingretries/queues/retry",
                        """{"queueaddress":"Sales@localhost","from":"2024-01-01T00:00:00Z","to":"2024-12-31T00:00:00Z"}""");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for POST api/pendingretries/queues/retry");
        }

        [Test]
        public async Task PendingRetriesQueueRetry_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Post,
                        "/api/pendingretries/queues/retry",
                        """{"queueaddress":"Sales@localhost","from":"2024-01-01T00:00:00Z","to":"2024-12-31T00:00:00Z"}""");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/pendingretries/queues/retry");
        }

        // -----------------------------------------------------------------------
        // PATCH api/pendingretries/resolve
        // -----------------------------------------------------------------------

        [Test]
        public async Task PendingRetriesResolve_operator_receives_accepted()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Patch,
                        "/api/pendingretries/resolve",
                        """{"uniquemessageids":[],"from":null,"to":null}""");
                    return response != null;
                })
                .Run();

            // Empty/null IDs may return UnprocessableEntity or Accepted — NOT 403
            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for PATCH api/pendingretries/resolve");
        }

        [Test]
        public async Task PendingRetriesResolve_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Patch,
                        "/api/pendingretries/resolve",
                        """{"uniquemessageids":[],"from":null,"to":null}""");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for PATCH api/pendingretries/resolve");
        }

        // -----------------------------------------------------------------------
        // PATCH api/pendingretries/queues/resolve
        // -----------------------------------------------------------------------

        [Test]
        public async Task PendingRetriesQueueResolve_operator_receives_accepted()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Patch,
                        "/api/pendingretries/queues/resolve",
                        """{"queueaddress":"Sales@localhost","from":"2024-01-01T00:00:00Z","to":"2024-12-31T00:00:00Z"}""");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for PATCH api/pendingretries/queues/resolve");
        }

        [Test]
        public async Task PendingRetriesQueueResolve_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Patch,
                        "/api/pendingretries/queues/resolve",
                        """{"queueaddress":"Sales@localhost","from":"2024-01-01T00:00:00Z","to":"2024-12-31T00:00:00Z"}""");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for PATCH api/pendingretries/queues/resolve");
        }

        // -----------------------------------------------------------------------
        // OIDC disabled
        // -----------------------------------------------------------------------

        [Test]
        public async Task When_auth_disabled_pending_retry_endpoints_accept_without_token()
        {
            configuration?.Dispose();
            configuration = new OpenIdConnectTestConfiguration(ServiceControlInstanceType.Primary)
                .WithAuthenticationDisabled();

            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await SendJsonRequest(null, HttpMethod.Post,
                        "/api/pendingretries/retry", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden).And.Not.EqualTo(HttpStatusCode.Unauthorized),
                "With OIDC disabled, pending-retry endpoint must accept unauthenticated requests");
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
            request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            return HttpClient.SendAsync(request);
        }

        class Context : ScenarioContext;
    }
}
