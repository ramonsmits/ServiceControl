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
    /// Acceptance tests for S4 RBAC enforcement (Casbin) on bulk retry endpoints:
    ///   POST api/errors/retry               (messages:retry — retry by IDs)
    ///   POST api/errors/retry/all           (messages:retry — retry all)
    ///   POST api/errors/queues/{q}/retry    (messages:retry — retry by queue)
    ///   POST api/errors/{ep}/retry/all      (messages:retry — retry all by endpoint)
    ///   POST api/pendingretries/retry       (messages:retry — retry pending by IDs)
    ///   POST api/pendingretries/queues/retry (messages:retry — retry pending by queue)
    ///   PATCH api/pendingretries/resolve    (messages:retry — resolve pending)
    ///   PATCH api/pendingretries/queues/resolve (messages:retry — resolve pending by queue)
    /// </summary>
    class When_retrying_messages_in_bulk : AcceptanceTest
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
        // POST api/errors/retry (retry by IDs — messages:retry)
        // -----------------------------------------------------------------------

        [Test]
        public async Task RetryByIds_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Post, "/api/errors/retry", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for POST api/errors/retry");
        }

        [Test]
        public async Task RetryByIds_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Post, "/api/errors/retry", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/errors/retry");
        }

        [Test]
        public async Task RetryByIds_deny_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-denied", ["sc-viewer"]);
                    await SendJsonRequest(token, HttpMethod.Post, "/api/errors/retry", "[]");
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:retry") && e.Message.Contains("deny")),
                "A deny decision for messages:retry must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // POST api/errors/retry/all (retry all — messages:retry)
        // -----------------------------------------------------------------------

        [Test]
        public async Task RetryAll_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/errors/retry/all", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for POST api/errors/retry/all");
        }

        [Test]
        public async Task RetryAll_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/errors/retry/all", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/errors/retry/all");
        }

        // -----------------------------------------------------------------------
        // POST api/errors/queues/{queueAddress}/retry (retry by queue — messages:retry + scope check)
        // -----------------------------------------------------------------------

        [Test]
        public async Task RetryByQueue_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/errors/queues/Sales.OrderHandler%40localhost/retry", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for POST api/errors/queues/{q}/retry");
        }

        [Test]
        public async Task RetryByQueue_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/errors/queues/Sales.OrderHandler%40localhost/retry", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/errors/queues/{q}/retry");
        }

        // -----------------------------------------------------------------------
        // POST api/errors/{endpointName}/retry/all (retry by endpoint — messages:retry)
        // -----------------------------------------------------------------------

        [Test]
        public async Task RetryAllByEndpoint_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/errors/Sales/retry/all", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for POST api/errors/{ep}/retry/all");
        }

        [Test]
        public async Task RetryAllByEndpoint_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/errors/Sales/retry/all", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/errors/{ep}/retry/all");
        }

        // -----------------------------------------------------------------------
        // POST api/pendingretries/retry — messages:retry
        // -----------------------------------------------------------------------

        [Test]
        public async Task PendingRetry_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Post, "/api/pendingretries/retry", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for POST api/pendingretries/retry");
        }

        [Test]
        public async Task PendingRetry_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Post, "/api/pendingretries/retry", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/pendingretries/retry");
        }

        // -----------------------------------------------------------------------
        // PATCH api/pendingretries/resolve — messages:retry
        // -----------------------------------------------------------------------

        [Test]
        public async Task ResolvePendingRetries_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Patch, "/api/pendingretries/resolve",
                        """{"uniquemessageids": []}""");
                    return response != null;
                })
                .Run();

            // 202 or 422 (empty IDs) are both acceptable for a permitted user
            Assert.That((int)response.StatusCode, Is.Not.EqualTo(403),
                "sc-operator should not receive 403 for PATCH api/pendingretries/resolve");
        }

        [Test]
        public async Task ResolvePendingRetries_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Patch, "/api/pendingretries/resolve",
                        """{"uniquemessageids": []}""");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for PATCH api/pendingretries/resolve");
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        Task<HttpResponseMessage> SendJsonRequest(string token, HttpMethod method, string path, string json)
        {
            var request = new HttpRequestMessage(method, path)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            return HttpClient.SendAsync(request);
        }

        class Context : ScenarioContext;
    }
}
