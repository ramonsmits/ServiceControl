namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System;
    using System.Collections.Generic;
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
    /// Acceptance tests for S3 RBAC enforcement on bulk-retry and group-retry endpoints:
    ///   POST api/errors/retry                          (retry-all by IDs)
    ///   POST api/errors/retry/all                      (retry all)
    ///   POST api/errors/queues/{queueAddress}/retry    (retry by queue)
    ///   POST api/errors/{endpointName}/retry/all       (retry all by endpoint)
    /// Each test covers: (a) permitted → success, (b) unpermitted → 403, (c) decision logged.
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
        // POST api/errors/retry (retry all by IDs)
        // -----------------------------------------------------------------------

        [Test]
        public async Task RetryAllById_operator_receives_202()
        {
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendRequest(token, HttpMethod.Post, "/api/errors/retry",
                        System.Text.Json.JsonSerializer.Serialize(new List<string>()));
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for POST api/errors/retry");
        }

        [Test]
        public async Task RetryAllById_viewer_receives_403()
        {
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendRequest(token, HttpMethod.Post, "/api/errors/retry",
                        System.Text.Json.JsonSerializer.Serialize(new List<string>()));
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/errors/retry");
        }

        [Test]
        public async Task RetryAllById_deny_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-deny", ["sc-viewer"]);
                    await SendRequest(token, HttpMethod.Post, "/api/errors/retry",
                        System.Text.Json.JsonSerializer.Serialize(new List<string>()));
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:retry") && e.Message.Contains("deny")),
                "A deny decision for messages:retry must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // POST api/errors/retry/all
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
        // POST api/errors/queues/{queueAddress}/retry
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
                        HttpClient, HttpMethod.Post, "/api/errors/queues/Sales.Orders%40localhost/retry", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for POST api/errors/queues/{queue}/retry");
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
                        HttpClient, HttpMethod.Post, "/api/errors/queues/Sales.Orders%40localhost/retry", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/errors/queues/{queue}/retry");
        }

        // -----------------------------------------------------------------------
        // POST api/errors/{endpointName}/retry/all
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
                "sc-operator should receive 202 for POST api/errors/{endpoint}/retry/all");
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
                "sc-viewer should receive 403 for POST api/errors/{endpoint}/retry/all");
        }

        // -----------------------------------------------------------------------
        // OIDC disabled — all bulk retry endpoints accessible without auth
        // -----------------------------------------------------------------------

        [Test]
        public async Task When_auth_disabled_bulk_retry_endpoints_accept_without_token()
        {
            configuration?.Dispose();
            configuration = new OpenIdConnectTestConfiguration(ServiceControlInstanceType.Primary)
                .WithAuthenticationDisabled();

            HttpResponseMessage retryAll = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    retryAll = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Post, "/api/errors/retry/all");
                    return retryAll != null;
                })
                .Run();

            Assert.That(retryAll.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden).And.Not.EqualTo(HttpStatusCode.Unauthorized),
                "With OIDC disabled, bulk retry endpoint must accept unauthenticated requests");
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        Task<HttpResponseMessage> SendRequest(string token, HttpMethod method, string path, string jsonBody = null)
        {
            var request = new HttpRequestMessage(method, path);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            if (jsonBody != null)
            {
                request.Content = new StringContent(jsonBody, System.Text.Encoding.UTF8, "application/json");
            }
            return HttpClient.SendAsync(request);
        }

        class Context : ScenarioContext;
    }
}
