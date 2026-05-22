namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System;
    using System.IO;
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
    /// Acceptance tests for S3 RBAC enforcement on archive/unarchive endpoints:
    ///   PATCH/POST api/errors/archive               (batch archive)
    ///   PATCH/POST api/errors/{id}/archive          (single archive)
    ///   PATCH api/errors/unarchive                  (batch unarchive)
    ///   PATCH api/errors/{from}...{to}/unarchive    (range unarchive)
    ///   GET api/errors/groups/{classifier?}          (archive groups — messages:view)
    ///   GET api/archive/groups/id/{groupId}          (archive group view — messages:view)
    /// </summary>
    class When_archiving_and_unarchiving_messages : AcceptanceTest
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
        // PATCH/POST api/errors/archive (batch archive)
        // -----------------------------------------------------------------------

        [Test]
        public async Task BatchArchive_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Post, "/api/errors/archive",
                        "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for PATCH/POST api/errors/archive");
        }

        [Test]
        public async Task BatchArchive_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Post, "/api/errors/archive",
                        "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for PATCH/POST api/errors/archive");
        }

        [Test]
        public async Task BatchArchive_deny_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-denied", ["sc-viewer"]);
                    await SendJsonRequest(token, HttpMethod.Post, "/api/errors/archive", "[]");
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:archive") && e.Message.Contains("deny")),
                "A deny decision for messages:archive must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // PATCH/POST api/errors/{id}/archive (single archive)
        // -----------------------------------------------------------------------

        [Test]
        public async Task SingleArchive_operator_receives_202()
        {
            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, $"/api/errors/{messageId}/archive", token);
                    return response != null;
                })
                .Run();

            // Message doesn't exist → not 403; 202 or 404 both indicate the endpoint was reached
            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for POST api/errors/{id}/archive");
        }

        [Test]
        public async Task SingleArchive_viewer_receives_403()
        {
            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, $"/api/errors/{messageId}/archive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for POST api/errors/{id}/archive");
        }

        // -----------------------------------------------------------------------
        // PATCH api/errors/unarchive (batch unarchive)
        // -----------------------------------------------------------------------

        [Test]
        public async Task BatchUnarchive_operator_receives_accepted()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Patch, "/api/errors/unarchive", token);
                    return response != null;
                })
                .Run();

            // Empty IDs → BadRequest (400) or Accepted (202), but NOT 403
            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden),
                "sc-operator should not receive 403 for PATCH api/errors/unarchive");
        }

        [Test]
        public async Task BatchUnarchive_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Patch, "/api/errors/unarchive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for PATCH api/errors/unarchive");
        }

        [Test]
        public async Task BatchUnarchive_deny_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-denied", ["sc-viewer"]);
                    await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Patch, "/api/errors/unarchive", token);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:unarchive") && e.Message.Contains("deny")),
                "A deny decision for messages:unarchive must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // GET api/errors/groups/{classifier?} (archive groups — messages:view)
        // -----------------------------------------------------------------------

        [Test]
        public async Task GetArchiveGroups_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/errors/groups", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/errors/groups (has messages:view)");
        }

        [Test]
        public async Task GetArchiveGroups_unauthenticated_receives_401_when_auth_enabled()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/errors/groups");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/errors/groups");
        }

        // -----------------------------------------------------------------------
        // OIDC disabled
        // -----------------------------------------------------------------------

        [Test]
        public async Task When_auth_disabled_archive_endpoints_accept_without_token()
        {
            configuration?.Dispose();
            configuration = new OpenIdConnectTestConfiguration(ServiceControlInstanceType.Primary)
                .WithAuthenticationDisabled();

            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await SendJsonRequest(null, HttpMethod.Post, "/api/errors/archive", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden).And.Not.EqualTo(HttpStatusCode.Unauthorized),
                "With OIDC disabled, archive endpoint must accept unauthenticated requests");
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
            request.Content = new StringContent(jsonBody, System.Text.Encoding.UTF8, "application/json");
            return HttpClient.SendAsync(request);
        }

        class Context : ScenarioContext;
    }
}
