namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System;
    using System.IO;
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
    /// Acceptance tests for S4 RBAC enforcement (Casbin) on archive/unarchive endpoints:
    ///   PATCH/POST api/errors/archive               (messages:archive — batch)
    ///   PATCH/POST api/errors/{id}/archive          (messages:archive — single)
    ///   PATCH api/errors/unarchive                  (messages:unarchive — batch)
    ///   PATCH api/errors/{from}...{to}/unarchive    (messages:unarchive — range)
    ///   GET api/errors/groups/{classifier?}          (messages:view)
    ///   GET api/archive/groups/id/{groupId}          (messages:view)
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
        // PATCH/POST api/errors/archive (batch archive — messages:archive)
        // -----------------------------------------------------------------------

        [Test]
        public async Task BatchArchive_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Post, "/api/errors/archive", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator (has messages:archive) should receive 202 for batch archive");
        }

        [Test]
        public async Task BatchArchive_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Post, "/api/errors/archive", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer (no messages:archive) should receive 403 for batch archive");
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
        // PATCH/POST api/errors/{id}/archive (single archive — messages:archive)
        // -----------------------------------------------------------------------

        [Test]
        public async Task SingleArchive_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/errors/test-message-id/archive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for single archive");
        }

        [Test]
        public async Task SingleArchive_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Post, "/api/errors/test-message-id/archive", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for single archive");
        }

        // -----------------------------------------------------------------------
        // PATCH api/errors/unarchive (batch unarchive — messages:unarchive)
        // -----------------------------------------------------------------------

        [Test]
        public async Task BatchUnarchive_operator_receives_202()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await SendJsonRequest(token, HttpMethod.Patch, "/api/errors/unarchive", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator should receive 202 for batch unarchive");
        }

        [Test]
        public async Task BatchUnarchive_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await SendJsonRequest(token, HttpMethod.Patch, "/api/errors/unarchive", "[]");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer should receive 403 for batch unarchive");
        }

        // -----------------------------------------------------------------------
        // GET api/errors/groups/{classifier?} — messages:view
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

            Assert.That((int)response.StatusCode, Is.EqualTo(200).Or.EqualTo(204),
                "sc-viewer (has messages:view) should receive 200/204 for GET api/errors/groups");
        }

        [Test]
        public async Task GetArchiveGroups_unauthenticated_receives_401()
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
                "Unauthenticated should receive 401 for GET api/errors/groups");
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
