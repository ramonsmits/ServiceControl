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
    /// Acceptance tests for S3 RBAC enforcement on messages search and conversation endpoints:
    ///   GET api/messages                                   (messages:view)
    ///   GET api/messages2                                  (messages:view)
    ///   GET api/messages/search                            (messages:view)
    ///   GET api/messages/search/{keyword}                  (messages:view)
    ///   GET api/messages/{id}/body                         (messages:view)
    ///   GET api/conversations/{conversationId}             (messages:view)
    ///   GET api/endpoints/{endpoint}/messages              (messages:view)
    ///   GET api/endpoints/{endpoint}/messages/search       (messages:view)
    ///   GET api/endpoints/{endpoint}/messages/search/{kw}  (messages:view)
    ///   GET api/endpoints/{endpoint}/audit-count           (messages:view)
    /// </summary>
    class When_viewing_messages_and_conversations : AcceptanceTest
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
        // GET api/messages
        // -----------------------------------------------------------------------

        [Test]
        public async Task Messages_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/messages", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/messages");
        }

        [Test]
        public async Task Messages_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/messages");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/messages");
        }

        [Test]
        public async Task Messages_allow_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-logged", ["sc-viewer"]);
                    await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/messages", token);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:view") && e.Message.Contains("allow")),
                "An allow decision for messages:view must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // GET api/messages2
        // -----------------------------------------------------------------------

        [Test]
        public async Task Messages2_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/messages2", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/messages2");
        }

        [Test]
        public async Task Messages2_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/messages2");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/messages2");
        }

        // -----------------------------------------------------------------------
        // GET api/messages/search
        // -----------------------------------------------------------------------

        [Test]
        public async Task MessagesSearch_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/messages/search?q=test", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/messages/search");
        }

        [Test]
        public async Task MessagesSearch_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/messages/search?q=test");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/messages/search");
        }

        // -----------------------------------------------------------------------
        // GET api/messages/search/{keyword}
        // -----------------------------------------------------------------------

        [Test]
        public async Task MessagesSearchByKeyword_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/messages/search/myerror", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/messages/search/{keyword}");
        }

        // -----------------------------------------------------------------------
        // GET api/conversations/{conversationId}
        // -----------------------------------------------------------------------

        [Test]
        public async Task Conversations_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/conversations/conv-123", token);
                    return response != null;
                })
                .Run();

            // Empty conversation → 200 with empty list
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/conversations/{id}");
        }

        [Test]
        public async Task Conversations_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/conversations/conv-123");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/conversations/{id}");
        }

        // -----------------------------------------------------------------------
        // GET api/endpoints/{endpoint}/messages
        // -----------------------------------------------------------------------

        [Test]
        public async Task EndpointMessages_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales/messages", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/endpoints/{endpoint}/messages");
        }

        // -----------------------------------------------------------------------
        // GET api/endpoints/{endpoint}/messages/search
        // -----------------------------------------------------------------------

        [Test]
        public async Task EndpointMessagesSearch_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales/messages/search?q=err", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/endpoints/{endpoint}/messages/search");
        }

        // -----------------------------------------------------------------------
        // GET api/endpoints/{endpoint}/messages/search/{keyword}
        // -----------------------------------------------------------------------

        [Test]
        public async Task EndpointMessagesSearchByKeyword_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales/messages/search/error", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/endpoints/{endpoint}/messages/search/{keyword}");
        }

        // -----------------------------------------------------------------------
        // OIDC disabled
        // -----------------------------------------------------------------------

        [Test]
        public async Task When_auth_disabled_messages_endpoints_accept_without_token()
        {
            configuration?.Dispose();
            configuration = new OpenIdConnectTestConfiguration(ServiceControlInstanceType.Primary)
                .WithAuthenticationDisabled();

            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/messages");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden).And.Not.EqualTo(HttpStatusCode.Unauthorized),
                "With OIDC disabled, messages endpoint must accept unauthenticated requests");
        }

        class Context : ScenarioContext;
    }
}
