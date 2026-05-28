namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;
    using AcceptanceTesting;
    using AcceptanceTesting.Auth;
    using AcceptanceTesting.OpenIdConnect;
    using NServiceBus.AcceptanceTesting;
    using NUnit.Framework;

    /// <summary>
    /// Acceptance tests for S4 RBAC enforcement (Casbin) on messages search and conversation endpoints:
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
                "Unauthenticated should receive 401 for GET api/messages");
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

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
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

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
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
                        HttpClient, HttpMethod.Get, "/api/messages/search/test-keyword", token);
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
                        HttpClient, HttpMethod.Get, "/api/conversations/test-conversation-id", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/conversations/{conversationId}");
        }

        [Test]
        public async Task Conversations_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/conversations/test-conversation-id");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
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

        [Test]
        public async Task EndpointMessages_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales/messages");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
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
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales/messages/search?q=test", token);
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
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales/messages/search/test-keyword", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/endpoints/{endpoint}/messages/search/{keyword}");
        }

        // -----------------------------------------------------------------------
        // GET api/endpoints/{endpoint}/audit-count
        // -----------------------------------------------------------------------

        [Test]
        public async Task AuditCount_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales/audit-count", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/endpoints/{endpoint}/audit-count");
        }

        [Test]
        public async Task AuditCount_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales/audit-count");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        class Context : ScenarioContext;
    }
}
