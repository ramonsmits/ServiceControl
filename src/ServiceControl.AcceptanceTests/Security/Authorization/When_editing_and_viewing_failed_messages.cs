namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;
    using AcceptanceTesting;
    using AcceptanceTesting.Auth;
    using AcceptanceTesting.OpenIdConnect;
    using Contracts.Operations;
    using MessageFailures;
    using Microsoft.Extensions.DependencyInjection;
    using NServiceBus.AcceptanceTesting;
    using NUnit.Framework;
    using ServiceControl.Operations;
    using ServiceControl.Persistence;

    /// <summary>
    /// Acceptance tests for S3 RBAC enforcement on:
    ///   GET  api/edit/config                    (messages:edit)
    ///   POST api/edit/{id}                      (messages:edit + resource-scope check)
    ///   GET  api/errors/{id}                    (messages:view + resource-scope check)
    ///   GET  api/errors/last/{id}               (messages:view)
    ///   GET  api/errors                         (messages:view)
    ///   HEAD api/errors                         (messages:view)
    ///   GET  api/errors/summary                 (messages:view)
    ///   GET  api/endpoints/{name}/errors        (messages:view)
    /// </summary>
    class When_editing_and_viewing_failed_messages : AcceptanceTest
    {
        const string TestAudience = "api://test-audience";
        const string TestClientId = "test-client-id";
        const string TestApiScopes = "api://test-audience/.default";

        const string SalesQueueAddress = "Sales.OrderHandler@localhost";
        const string FinanceQueueAddress = "Finance.Payments@localhost";

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
        // GET api/edit/config (messages:edit)
        // -----------------------------------------------------------------------

        [Test]
        public async Task EditConfig_operator_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("operator-alice", ["sc-operator"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/edit/config", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-operator (has messages:edit) should receive 200 for GET api/edit/config");
        }

        [Test]
        public async Task EditConfig_viewer_receives_403()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/edit/config", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer (no messages:edit) should receive 403 for GET api/edit/config");
        }

        [Test]
        public async Task EditConfig_deny_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-denied", ["sc-viewer"]);
                    await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/edit/config", token);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:edit") && e.Message.Contains("deny")),
                "A deny decision for messages:edit must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // GET api/errors (messages:view)
        // -----------------------------------------------------------------------

        [Test]
        public async Task ErrorsList_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/errors", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer (has messages:view) should receive 200 for GET api/errors");
        }

        [Test]
        public async Task ErrorsList_unauthenticated_receives_401_when_auth_enabled()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/errors");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/errors");
        }

        [Test]
        public async Task ErrorsList_allow_decision_is_logged()
        {
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-logged", ["sc-viewer"]);
                    await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/errors", token);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:view") && e.Message.Contains("allow")),
                "An allow decision for messages:view must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // GET api/errors/{id} — resource-scope check: in-scope 200, out-of-scope 403
        // -----------------------------------------------------------------------

        [Test]
        public async Task GetErrorById_operator_in_scope_receives_200()
        {
            var messageId = Guid.NewGuid().ToString("N");
            using var scopedConfig = new ScopedRbacConfiguration();
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, SalesQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-viewer", ["sales-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, $"/api/errors/{messageId}", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sales-viewer with in-scope queue should receive 200 for GET api/errors/{id}");
        }

        [Test]
        public async Task GetErrorById_operator_out_of_scope_receives_403()
        {
            var messageId = Guid.NewGuid().ToString("N");
            using var scopedConfig = new ScopedRbacConfiguration();
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-viewer-oos", ["sales-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, $"/api/errors/{messageId}", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sales-viewer with out-of-scope queue should receive 403 for GET api/errors/{id}");
        }

        [Test]
        public async Task GetErrorById_resource_scope_deny_is_logged_with_queue()
        {
            var messageId = Guid.NewGuid().ToString("N");
            using var scopedConfig = new ScopedRbacConfiguration();
            var recordingProvider = new RecordingLoggerProvider();
            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, FinanceQueueAddress);
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-viewer-audit", ["sales-viewer"]);
                    await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, $"/api/errors/{messageId}", token);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:view")
                && e.Message.Contains("deny")
                && e.Message.Contains(FinanceQueueAddress)),
                "The resource-scope deny must include the out-of-scope queue address in the log");
        }

        // -----------------------------------------------------------------------
        // POST api/edit/{id} — resource-scope check: scoped user denied edit of
        // out-of-scope message (Fix 3)
        // -----------------------------------------------------------------------

        [Test]
        public async Task Edit_scoped_operator_out_of_scope_receives_403()
        {
            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;
            using var scopedConfig = new ScopedRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-editor-oos", ["sales-editor"]);
                    // POST with empty body — we expect 403 before body validation runs
                    using var request = new HttpRequestMessage(HttpMethod.Post, $"/api/edit/{messageId}");
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                    request.Content = new StringContent("{\"messageBody\":\"\",\"messageHeaders\":{}}", System.Text.Encoding.UTF8, "application/json");
                    response = await HttpClient.SendAsync(request);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "Sales-scoped editor must receive 403 when editing a Finance-queue message");
        }

        // -----------------------------------------------------------------------
        // GET api/errors/summary (messages:view)
        // -----------------------------------------------------------------------

        [Test]
        public async Task ErrorsSummary_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/errors/summary", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/errors/summary");
        }

        [Test]
        public async Task ErrorsSummary_unauthenticated_receives_401()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/errors/summary");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized),
                "Unauthenticated request should receive 401 for GET api/errors/summary");
        }

        // -----------------------------------------------------------------------
        // GET api/endpoints/{name}/errors (messages:view)
        // -----------------------------------------------------------------------

        [Test]
        public async Task ErrorsByEndpoint_viewer_receives_200()
        {
            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-bob", ["sc-viewer"]);
                    response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/endpoints/Sales/errors", token);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK),
                "sc-viewer should receive 200 for GET api/endpoints/{name}/errors");
        }

        // -----------------------------------------------------------------------
        // OIDC disabled
        // -----------------------------------------------------------------------

        [Test]
        public async Task When_auth_disabled_view_endpoints_accept_without_token()
        {
            configuration?.Dispose();
            configuration = new OpenIdConnectTestConfiguration(ServiceControlInstanceType.Primary)
                .WithAuthenticationDisabled();

            HttpResponseMessage response = null;
            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient, HttpMethod.Get, "/api/errors");
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Forbidden).And.Not.EqualTo(HttpStatusCode.Unauthorized),
                "With OIDC disabled, errors list must accept unauthenticated requests");
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        Task StoreFailedMessage(string messageId, string queueAddress)
        {
            var dataStore = Services.GetRequiredService<IErrorMessageDataStore>();
            return dataStore.StoreFailedMessagesForTestsOnly(BuildFailedMessage(messageId, queueAddress));
        }

        static FailedMessage BuildFailedMessage(string uniqueMessageId, string queueAddress) =>
            new()
            {
                Id = $"FailedMessages/{uniqueMessageId}",
                UniqueMessageId = uniqueMessageId,
                Status = FailedMessageStatus.Unresolved,
                ProcessingAttempts =
                [
                    new FailedMessage.ProcessingAttempt
                    {
                        AttemptedAt = DateTime.UtcNow,
                        MessageId = uniqueMessageId,
                        FailureDetails = new FailureDetails
                        {
                            AddressOfFailingEndpoint = queueAddress,
                            TimeOfFailure = DateTime.UtcNow
                        },
                        Headers = new Dictionary<string, string>
                        {
                            ["NServiceBus.MessageId"] = uniqueMessageId,
                            ["NServiceBus.FailedQ"] = queueAddress
                        },
                        MessageMetadata = new Dictionary<string, object>
                        {
                            ["MessageId"] = uniqueMessageId,
                            ["MessageType"] = "TestMessage",
                            ["IsSystemMessage"] = false,
                            ["TimeSent"] = DateTime.UtcNow,
                            ["ReceivingEndpoint"] = new EndpointDetails
                            {
                                Name = queueAddress.Split('@')[0],
                                Host = "localhost",
                                HostId = Guid.Empty
                            },
                            ["SendingEndpoint"] = new EndpointDetails
                            {
                                Name = queueAddress.Split('@')[0],
                                Host = "localhost",
                                HostId = Guid.Empty
                            }
                        }
                    }
                ]
            };

        /// <summary>
        /// RBAC config with a "sales-viewer" role scoped to Sales.* queues for messages:view.
        /// </summary>
        sealed class ScopedRbacConfiguration : IDisposable
        {
            readonly string tempYamlPath;
            bool disposed;

            public ScopedRbacConfiguration()
            {
                const string scopedYaml = """
                    schemaVersion: 1
                    roles:
                      sc-admin:
                        bindings: [ "role:sc-admin" ]
                        permissions: [ "*" ]
                      sc-operator:
                        bindings: [ "role:sc-operator" ]
                        permissions:
                          - "messages:view"
                          - "messages:retry"
                          - "messages:edit"
                      sc-viewer:
                        bindings: [ "role:sc-viewer" ]
                        permissions:
                          - "messages:view"
                      sales-viewer:
                        bindings: [ "role:sales-viewer" ]
                        permissions:
                          - permission: "messages:view"
                            scope: { allow: ["Sales.*"] }
                      sales-editor:
                        bindings: [ "role:sales-editor" ]
                        permissions:
                          - permission: "messages:view"
                            scope: { allow: ["Sales.*"] }
                          - permission: "messages:edit"
                            scope: { allow: ["Sales.*"] }
                    """;

                tempYamlPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"rbac-test-{Guid.NewGuid():N}.yaml");
                File.WriteAllText(tempYamlPath, scopedYaml);
                Environment.SetEnvironmentVariable("SERVICECONTROL_AUTHENTICATION_RBACPOLICYFILE", tempYamlPath);
            }

            public void Dispose()
            {
                if (!disposed)
                {
                    Environment.SetEnvironmentVariable("SERVICECONTROL_AUTHENTICATION_RBACPOLICYFILE", null);
                    if (File.Exists(tempYamlPath))
                    {
                        File.Delete(tempYamlPath);
                    }
                    disposed = true;
                }
            }
        }

        class Context : ScenarioContext;
    }
}
