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
    using ServiceControl.Persistence;

    /// <summary>
    /// Acceptance tests for the S4 RBAC enforcement (Casbin) on <c>POST api/errors/{id}/retry</c>.
    /// Covers the full test matrix:
    /// (a) permitted role → 202 Accepted
    /// (b) unpermitted role → 403 Forbidden
    /// (c) scoped role → in-scope 202, out-of-scope 403
    /// (d) allow AND deny decisions appear in the ServiceControl.Audit log;
    ///     out-of-scope deny must be logged with the queue address as the resource
    ///     — proving it was fired by the Casbin resource-scope check, not some other path
    /// (e) OIDC disabled → endpoint accessible without auth (returns 202 Accepted)
    /// </summary>
    class When_retrying_a_failed_message : AcceptanceTest
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
        // (a) sc-operator (has messages:retry) → 202 Accepted
        // -----------------------------------------------------------------------

        [Test]
        public async Task Operator_with_retry_permission_receives_202()
        {
            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, SalesQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles(
                        subject: "operator-alice",
                        realmRoles: ["sc-operator"]);

                    response = await SendRetry(token, messageId);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sc-operator with messages:retry should receive 202 Accepted");
        }

        // -----------------------------------------------------------------------
        // (b) sc-viewer (no messages:retry) → 403 Forbidden
        // -----------------------------------------------------------------------

        [Test]
        public async Task Viewer_without_retry_permission_receives_403()
        {
            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, SalesQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles(
                        subject: "viewer-bob",
                        realmRoles: ["sc-viewer"]);

                    response = await SendRetry(token, messageId);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sc-viewer without messages:retry should receive 403 Forbidden");
        }

        // -----------------------------------------------------------------------
        // (c) Scoped role: in-scope → 202, out-of-scope → 403
        // -----------------------------------------------------------------------

        [Test]
        public async Task Scoped_role_in_scope_receives_202()
        {
            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;

            using var scopedConfig = new ScopedRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, SalesQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles(
                        subject: "sales-operator",
                        realmRoles: ["sales-operator"]);

                    response = await SendRetry(token, messageId);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "sales-operator with scoped retry permission should receive 202 for in-scope queue");
        }

        [Test]
        public async Task Scoped_role_out_of_scope_receives_403()
        {
            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;

            using var scopedConfig = new ScopedRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    // Finance queue is outside sales-operator's scope
                    await StoreFailedMessage(messageId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles(
                        subject: "sales-operator-out",
                        realmRoles: ["sales-operator"]);

                    response = await SendRetry(token, messageId);
                    return response != null;
                })
                .Run();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden),
                "sales-operator with scoped retry permission should receive 403 for out-of-scope queue");
        }

        // -----------------------------------------------------------------------
        // (d) Decision logging: both allow and deny appear in ServiceControl.Audit log
        // -----------------------------------------------------------------------

        [Test]
        public async Task Allow_decision_is_logged_to_ServiceControl_Audit_category()
        {
            var messageId = Guid.NewGuid().ToString("N");
            var recordingProvider = new RecordingLoggerProvider();

            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, SalesQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles(
                        subject: "operator-logged",
                        realmRoles: ["sc-operator"]);

                    await SendRetry(token, messageId);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");

            // The resource-stage allow decision must be present, identifiable by the queue address.
            // The S4 Casbin scope checker logs the decision with the queue address as the resource field.
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:retry")
                && e.Message.Contains("allow")
                && e.Message.Contains(SalesQueueAddress)),
                "A resource-stage allow decision for messages:retry must appear in ServiceControl.Audit log " +
                "and must include the queue address as the resource — proving Casbin fired");
        }

        [Test]
        public async Task Deny_decision_for_out_of_scope_is_logged_with_queue_as_resource()
        {
            // This test specifically verifies that the resource-stage deny — fired by Casbin's
            // enforcer.EnforceAsync(sub, perm, resource) — is logged with the queue address.
            // The presence of the queue address proves the CasbinResourceScopeChecker ran,
            // not just the verb-stage handler.
            var messageId = Guid.NewGuid().ToString("N");
            var recordingProvider = new RecordingLoggerProvider();

            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            using var scopedConfig = new ScopedRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    // Finance queue is outside sales-operator's scope
                    await StoreFailedMessage(messageId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles(
                        subject: "sales-operator-audit",
                        realmRoles: ["sales-operator"]);

                    await SendRetry(token, messageId);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");

            // The resource-stage deny must include the queue address as the resource field,
            // proving it is the Casbin resource-scope log (not just the verb-stage log).
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:retry")
                && e.Message.Contains("deny")
                && e.Message.Contains(FinanceQueueAddress)),
                "A resource-stage deny decision for messages:retry must appear in ServiceControl.Audit log " +
                "and must include the out-of-scope queue address — proving CasbinResourceScopeChecker fired");
        }

        [Test]
        public async Task Deny_decision_is_logged_to_ServiceControl_Audit_category()
        {
            // Verb-stage deny: sc-viewer has no messages:retry permission at all.
            var messageId = Guid.NewGuid().ToString("N");
            var recordingProvider = new RecordingLoggerProvider();

            CustomizeHostBuilder = hb =>
                hb.Services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(recordingProvider);

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, SalesQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles(
                        subject: "viewer-denied",
                        realmRoles: ["sc-viewer"]);

                    await SendRetry(token, messageId);
                    return true;
                })
                .Run();

            var auditEntries = recordingProvider.EntriesFor("ServiceControl.Audit");
            Assert.That(auditEntries, Has.Some.Matches<LogEntry>(e =>
                e.Message.Contains("messages:retry") && e.Message.Contains("deny")),
                "A deny decision for messages:retry must appear in ServiceControl.Audit log");
        }

        // -----------------------------------------------------------------------
        // (e) OIDC disabled → endpoint accessible without auth (non-breaking guarantee)
        // -----------------------------------------------------------------------

        [Test]
        public async Task When_auth_disabled_retry_endpoint_accepts_without_token()
        {
            // Override: disable auth for this test
            configuration?.Dispose();
            configuration = new OpenIdConnectTestConfiguration(ServiceControlInstanceType.Primary)
                .WithAuthenticationDisabled();

            var messageId = Guid.NewGuid().ToString("N");
            HttpResponseMessage response = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(messageId, SalesQueueAddress);
                    // No bearer token — send unauthenticated request
                    response = await OpenIdConnectAssertions.SendRequestWithoutAuth(
                        HttpClient,
                        HttpMethod.Post,
                        $"/api/errors/{messageId}/retry");

                    return response != null;
                })
                .Run();

            // With auth disabled, the endpoint behaves as pre-RBAC: it accepts without a token.
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted),
                "With OIDC disabled, the retry endpoint must accept unauthenticated requests with 202 Accepted");
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        Task StoreFailedMessage(string messageId, string queueAddress)
        {
            var dataStore = Services.GetRequiredService<IErrorMessageDataStore>();
            var message = BuildFailedMessage(messageId, queueAddress);
            return dataStore.StoreFailedMessagesForTestsOnly(message);
        }

        Task<HttpResponseMessage> SendRetry(string token, string messageId) =>
            OpenIdConnectAssertions.SendRequestWithBearerToken(
                HttpClient,
                HttpMethod.Post,
                $"/api/errors/{messageId}/retry",
                token);

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
                        }
                    }
                ]
            };

        /// <summary>
        /// Temporarily sets a scoped rbac.yaml that includes a "sales-operator" role
        /// restricted to the Sales.* queue prefix.
        /// The Casbin compiler will produce allow lines for Sales.* and deny the rest via
        /// the deny-override effect — the S4 <c>enforcer.EnforceAsync</c> call handles this.
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
                      sc-viewer:
                        bindings: [ "role:sc-viewer" ]
                        permissions:
                          - "messages:view"
                      sales-operator:
                        bindings: [ "role:sales-operator" ]
                        permissions:
                          - permission: "messages:retry"
                            scope: { allow: ["Sales.*"] }
                    """;

                tempYamlPath = Path.Combine(Path.GetTempPath(), $"rbac-test-{Guid.NewGuid():N}.yaml");
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
