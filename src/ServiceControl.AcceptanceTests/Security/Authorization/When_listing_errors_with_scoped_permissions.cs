namespace ServiceControl.AcceptanceTests.Security.Authorization
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Text.Json;
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
    /// Acceptance tests for the R1 scope filter on list endpoints.
    /// A scoped user sees only messages from queues matching their scope; an unrestricted
    /// user sees all messages. Applied to:
    ///   GET api/errors
    ///   GET api/endpoints/{name}/errors
    /// </summary>
    class When_listing_errors_with_scoped_permissions : AcceptanceTest
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
        // R1: unrestricted viewer sees all messages
        // -----------------------------------------------------------------------

        [Test]
        public async Task Unrestricted_viewer_sees_all_messages()
        {
            var salesId = Guid.NewGuid().ToString("N");
            var financeId = Guid.NewGuid().ToString("N");
            string responseBody = null;

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(salesId, SalesQueueAddress);
                    await StoreFailedMessage(financeId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("viewer-all", ["sc-viewer"]);
                    var response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/errors", token);

                    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                    responseBody = await response.Content.ReadAsStringAsync();
                    return true;
                })
                .Run();

            // sc-viewer has unrestricted messages:view → both messages returned
            using var doc = JsonDocument.Parse(responseBody!);
            var ids = doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("id", out var idProp) ? idProp.GetString() : null)
                .ToList();

            Assert.That(ids, Has.Some.Contains(salesId),
                "Unrestricted viewer should see the Sales message");
            Assert.That(ids, Has.Some.Contains(financeId),
                "Unrestricted viewer should see the Finance message");
        }

        // -----------------------------------------------------------------------
        // R1: scoped viewer sees only in-scope messages
        // -----------------------------------------------------------------------

        [Test]
        public async Task Scoped_viewer_sees_only_in_scope_messages()
        {
            var salesId = Guid.NewGuid().ToString("N");
            var financeId = Guid.NewGuid().ToString("N");
            string responseBody = null;

            using var scopedConfig = new ScopedViewerRbacConfiguration();

            _ = await Define<Context>()
                .Done(async ctx =>
                {
                    await StoreFailedMessage(salesId, SalesQueueAddress);
                    await StoreFailedMessage(financeId, FinanceQueueAddress);

                    var token = mockOidcServer.GenerateTokenWithRealmRoles("sales-viewer", ["sales-viewer"]);
                    var response = await OpenIdConnectAssertions.SendRequestWithBearerToken(
                        HttpClient, HttpMethod.Get, "/api/errors", token);

                    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                    responseBody = await response.Content.ReadAsStringAsync();
                    return true;
                })
                .Run();

            // sales-viewer has messages:view scoped to Sales.* → only Sales message returned
            using var doc = JsonDocument.Parse(responseBody!);
            var ids = doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("id", out var idProp) ? idProp.GetString() : null)
                .ToList();

            Assert.That(ids, Has.Some.Contains(salesId),
                "Scoped viewer should see the in-scope Sales message");
            Assert.That(ids.Any(id => id?.Contains(financeId) == true), Is.False,
                "Scoped viewer must NOT see the out-of-scope Finance message");
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
                        }
                    }
                ]
            };

        /// <summary>
        /// RBAC config with a "sales-viewer" role scoped to Sales.* queues only.
        /// </summary>
        sealed class ScopedViewerRbacConfiguration : IDisposable
        {
            readonly string tempYamlPath;
            bool disposed;

            public ScopedViewerRbacConfiguration()
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
                      sales-viewer:
                        bindings: [ "role:sales-viewer" ]
                        permissions:
                          - permission: "messages:view"
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
